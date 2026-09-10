"""Build an isolated, experimental Skype 4.2 PE from the verified offline image.

Developer tool only. Never overwrites an installed client or an existing output.
Requires the pinned pefile package used by Inspect-PackedSkype.py. The generated
EXE contains locally installed commercial code and must not be redistributed.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".packages" / "analysis"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pefile
from Skype42Integrity import checksum_table, MODULUS_RVA, sign_table, verify_table_signature

ORIGINAL_HASH = "a2e175ce7c9888c125e2b3d4c2343229832ba0d0cd8a8a1ce120ce92624e856c"
IMAGE_HASH = "53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac"
BASE = 0x400000
IMAGE_SIZE = 0x1848000
PRIVATE_DELTA = 0xF1000
SEEDS_RVA = 0x8763E0
SEEDS_COUNT = 200
SEEDS_HASH = "fb35406b469cd55c5993ddbdb0622cc9cf62f5f7a5aa350ae1b0ee65f562bac4"
SERVER_PORTS = (12350, 12351, 13392, 33033, 10100, 23456)
KEY_SLOTS = (("login", "OriginalLoginModulus", 0x870EC9, 192),
             ("credentials", "OriginalCredentialsModulus", 0x871950, 256))
SERVER_LISTS = {
    0x883924: "204.9.163.211:12350 130.117.72.100:12350",
    0x889F30: "193.88.6.19:33033 194.165.188.82:33033 212.72.49.143:33033 195.46.253.211:33033",
    0x88A60C: "193.88.6.13:33033 194.165.188.79:33033 195.46.253.219:33033",
    0x88A668: "193.88.8.59:12350 194.165.188.76:12350 212.8.163.76:12350",
    0x88C6A0: "194.165.188.93:13392 195.46.253.218:13392",
    0x88E334: "193.88.8.59:12350 194.165.188.76:12350",
    0x88FCD0: "194.165.188.89:33033 212.187.172.43:33033 195.46.253.200:33033 212.8.163.113:33033",
    0x892198: "195.215.8.140:23456 212.72.49.155:23456",
    0x8990C0: "194.165.188.85:12350",
    0x8A0A48: "195.46.253.205:12351",
    0x8A1AF8: "194.165.188.92:10100 195.46.253.217:10100",
    0x8A1CA8: "194.165.188.77:12350",
    0x8B2878: "212.8.163.77:12351 212.8.163.78:12350 194.165.188.86:12351 194.165.188.87:12351",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def span(data, at, size):
    if at < 0 or size < 0 or at + size > len(data):
        raise ValueError("Out-of-bounds image structure")
    return data[at:at + size]


def u32(data, at):
    return struct.unpack("<I", span(data, at, 4))[0]


def zstring(data, at, limit=512):
    end = data.find(b"\0", at, min(len(data), at + limit))
    if at < 0 or end < 0:
        raise ValueError("Unterminated image string")
    return bytes(data[at:end])


def replace_exact(image, at, old, new):
    if len(new) > len(old) or span(image, at, len(old)) != old:
        raise ValueError(f"Patch precondition failed at RVA {at:08x}")
    image[at:at + len(old)] = new.ljust(len(old), b"\0")


def public_modulus(path, size):
    raw = path.read_bytes()
    if len(raw) > 4096 or b"<!" in raw:
        raise ValueError("Invalid public key XML")
    root = ET.fromstring(raw)
    if root.tag != "RSAKeyValue" or sorted(child.tag for child in root) != ["Exponent", "Modulus"]:
        raise ValueError("Only public RSA XML is accepted")
    modulus = base64.b64decode(root.findtext("Modulus"), validate=True)
    exponent = base64.b64decode(root.findtext("Exponent"), validate=True)
    if len(modulus) != size or not modulus[0] & 128 or not modulus[-1] & 1 or exponent != b"\1\0\1":
        raise ValueError("Unexpected RSA size/exponent")
    return modulus


def import_descriptors(image, rva, size, delta=0):
    records, inventory = [], []
    changed_thunks = set()
    for offset in range(0, min(size, 256 * 20), 20):
        desc = list(struct.unpack("<5I", span(image, rva + offset, 20)))
        if not any(desc):
            return records, inventory
        original_thunk, _, _, name, first_thunk = desc
        if not name or not first_thunk or not original_thunk:
            raise ValueError("Unsupported import descriptor")
        module = zstring(image, name + delta).decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(dll|drv)", module, re.IGNORECASE):
            raise ValueError("Unexpected DLL name")
        names = []
        for i in range(4096):
            at = original_thunk + delta + i * 4
            value = u32(image, at)
            if not value:
                break
            if value & 0x80000000:
                names.append("#" + str(value & 0xFFFF))
                converted = value
            else:
                names.append(zstring(image, value + delta + 2).decode("ascii"))
                converted = value + delta
            for target in (at, first_thunk + delta + i * 4):
                if target not in changed_thunks:
                    struct.pack_into("<I", image, target, converted)
                    changed_thunks.add(target)
        else:
            raise ValueError("Unterminated import thunks")
        if u32(image, first_thunk + delta + len(names) * 4):
            raise ValueError("Mismatched import thunk terminator")
        desc = [original_thunk + delta, 0, 0, name + delta, first_thunk + delta]
        records.append(struct.pack("<5I", *desc))
        inventory.append({"dll": module, "iat_rva": first_thunk + delta, "symbols": names})
    raise ValueError("Unterminated import descriptors")


def startup_stub(rva, size):
    code = bytearray(b"\xfc")  # CLD, as in the original entry.

    def branch(opcode, target):
        code.append(opcode)
        code.extend(struct.pack("<i", target - (BASE + rva + len(code) + 4)))

    # Original loader: EAX=main image, one cdecl stack argument=SizeOfImage.
    code.extend(b"\xb8" + struct.pack("<I", BASE))
    code.extend(b"\x68" + struct.pack("<I", size))
    branch(0xE8, 0x52B690)
    code.extend(b"\x83\xc4\x04\xc6\x05" + struct.pack("<I", 0xD19A98) + b"\x01")
    # Embedded networking CRT uses stdcall DllMain(base, PROCESS_ATTACH, NULL).
    code.extend(b"\x6a\x00\x6a\x01\x68" + struct.pack("<I", BASE + PRIVATE_DELTA))
    branch(0xE8, 0xA90EE6)
    branch(0xE9, 0x1019FD4)
    return bytes(code)


def bootstrap_address_exception(image, stub_rva, server_ip):
    # HostCache's default-table importer rejects RFC1918/loopback addresses.
    # Admit ONLY the configured server; all other addresses retain original rules.
    site, resume, port_check = 0x64BDB7, 0x64BDBF, 0x64BDF7
    original = bytes.fromhex("89 74 24 30 89 5c 24 34")
    code = bytearray(original + b"\x9c\x81\xfe" + struct.pack("<I", int(ipaddress.IPv4Address(server_ip))))
    code.extend(b"\x75\x06\x9d")
    code.extend(b"\xe9" + struct.pack("<i", port_check - (BASE + stub_rva + len(code) + 5)))
    code.extend(b"\x9d")
    code.extend(b"\xe9" + struct.pack("<i", resume - (BASE + stub_rva + len(code) + 5)))
    replace_exact(image, site - BASE, original,
                  b"\xe9" + struct.pack("<i", BASE + stub_rva - site - 5) + b"\x90" * 3)
    return bytes(code)


def endpoint_address_exception(image, stub_rva, server_ip):
    # Endpoint::isPublic also gates cached peers and login-server connections.
    # Only the configured service endpoints become eligible, not the whole LAN.
    site = 0x56E350
    original = bytes.fromhex("8b 0a 8b c1 25 00 00 00 ff")
    code = bytearray(original + b"\x9c\x81\xf9" + struct.pack("<I", int(ipaddress.IPv4Address(server_ip))))
    code += b"\x75\x00"
    different_ip = len(code) - 1
    accepted_jumps = []
    for port in SERVER_PORTS:
        code += b"\x81\x7a\x04" + struct.pack("<I", port) + b"\x74\x00"
        accepted_jumps.append(len(code) - 1)
    fallback = len(code)
    code += b"\x9d\xe9" + struct.pack("<i", site + len(original) - (BASE + stub_rva + len(code) + 6))
    accepted = len(code)
    code += b"\x9d\xe9" + struct.pack("<i", 0x56E396 - (BASE + stub_rva + len(code) + 6))
    code[different_ip] = fallback - different_ip - 1
    for jump in accepted_jumps:
        code[jump] = accepted - jump - 1
    replace_exact(image, site - BASE, original,
                  b"\xe9" + struct.pack("<i", BASE + stub_rva - site - 5) + b"\x90" * 4)
    return bytes(code)


def build(original, decoded, key_dir, server_ip, openssl=Path(r"C:\Program Files\Git\usr\bin\openssl.exe")):
    if sha(original) != ORIGINAL_HASH or sha(decoded) != IMAGE_HASH:
        raise ValueError("Unsupported original or static image fingerprint")
    ip = ipaddress.IPv4Address(server_ip)
    if ip.is_multicast or ip.is_unspecified or ip == ipaddress.IPv4Address("255.255.255.255"):
        raise ValueError("Unicast server IPv4 required")
    image = bytearray(decoded)
    if not verify_table_signature(image):
        raise ValueError("Original integrity signature did not verify")
    pe = pefile.PE(data=decoded, fast_load=True)
    if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.OPTIONAL_HEADER.SizeOfImage != IMAGE_SIZE or len(pe.sections) != 7:
        raise ValueError("Unexpected PE layout")
    if pe.OPTIONAL_HEADER.SectionAlignment != 4096 or pe.OPTIONAL_HEADER.FileAlignment != 512:
        raise ValueError("Unexpected PE alignment")
    patch_log = []
    template = (ROOT / "skypatch.ps1").read_text(encoding="utf-8-sig")
    for name, variable, rva, size in KEY_SLOTS:
        match = re.search(r"\$" + variable + r" = '([0-9A-F]+)'", template)
        if not match:
            raise ValueError("Original public authority missing from template")
        old = match[1].lower().encode("ascii")
        new = public_modulus(key_dir / (name + ".public.xml"), size)
        if len(old) != size * 2 or image.count(old) != 1:
            raise ValueError("Authority slot is not unique")
        replace_exact(image, rva, old + b"\0", new.hex().encode("ascii") + b"\0")
        patch_log.append({"role": name + "-authority", "rva": rva, "public_sha256": sha(new)})
    for rva, text in SERVER_LISTS.items():
        ports = list(dict.fromkeys(endpoint.split(":")[1] for endpoint in text.split()))
        replacement = " ".join(str(ip) + ":" + port for port in ports)
        replace_exact(image, rva, text.encode() + b"\0", replacement.encode() + b"\0")
        patch_log.append({"role": "server-list", "rva": rva, "old": text, "new": replacement})
    seeds = span(image, SEEDS_RVA, SEEDS_COUNT * 6)
    if sha(seeds) != SEEDS_HASH or any(span(image, SEEDS_RVA + SEEDS_COUNT * 6, 6)):
        raise ValueError("Default bootstrap table changed")
    # The importer deduplicates by IP, so repeated entries resolve to one lab node.
    image[SEEDS_RVA:SEEDS_RVA + len(seeds)] = (ip.packed + struct.pack(">H", 12350)) * SEEDS_COUNT
    patch_log.append({"role": "binary-bootstrap-table", "rva": SEEDS_RVA, "count": SEEDS_COUNT, "endpoint": str(ip) + ":12350"})
    # Getter for *Lib/Connection/DisableSupernode: default true in this lab.
    replace_exact(image, 0x16FCF4, bytes.fromhex("6a 00 68 8c b9 c8 00"), bytes.fromhex("6a 01 68 8c b9 c8 00"))
    patch_log.append({"role": "disable-supernode-default", "rva": 0x16FCF5, "value": 1})

    integrity_hex = (key_dir / "client-integrity" / "integrity.modulus.hex").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9A-Fa-f]{192}", integrity_hex) or int(integrity_hex, 16).bit_length() != 768:
        raise ValueError("Generate a client-integrity key with skyserver-keygen -ClientIntegrity")
    integrity_modulus = bytes.fromhex(integrity_hex)
    image[MODULUS_RVA:MODULUS_RVA + 96] = integrity_modulus[::-1]
    patch_log.append({"role": "image-integrity-authority", "rva": MODULUS_RVA, "public_sha256": sha(integrity_modulus)})

    main, main_inventory = import_descriptors(image, 0xC5F000, 0x521A)
    private, private_inventory = import_descriptors(image, 0x80AB9C + PRIVATE_DELTA, 0x154, PRIVATE_DELTA)
    if len(private) != 16:
        raise ValueError("Private import count changed")
    table = b"".join(main + private) + bytes(20)
    section_rva, section_size = IMAGE_SIZE, 0x1000
    if len(table) + 0x100 > 0x500:
        raise ValueError("Merged import table does not fit")
    new_size = IMAGE_SIZE + section_size
    code = startup_stub(section_rva, new_size)
    if len(code) > 0x100:
        raise ValueError("Startup stub overlaps imports")
    bootstrap_code = bootstrap_address_exception(image, section_rva + 0x80, str(ip))
    if len(code) > 0x80 or len(bootstrap_code) > 0x80:
        raise ValueError("Bootstrap exception overlaps startup or imports")
    patch_log.append({"role": "configured-bootstrap-address-exception", "rva": 0x24BDB7, "server_ip": str(ip)})
    endpoint_code = endpoint_address_exception(image, section_rva + 0x500, str(ip))
    if len(endpoint_code) > 0x100:
        raise ValueError("Endpoint exception exceeds reserved space")
    patch_log.append({"role": "configured-endpoint-address-exception", "rva": 0x16E350, "server_ip": str(ip), "ports": SERVER_PORTS})
    new_header = pe.sections[-1].get_file_offset() + 40
    if new_header + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders or any(image[new_header:new_header + 40]):
        raise ValueError("No room for another section header")
    for section in pe.sections:
        if section.SizeOfRawData:
            section.PointerToRawData = section.VirtualAddress
        elif any(span(image, section.VirtualAddress, section.Misc_VirtualSize)):
            raise ValueError("Virtual-only section has nonzero bytes")
    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = section_rva
    pe.OPTIONAL_HEADER.SizeOfImage = new_size
    pe.OPTIONAL_HEADER.SizeOfCode += section_size
    pe.OPTIONAL_HEADER.CheckSum = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = section_rva + 0x100
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = len(table)
    # No Authenticode certificate, bound imports, or misleading main-only IAT span.
    for number in (4, 11, 12):
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[number].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[number].Size = 0
    image[:pe.OPTIONAL_HEADER.SizeOfHeaders] = pe.write()[:pe.OPTIONAL_HEADER.SizeOfHeaders]
    struct.pack_into("<8s6I2HI", image, new_header, b".skyinit", section_size,
                     section_rva, section_size, section_rva, 0, 0, 0, 0, 0x60000020)
    image.extend(bytes(section_size))
    image[section_rva:section_rva + len(code)] = code
    image[section_rva + 0x80:section_rva + 0x80 + len(bootstrap_code)] = bootstrap_code
    image[section_rva + 0x100:section_rva + 0x100 + len(table)] = table
    image[section_rva + 0x500:section_rva + 0x500 + len(endpoint_code)] = endpoint_code
    # Optional Windows PE checksum stays zero: it includes the integrity table,
    # while the client's integrity table includes this header (a circular sum).
    integrity = checksum_table(image, update=True)
    sign_table(image, key_dir, openssl)
    check = pefile.PE(data=bytes(image))
    actual_imports = [(entry.dll.decode("ascii"), ["#" + str(symbol.ordinal) if symbol.import_by_ordinal else symbol.name.decode("ascii")
                                                for symbol in entry.imports]) for entry in check.DIRECTORY_ENTRY_IMPORT]
    inventory = main_inventory + private_inventory
    if actual_imports != [(entry["dll"], entry["symbols"]) for entry in inventory]:
        mismatch = next(((i, actual, expected) for i, (actual, expected) in enumerate(
            zip(actual_imports, [(entry["dll"], entry["symbols"]) for entry in inventory])) if actual != expected), None)
        raise ValueError(f"Import validation failed: actual={len(actual_imports)}, expected={len(inventory)}, first={mismatch}, warnings={check.get_warnings()}")
    mapped = check.get_memory_mapped_image()
    if mapped[:len(image)] != image:
        raise ValueError("PE file/memory layout mismatch")
    if check.OPTIONAL_HEADER.CheckSum != 0 or check.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress != 0xC66000:
        raise ValueError("Header/TLS verification failed")
    return bytes(image), {"original_sha256": sha(original), "static_image_sha256": sha(decoded),
                          "patched_sha256": sha(image), "server_ip": str(ip), "patches": patch_log,
                          "imports": inventory, "entry_rva": section_rva, "gui_entry_va": 0x1019FD4,
                          "private_init_va": 0xA90EE6, "private_base_va": BASE + PRIVATE_DELTA,
                          "integrity_regions": integrity,
                          "unverified": ["native client login", "profile and contacts", "non-list endpoints and cached IPs"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=Path(r"C:\Program Files (x86)\Skype\Phone\Skype.exe"))
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--keys-dir", type=Path, default=ROOT / "private-keys")
    parser.add_argument("--server-ip", default="192.168.1.101")
    parser.add_argument("--openssl", type=Path, default=Path(r"C:\Program Files\Git\usr\bin\openssl.exe"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.relative_to((ROOT / "diagnostics").resolve())
    if output.exists() or not output.parent.is_dir():
        raise ValueError("Use a NEW directory directly below an existing diagnostics directory")
    original = args.client.read_bytes()
    patched, manifest = build(original, args.image.read_bytes(), args.keys_dir, args.server_ip, args.openssl)
    manifest["utc"] = datetime.now(timezone.utc).isoformat()
    manifest["source_path"] = str(args.client.resolve())
    output.mkdir()
    # Backup is always the exact original, not a prior patched/analysis image.
    with (output / "Skype.exe.bak").open("xb") as stream:
        stream.write(original)
    with (output / "Skype.exe").open("xb") as stream:
        stream.write(patched)
    with (output / "build.json").open("x", encoding="ascii") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=True)
    print(json.dumps({"output": str(output), "sha256": sha(patched), "import_descriptors": len(manifest["imports"]),
                      "server_ip": args.server_ip, "status": "experimental; not launched or login-verified"}))


if __name__ == "__main__":
    main()
