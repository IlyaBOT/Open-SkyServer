"""Offline CPU analysis of the exact Skype 4.2 loader, never a client patch.

Dependencies, local to this repository:
py -3 -m pip install --only-binary=:all: --target skyserver/.packages/analysis \
    unicorn==2.1.4 pefile==2024.8.26
"""
import argparse
import hashlib
from pathlib import Path
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".packages" / "analysis"))
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_HOOK_INTR
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_EIP

ORIGINAL_SHA256 = "a2e175ce7c9888c125e2b3d4c2343229832ba0d0cd8a8a1ce120ce92624e856c"
BASE = 0x400000
DESCRIPTOR = 0x101B000


def rol(value, bits):
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def prepare_image(raw):
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("Unsupported original executable hash")
    pe = pefile.PE(data=raw, fast_load=True)
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.ImageBase != BASE:
        raise ValueError("Unexpected PE architecture/base")
    image = bytearray(pe.get_memory_mapped_image())
    size = pe.OPTIONAL_HEADER.SizeOfImage
    if size != 0x1848000:
        raise ValueError("Unexpected image size")
    image.extend(b"\0" * (size - len(image)))
    key = 0x8C705817
    va = 0x4F92E0
    while va < 0x50F364:
        if va == 0x50F16E:
            va += 0x27
        image[va - BASE] ^= key & 0xFF
        key = rol(key, 3)
        va += 1
    key = 0
    for value in image[0x50F160 - BASE:0x50F364 - BASE]:
        key = ((key * 2 + value) & 0xFFFFFFFF) ^ (key >> 31)
    if key != 0x953DABFF:
        raise ValueError("Stage-one checksum disagrees with Ghidra")
    for offset in range(4, 0x88):
        key = rol(key, 3)
        image[DESCRIPTOR - BASE + offset] ^= key & 0xFF
    descriptor = bytes(image[DESCRIPTOR - BASE:DESCRIPTOR - BASE + 0x118])
    if struct.unpack_from("<I", descriptor, 4)[0] != BASE:
        raise ValueError("Descriptor decoding failed")
    return image, descriptor


def scan_public_constants(image):
    for address in (b"193.88.6.13", b"194.165.188.79", b"195.46.253.219", b"login.skype.com"):
        at = image.find(address)
        print(f"public endpoint {address.decode()}: " + (f"RVA=0x{at:x}" if at >= 0 else "not found"))
    template = (ROOT / "skypatch.ps1").read_text(encoding="utf-8-sig")
    for name in ("OriginalLoginModulus", "OriginalCredentialsModulus"):
        match = re.search(r"\$" + name + r" = '([0-9A-F]+)'", template)
        if not match:
            raise ValueError("Public modulus is missing from patcher template")
        modulus = bytes.fromhex(match[1])
        for order, value in (("BE", modulus), ("LE", modulus[::-1])):
            at = image.find(value)
            print(f"public modulus {name}/{order}: " + (f"RVA=0x{at:x}" if at >= 0 else "not found"))
        for order, value in (("hex-lower", match[1].lower().encode("ascii")), ("hex-upper", match[1].encode("ascii"))):
            at = image.find(value)
            print(f"public modulus {name}/{order}: " + (f"RVA=0x{at:x}" if at >= 0 else "not found"))


def loader_checksums(client, decoded_path):
    image, descriptor = prepare_image(client.read_bytes())
    decoded = decoded_path.read_bytes()
    if hashlib.sha256(decoded).hexdigest() != "53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac":
        raise ValueError("Unexpected static decompressed image")
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    tls = struct.unpack_from("<I", image, pe + 0xC0)[0]
    index = struct.unpack_from("<I", image, tls + 8)[0]
    image[DESCRIPTOR-BASE:DESCRIPTOR-BASE+0x118] = bytes(0x118)
    image[0x12:0x14] = bytes(2)
    for offset in (pe + 0x58, pe + 0x98, pe + 0x9C, index - BASE):
        struct.pack_into("<I", image, offset, 0)
    before = 0
    print("Computing the loader's pre/post-decompression image checksums", flush=True)
    for byte in image:
        before = ((before * 2 + byte) & 0xFFFFFFFF) ^ (before >> 31)
    after = 0xA9C35B72
    for byte in decoded:
        after = ((after << 4) + byte) & 0xFFFFFFFF
        high = after & 0xF0000000
        after = (after ^ (high >> 24)) & (~high & 0xFFFFFFFF)
    mixed = before ^ after
    masked_entry = mixed ^ struct.unpack_from("<I", descriptor, 0x1C)[0]
    final_key = rol(0x8C705817, (3 * (0x50F364 - 0x4F92E0 - 0x27)) % 32)
    entry = masked_entry ^ final_key  # PUSH EAX / CALL / XOR [ESP],EAX / RET at 0050f195
    secondary = (mixed >> 2) ^ ((mixed * 5) & 0xFFFFFFFF)
    private_base = secondary ^ struct.unpack_from("<I", descriptor, 0x80)[0]
    private_init = (~(secondary * 3) & 0xFFFFFFFF) ^ struct.unpack_from("<I", descriptor, 0x84)[0]
    private_imports = struct.unpack_from("<I", descriptor, 0x88)[0] ^ struct.unpack_from("<I", descriptor, 0x80)[0] ^ private_init
    private_size = struct.unpack_from("<I", descriptor, 0x8C)[0] ^ struct.unpack_from("<I", descriptor, 0x84)[0] ^ private_base
    print(f"Before={before:08x} After={after:08x} Mixed={mixed:08x} MaskedEntry={masked_entry:08x} FinalMask={final_key:08x} EntryVA={entry:08x}")
    print(f"PrivateBase={private_base:08x} PrivateInit={private_init:08x} PrivateImportsRVA={private_imports:08x} PrivateImportsSize={private_size:08x}")
    if not BASE <= entry < BASE + len(decoded):
        raise ValueError("Derived entry is outside image; loader assumptions are incomplete")
    print("Candidate entry bytes=" + decoded[entry-BASE:entry-BASE+24].hex())
    scan_public_constants(decoded)


def analyze(client, seconds, output=None):
    if output is not None:
        output = output.resolve()
        output.relative_to((ROOT / "diagnostics").resolve())
        if not output.parent.is_dir() or output.exists():
            raise ValueError("Output needs an existing diagnostics directory and a new file name")
    image, descriptor = prepare_image(client.read_bytes())
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    size = (len(image) + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, size, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_write(BASE, bytes(image))
    # Only the previously decoded loader pages are executable. No host API
    # emulation, DLL loading, process attachment or memory-write API is provided.
    mu.mem_protect(0x4F9000, 0x17000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    mu.mem_map(0x20000000, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
    context = 0x20080000
    stack = 0x200FF000
    end = 0x4F9000
    mu.mem_write(context, descriptor)
    mu.mem_write(DESCRIPTOR, bytes(0x118))
    mu.mem_write(stack, struct.pack("<I", end))
    mu.reg_write(UC_X86_REG_ESP, stack)
    mu.reg_write(UC_X86_REG_ECX, context)

    def reject_interrupt(emulator, number, data):
        raise ValueError(f"Unexpected emulated interrupt {number}")

    mu.hook_add(UC_HOOK_INTR, reject_interrupt)
    started = time.monotonic()
    print("Emulating only cipher routine 0050eee0; no installed-file changes", flush=True)
    try:
        mu.emu_start(0x50EEE0, end, timeout=seconds * 1000000, count=5000000000)
    except UcError as error:
        raise ValueError(f"Emulation stopped at EIP={mu.reg_read(UC_X86_REG_EIP):08x}: {error}") from error
    if mu.reg_read(UC_X86_REG_EIP) != end:
        raise ValueError(f"Emulation limit reached at EIP={mu.reg_read(UC_X86_REG_EIP):08x}")
    print(f"Cipher returned in {time.monotonic() - started:.2f}s", flush=True)
    decoded = bytes(mu.mem_read(BASE, len(image)))
    print("Decoded image SHA256=" + hashlib.sha256(decoded).hexdigest())
    # Reproduce the loader's bounded bump allocator, not any Windows allocation
    # API. The decoder receives {used, arenaBase} as its one stack argument.
    arena = 0x30000000
    allocator = context + 0x200
    mu.mem_map(arena, 0x100000, UC_PROT_READ | UC_PROT_WRITE)
    mu.mem_write(allocator, struct.pack("<II", 0, arena))
    mu.mem_write(stack, struct.pack("<II", end, allocator))
    mu.reg_write(UC_X86_REG_ESP, stack)
    mu.reg_write(UC_X86_REG_ECX, context)
    mu.reg_write(UC_X86_REG_EDX, BASE)
    print("Emulating only decompressor 0050e9f0", flush=True)
    started = time.monotonic()
    try:
        mu.emu_start(0x50E9F0, end, timeout=seconds * 1000000, count=5000000000)
    except UcError as error:
        raise ValueError(f"Decompression stopped at EIP={mu.reg_read(UC_X86_REG_EIP):08x}: {error}") from error
    if mu.reg_read(UC_X86_REG_EIP) != end or mu.reg_read(UC_X86_REG_EAX) & 0xFF != 1:
        raise ValueError(f"Decompressor did not succeed: EIP={mu.reg_read(UC_X86_REG_EIP):08x} EAX={mu.reg_read(UC_X86_REG_EAX):08x}")
    print(f"Decompressor returned in {time.monotonic() - started:.2f}s", flush=True)
    decoded = bytes(mu.mem_read(BASE, len(image)))
    print("Uncompressed image SHA256=" + hashlib.sha256(decoded).hexdigest())
    scan_public_constants(decoded)
    unpacked = pefile.PE(data=decoded, fast_load=True)
    for section in unpacked.sections:
        print(f"unpacked section {section.Name.rstrip(bytes([0])).decode('ascii')}: "
              f"RVA={section.VirtualAddress:08x} virtual={section.Misc_VirtualSize:08x} "
              f"raw={section.PointerToRawData:08x}+{section.SizeOfRawData:08x}")
    if output is not None:
        # A static, memory-layout analysis artifact, NOT a launchable/rebuilt PE.
        # No bytes from a running process or from user profiles are read.
        with output.open("xb") as stream:
            stream.write(decoded)
        print(f"Static analysis image saved: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, default=Path(r"C:\Program Files (x86)\Skype\Phone\Skype.exe"))
    parser.add_argument("--seconds", type=int, default=60, choices=range(1, 121))
    parser.add_argument("--output", type=Path, help="new static .image.bin inside skyserver/diagnostics; not a patched executable")
    parser.add_argument("--checksums-image", type=Path, help="derive loader addresses from an existing static analysis image; no CPU emulation")
    args = parser.parse_args()
    if args.checksums_image:
        loader_checksums(args.client, args.checksums_image)
    else:
        analyze(args.client, args.seconds, args.output)
