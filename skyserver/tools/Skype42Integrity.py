"""Reproduce Skype 4.2's 16-step MD5-like IMAGE integrity checksum.

Recovered from VA 0052ac10 in the exact offline image. This is not MD5 or a
cryptographic signature. The check routine is retained; only its data table is
recomputed for a locally rebuilt executable.
"""
import struct
import subprocess

BASE = 0x400000
TABLE_VA = 0x52BD10
TABLE_RVA = TABLE_VA - BASE
TABLE_END = 0x52BE0B
REGIONS = 13
MODULUS_RVA = 0x12BCB0
SIGNATURE_RVA = TABLE_RVA + REGIONS * 12
MASK = 0xFFFFFFFF
CONSTANTS = (0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
             0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
             0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
             0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821)
ROTATIONS = (7, 12, 17, 22) * 4


def region_checksum(image, va, size):
    start = va - BASE
    if start < 0 or size < 0 or start + size > len(image):
        raise ValueError("Integrity region is outside the image")
    # The original loop ignores a trailing partial DWORD and zero-pads the last
    # 64-byte block. There is no MD5 0x80/bit-length suffix.
    count = size // 4 * 4
    data = bytearray(image[start:start + count])
    for at in range(max(start, TABLE_RVA), min(start + count, TABLE_END - BASE + 1), 4):
        if (at - start) % 4:
            raise ValueError("Unexpected unaligned checksum table overlap")
        data[at - start:at - start + 4] = bytes(4)
    data.extend(bytes((-len(data)) % 64))
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for words in struct.iter_unpack("<16I", data):
        a, b, c, d = a0, b0, c0, d0
        for i, word in enumerate(words):
            if i < 4:
                f = (b & c) | (~b & d)
            elif i < 8:
                f = (b & d) | (c & ~d)
            elif i < 12:
                f = b ^ c ^ d
            else:
                f = c ^ (b | ~d)
            value = (a + f + CONSTANTS[i] + word) & MASK
            shift = ROTATIONS[i]
            value = ((value << shift) | (value >> (32 - shift))) & MASK
            a, b, c, d = d, (b + value) & MASK, b, c
        a0, b0, c0, d0 = (a0 + a) & MASK, (b0 + b) & MASK, (c0 + c) & MASK, (d0 + d) & MASK
    return (a0 - d0 - c0 - b0) & MASK


def checksum_table(image, update=False):
    result = []
    for index in range(REGIONS):
        at = TABLE_RVA + index * 12
        displacement, size, expected = struct.unpack_from("<3I", image, at)
        va = (TABLE_VA - displacement) & MASK
        actual = region_checksum(image, va, size)
        result.append({"index": index, "va": va, "size": size, "expected": expected, "actual": actual})
        if update:
            struct.pack_into("<I", image, at + 8, actual)
    return result


def table_message(image):
    words = []
    for i in range(23):
        start = (i >> 1) + ((i * 0x4CCCCCCCD) >> 34)
        size = min(3, 39 - start) * 4
        value = 0xA9C35B72
        for byte in image[TABLE_RVA + start * 4:TABLE_RVA + start * 4 + size]:
            value = ((value << 4) + byte) & MASK
            high = value & 0xF0000000
            value = (value ^ (high >> 24)) & (~high & MASK)
        words.append(value)
    # The verifier compares 95 low-order bytes. Original recovery ends in 01.
    return struct.pack("<23I", *words) + b"\0\0\0\1"


def verify_table_signature(image):
    modulus = int.from_bytes(image[MODULUS_RVA:MODULUS_RVA + 96], "little")
    signature = int.from_bytes(image[SIGNATURE_RVA:SIGNATURE_RVA + 96], "little")
    if modulus.bit_length() != 768 or not 0 < signature < modulus:
        return False
    recovered = pow(signature, 3, modulus).to_bytes(96, "little")
    return recovered[:95] == table_message(image)[:95]


def sign_table(image, key_dir, openssl):
    key = key_dir / "client-integrity" / "integrity.private.pem"
    # OpenSSL owns private-key parsing and the private RSA operation. No private
    # integers or unblinded Python private exponentiation enter this builder.
    # pkeyutl -sign limits undigested inputs to EVP_MAX_MD_SIZE; the raw private
    # RSA primitive uses -decrypt with no padding for this 96-byte legacy block.
    result = subprocess.run([str(openssl), "pkeyutl", "-decrypt", "-inkey", str(key),
                             "-pkeyopt", "rsa_padding_mode:none"],
                            input=table_message(image)[::-1], capture_output=True, timeout=15,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode or len(result.stdout) != 96:
        raise ValueError("OpenSSL integrity signing failed: " + result.stderr.decode("ascii", errors="replace")[:1000])
    image[SIGNATURE_RVA:SIGNATURE_RVA + 96] = result.stdout[::-1]
    if not verify_table_signature(image):
        raise ValueError("Integrity signature self-verification failed")
