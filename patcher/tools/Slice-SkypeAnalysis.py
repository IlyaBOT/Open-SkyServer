"""Create a provenance-bound, analysis-only PE slice of Skype 4.2.

Only the original endpoint classifier's page is included. This derived artifact
is for static Ghidra/REA analysis; it is not a patched client or a complete app.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.packages' / 'analysis'))
import pefile

IMAGE_HASH = '53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac'
RVA = 0x16E000
SIZE = 0x1000
ENTRY = 0x16E350


def make_slice(image):
    if hashlib.sha256(image).hexdigest() != IMAGE_HASH:
        raise ValueError('Only the verified original canonical image is supported')
    pe = pefile.PE(data=image, fast_load=True)
    section_at = pe.sections[0].get_file_offset()
    pe.FILE_HEADER.NumberOfSections = 1
    pe.FILE_HEADER.Characteristics |= 0x2000  # A DLL without a working runtime.
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = ENTRY
    pe.OPTIONAL_HEADER.SizeOfImage = RVA + SIZE
    pe.OPTIONAL_HEADER.SizeOfCode = SIZE
    pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
    pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x1000
    pe.OPTIONAL_HEADER.CheckSum = 0
    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        directory.VirtualAddress = 0
        directory.Size = 0
    header = bytearray(pe.write()[:0x1000])
    header[section_at:section_at + 40 * len(pe.sections)] = bytes(40 * len(pe.sections))
    struct.pack_into('<8s6I2HI', header, section_at, b'.slice', SIZE, RVA,
                     SIZE, 0x1000, 0, 0, 0, 0, 0x60000020)
    return bytes(header) + image[RVA:RVA + SIZE]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to((ROOT / 'diagnostics').resolve())
    if output.exists() or output.with_suffix('.json').exists():
        raise ValueError('Use new analysis output paths')
    image = args.image.read_bytes()
    derived = make_slice(image)
    record = {'purpose': 'static-only incomplete analysis slice; never launch',
              'source_image_sha256': IMAGE_HASH,
              'slice_sha256': hashlib.sha256(derived).hexdigest(),
              'source_image_offset': RVA, 'source_rva': RVA,
              'length': SIZE, 'slice_file_offset': 0x1000,
              'bytes_sha256': hashlib.sha256(image[RVA:RVA + SIZE]).hexdigest(),
              'entry_va': 0x400000 + ENTRY}
    with output.open('xb') as stream:
        stream.write(derived)
    with output.with_suffix('.json').open('x', encoding='ascii') as stream:
        json.dump(record, stream, indent=2)
    print(json.dumps(record))


if __name__ == '__main__':
    main()
