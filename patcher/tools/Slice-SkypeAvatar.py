"""Build a hash-bound static-only PE subset for avatar/storage analysis.

The original pages retain their virtual addresses. This incomplete analysis
carrier must never be launched as a client and contains no deployment keys.
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
REGIONS = (
    (b'.avatar', 0x1A8000, 0x3000, 0x60000020),
    (b'.lock', 0x23B000, 0x2000, 0x60000020),
    (b'.copy', 0x2C1000, 0x1000, 0x60000020),
    (b'.store', 0x34E000, 0x6000, 0x60000020),
    (b'.strings', 0x890000, 0x3000, 0x40000040),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.relative_to((ROOT / 'diagnostics').resolve())
    if output.exists() or output.with_suffix('.json').exists():
        raise ValueError('Choose new analysis output paths')
    image = args.image.read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_HASH:
        raise ValueError('Expected the exact original canonical image')
    pe = pefile.PE(data=image, fast_load=True)
    section_at = pe.sections[0].get_file_offset()
    original_sections = len(pe.sections)
    pe.FILE_HEADER.NumberOfSections = len(REGIONS)
    pe.FILE_HEADER.Characteristics |= 0x2000
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1A8DF0
    pe.OPTIONAL_HEADER.SizeOfImage = max(rva + size for _, rva, size, _ in REGIONS)
    pe.OPTIONAL_HEADER.SizeOfCode = sum(size for _, _, size, flags in REGIONS if flags & 0x20)
    pe.OPTIONAL_HEADER.SizeOfInitializedData = 0x3000
    pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x1000
    pe.OPTIONAL_HEADER.CheckSum = 0
    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        directory.VirtualAddress = directory.Size = 0
    result = bytearray(pe.write()[:0x1000])
    result[section_at:section_at + 40 * max(original_sections, len(REGIONS))] = bytes(40 * max(original_sections, len(REGIONS)))
    ranges = []
    for index, (name, rva, size, flags) in enumerate(REGIONS):
        raw = len(result)
        data = image[rva:rva + size]
        if len(data) != size:
            raise ValueError('Truncated source region')
        struct.pack_into('<8s6I2HI', result, section_at + index * 40,
                         name, size, rva, size, raw, 0, 0, 0, 0, flags)
        result.extend(data)
        ranges.append({'source_rva': rva, 'length': size, 'file_offset': raw,
                       'sha256': hashlib.sha256(data).hexdigest()})
    metadata = {'purpose': 'incomplete static analysis only; never execute',
                'source_image_sha256': IMAGE_HASH,
                'slice_sha256': hashlib.sha256(result).hexdigest(), 'regions': ranges}
    with output.open('xb') as stream:
        stream.write(result)
    with output.with_suffix('.json').open('x', encoding='ascii') as stream:
        json.dump(metadata, stream, indent=2)
    print(json.dumps(metadata))


if __name__ == '__main__':
    main()
