#!/usr/bin/env python3
"""Fail if any PNG or JPEG under captures/ still carries EXIF or text metadata.

Screenshots can hide a username, device name, software version or edit time in
metadata that nobody sees on screen. This reads chunk and marker names only,
never the metadata values, and needs no extra packages.
Exit codes: 0 clean, 1 metadata found, 2 unreadable image.
"""
import argparse
import struct
import sys
from pathlib import Path

IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg'}
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
# PNG chunks that hold free text or EXIF. gAMA, sRGB and pHYs are colour/size hints, so they are allowed.
PNG_METADATA_CHUNKS = {b'tEXt': 'text', b'zTXt': 'text', b'iTXt': 'text', b'eXIf': 'EXIF'}


def png_metadata(data: bytes) -> set[str]:
    """Return the kinds of metadata chunk found in a PNG file."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError('not a PNG')
    found, pos = set(), len(PNG_SIGNATURE)
    while pos + 8 <= len(data):
        length, kind = struct.unpack('>I4s', data[pos:pos + 8])
        if kind in PNG_METADATA_CHUNKS:
            found.add(PNG_METADATA_CHUNKS[kind])
        if kind == b'IEND':
            break
        pos += 12 + length  # length + type + data + CRC
    return found


def jpeg_metadata(data: bytes) -> set[str]:
    """Return the kinds of metadata segment found before the image data in a JPEG file."""
    if not data.startswith(b'\xff\xd8'):
        raise ValueError('not a JPEG')
    found, pos = set(), 2
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker == 0xDA:  # start of scan: image data follows, no more headers
            break
        length = struct.unpack('>H', data[pos + 2:pos + 4])[0]
        body = data[pos + 4:pos + 2 + length]
        if marker == 0xE1 and body.startswith(b'Exif\x00'):
            found.add('EXIF')
        elif marker == 0xE1 and body.startswith(b'http://ns.adobe.com/'):
            found.add('XMP')
        elif marker == 0xFE:
            found.add('comment')
        pos += 2 + length
    return found


def image_metadata(path: Path) -> set[str]:
    data = path.read_bytes()
    return png_metadata(data) if path.suffix.lower() == '.png' else jpeg_metadata(data)


def find_images(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in IMAGE_SUFFIXES)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='captures', type=Path)
    args = parser.parse_args(argv)
    status = 0
    images = find_images(args.root)
    for path in images:
        try:
            kinds = image_metadata(path)
        except (OSError, ValueError, struct.error):
            print(f'UNREADABLE {path}')
            status = max(status, 2)
            continue
        if kinds:
            print(f"METADATA {path}: {', '.join(sorted(kinds))}")
            status = max(status, 1)
    print(f'Checked {len(images)} image(s): ' + ('clean' if status == 0 else 'problems found'))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
