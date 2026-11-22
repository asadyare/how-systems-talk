#!/usr/bin/env python3
"""Rewrite PNG/JPEG files without EXIF, XMP, comments or PNG text chunks.

Only files that actually carry metadata are rewritten, so clean screenshots are
left byte-for-byte unchanged. Pixels are kept; JPEGs are re-encoded at quality 95.
Run check_metadata.py afterwards to confirm.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_metadata import find_images, image_metadata  # noqa: E402

# The only Image.info entry carried over: PNG transparency is part of the picture, not metadata.
KEEP_INFO = {'transparency'}


def strip(path: Path) -> None:
    """Save a metadata-free copy next to the file, then swap it in atomically."""
    from PIL import Image
    with Image.open(path) as img:
        img.load()
        fmt = img.format
        clean = img.copy()
    clean.info = {k: v for k, v in clean.info.items() if k in KEEP_INFO}
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=path.suffix)
    os.close(fd)
    try:
        if fmt == 'JPEG':
            clean.save(tmp, format='JPEG', quality=95, exif=b'')
        else:
            clean.save(tmp, format='PNG')  # no pnginfo/exif given, so no text chunks are written
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='captures', type=Path)
    args = parser.parse_args(argv)
    for path in find_images(args.root):
        kinds = image_metadata(path)
        if not kinds:
            print(f'clean      {path}')
            continue
        strip(path)
        left = image_metadata(path)
        print(f"stripped   {path}: removed {', '.join(sorted(kinds))}" + (' (some left!)' if left else ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
