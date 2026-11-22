"""Tests for check_metadata.py and strip_metadata.py using images made at run time."""
from PIL import Image
from PIL.PngImagePlugin import PngInfo

import check_metadata
import strip_metadata


def _png(path, text=None):
    info = PngInfo()
    if text:
        info.add_text('Author', text)
    Image.new('RGB', (8, 8), 'red').save(path, pnginfo=info)


def _jpeg(path, with_exif):
    exif = Image.Exif()
    if with_exif:
        exif[0x0131] = 'Some Camera App'  # Software tag
    Image.new('RGB', (8, 8), 'blue').save(path, exif=exif.tobytes() if with_exif else b'')


def test_clean_images_pass(tmp_path):
    _png(tmp_path / 'a.png')
    _jpeg(tmp_path / 'b.jpg', with_exif=False)
    assert check_metadata.main([str(tmp_path)]) == 0


def test_png_text_and_jpeg_exif_are_caught_and_stripped(tmp_path, capsys):
    _png(tmp_path / 'a.png', text='Private Name')
    _jpeg(tmp_path / 'b.jpg', with_exif=True)
    assert check_metadata.image_metadata(tmp_path / 'a.png') == {'text'}
    assert check_metadata.image_metadata(tmp_path / 'b.jpg') == {'EXIF'}
    assert check_metadata.main([str(tmp_path)]) == 1
    strip_metadata.main([str(tmp_path)])
    assert check_metadata.main([str(tmp_path)]) == 0
    assert 'Private Name' not in capsys.readouterr().out  # values are never printed
    with Image.open(tmp_path / 'a.png') as img:
        assert img.size == (8, 8) and img.getpixel((0, 0)) == (255, 0, 0)


def test_clean_file_left_unchanged(tmp_path):
    path = tmp_path / 'a.png'
    _png(path)
    before = path.read_bytes()
    strip_metadata.main([str(tmp_path)])
    assert path.read_bytes() == before
