from __future__ import annotations

import zipfile

import pytest

from secure_inspector.web_utils import safe_extract_zip, validate_zip_size


def test_safe_extract_zip_rejects_path_traversal(tmp_path):
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../escape.txt", "malicious")

    with pytest.raises(ValueError):
        safe_extract_zip(zip_path, tmp_path / "extract")


def test_safe_extract_zip_extracts_valid_members(tmp_path):
    zip_path = tmp_path / "good.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("src/app.js", "console.log('ok')")

    extracted = safe_extract_zip(zip_path, tmp_path / "extract")
    assert extracted
    assert (tmp_path / "extract" / "src" / "app.js").exists()


def test_validate_zip_size_blocks_too_large():
    with pytest.raises(ValueError):
        validate_zip_size(100, max_bytes=10)

