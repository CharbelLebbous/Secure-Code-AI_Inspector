from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path


DEFAULT_MAX_ZIP_BYTES = 80 * 1024 * 1024


def create_session_workspace(prefix: str = "secure_inspector_") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def save_zip_bytes(zip_bytes: bytes, destination: str | Path) -> Path:
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(zip_bytes)
    return dest


def validate_zip_size(size_bytes: int, max_bytes: int = DEFAULT_MAX_ZIP_BYTES) -> None:
    if size_bytes <= 0:
        raise ValueError("Uploaded ZIP is empty.")
    if size_bytes > max_bytes:
        raise ValueError(
            f"Uploaded ZIP exceeds limit ({size_bytes} bytes > {max_bytes} bytes)."
        )


def safe_extract_zip(zip_path: str | Path, extract_dir: str | Path) -> list[Path]:
    zip_file = Path(zip_path)
    out_dir = Path(extract_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted: list[Path] = []
    with zipfile.ZipFile(zip_file, "r") as zf:
        for member in zf.infolist():
            member_name = member.filename.replace("\\", "/")
            if not member_name or member.is_dir():
                continue

            member_path = Path(member_name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"Unsafe ZIP member path detected: {member_name}")

            target = (out_dir / member_path).resolve()
            if out_dir not in target.parents and target != out_dir:
                raise ValueError(f"ZIP extraction escaped target directory: {member_name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted.append(target)
    return extracted

