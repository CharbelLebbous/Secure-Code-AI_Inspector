from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from secure_inspector.config import ScopeConfig


@dataclass(frozen=True)
class ScannedFile:
    relative_path: str
    absolute_path: Path
    content: str
    line_count: int


def _is_excluded(relative_path: str, exclude_globs: list[str]) -> bool:
    normalized = relative_path.replace("\\", "/")
    return any(fnmatch(normalized, pattern) for pattern in exclude_globs)


def collect_scope_files(target_path: str | Path, scope: ScopeConfig) -> list[Path]:
    root = Path(target_path).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Target path does not exist or is not a directory: {root}")

    files: dict[str, Path] = {}

    if scope.include_globs:
        for pattern in scope.include_globs:
            for p in root.glob(pattern):
                if p.is_file():
                    rel = p.relative_to(root).as_posix()
                    files[rel] = p
    else:
        for p in root.rglob("*"):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                files[rel] = p

    selected: list[Path] = []
    for rel in sorted(files.keys()):
        if _is_excluded(rel, scope.exclude_globs):
            continue
        selected.append(files[rel])
        if len(selected) >= scope.max_files:
            break
    return selected


def load_scoped_files(target_path: str | Path, scope: ScopeConfig) -> list[ScannedFile]:
    root = Path(target_path).resolve()
    files = collect_scope_files(root, scope)
    scoped: list[ScannedFile] = []
    for path in files:
        content = path.read_text(encoding="utf-8", errors="ignore")
        line_count = max(1, content.count("\n") + 1)
        scoped.append(
            ScannedFile(
                relative_path=path.relative_to(root).as_posix(),
                absolute_path=path,
                content=content,
                line_count=line_count,
            )
        )
    return scoped

