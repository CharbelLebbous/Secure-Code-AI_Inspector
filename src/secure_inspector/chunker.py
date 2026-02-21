from __future__ import annotations

import re
from dataclasses import dataclass

from secure_inspector.scanner import ScannedFile


@dataclass(frozen=True)
class CodeChunk:
    id: str
    file_path: str
    start_line: int
    end_line: int
    content: str


_FUNCTION_LIKE_PATTERN = re.compile(
    r"^\s*(async\s+function|function|def|class|router\.(get|post|put|delete|patch)|app\.(get|post|put|delete|patch))\b",
    re.IGNORECASE,
)


def _find_boundaries(lines: list[str]) -> list[int]:
    starts = [idx + 1 for idx, line in enumerate(lines) if _FUNCTION_LIKE_PATTERN.search(line)]
    if not starts or starts[0] != 1:
        starts = [1] + starts
    starts = sorted(set(starts))
    return starts


def _build_segment_ranges(total_lines: int, starts: list[int]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] - 1 if idx + 1 < len(starts) else total_lines
        if end >= start:
            ranges.append((start, end))
    return ranges


def _window_segment(
    lines: list[str], file_path: str, start_line: int, end_line: int, max_chunk_lines: int
) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    current = start_line
    while current <= end_line:
        window_end = min(current + max_chunk_lines - 1, end_line)
        text = "\n".join(lines[current - 1 : window_end])
        chunk_id = f"{file_path}:{current}-{window_end}"
        chunks.append(
            CodeChunk(
                id=chunk_id,
                file_path=file_path,
                start_line=current,
                end_line=window_end,
                content=text,
            )
        )
        current = window_end + 1
    return chunks


def build_chunks(scoped_files: list[ScannedFile], max_chunk_lines: int) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    for scanned in scoped_files:
        lines = scanned.content.splitlines()
        if not lines:
            continue
        starts = _find_boundaries(lines)
        ranges = _build_segment_ranges(len(lines), starts)
        for start, end in ranges:
            chunks.extend(
                _window_segment(
                    lines=lines,
                    file_path=scanned.relative_path,
                    start_line=start,
                    end_line=end,
                    max_chunk_lines=max_chunk_lines,
                )
            )
    return chunks

