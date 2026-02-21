from secure_inspector.chunker import build_chunks
from secure_inspector.scanner import ScannedFile
from pathlib import Path


def test_chunker_preserves_line_ranges():
    content = "\n".join(
        [
            "function a() {",
            "  const x = 1;",
            "}",
            "function b() {",
            "  const y = 2;",
            "}",
        ]
    )
    scoped = [
        ScannedFile(
            relative_path="routes/sample.js",
            absolute_path=Path("routes/sample.js"),
            content=content,
            line_count=6,
        )
    ]
    chunks = build_chunks(scoped, max_chunk_lines=3)
    assert chunks
    assert chunks[0].file_path == "routes/sample.js"
    assert chunks[0].start_line == 1
    assert chunks[0].end_line <= 3
