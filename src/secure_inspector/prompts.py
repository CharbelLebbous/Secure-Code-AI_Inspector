from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from secure_inspector.chunker import CodeChunk
from secure_inspector.models import Finding


def read_text_file(path: str | Path) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Prompt/reference file not found: {p}")
    return p.read_text(encoding="utf-8")


def load_few_shot_examples(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Few-shot file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_owasp_reference(path: str | Path) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"OWASP data file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("OWASP reference file must be a mapping")
    lines = []
    for key, value in data.items():
        lines.append(f"- {key}: {value}")
    return "\n".join(lines)


def _replace_many(template: str, replacements: dict[str, str]) -> str:
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace(key, value)
    return rendered


def render_specialist_prompt(
    *,
    template_text: str,
    categories: list[str],
    chunk: CodeChunk,
    owasp_reference: str,
    secure_rules: str,
    few_shot_examples: list[dict[str, Any]],
) -> str:
    return _replace_many(
        template_text,
        {
            "__CATEGORY_LIST__": ", ".join(categories) if categories else "(none)",
            "__OWASP_REFERENCE__": owasp_reference,
            "__SECURE_RULES__": secure_rules,
            "__FEW_SHOT__": json.dumps(few_shot_examples, indent=2),
            "__CODE_CHUNK__": json.dumps(
                {
                    "file_path": chunk.file_path,
                    "chunk_id": chunk.id,
                    "line_start": chunk.start_line,
                    "line_end": chunk.end_line,
                    "code": chunk.content,
                },
                indent=2,
            ),
        },
    )


def render_verifier_prompt(
    *,
    template_text: str,
    findings: list[Finding],
    scope_index: dict[str, int],
    owasp_reference: str,
    secure_rules: str,
) -> str:
    payload = [f.model_dump() for f in findings]
    return _replace_many(
        template_text,
        {
            "__OWASP_REFERENCE__": owasp_reference,
            "__SECURE_RULES__": secure_rules,
            "__CANDIDATES_JSON__": json.dumps(payload, indent=2),
            "__SCOPE_INDEX_JSON__": json.dumps(scope_index, indent=2),
        },
    )


def render_aggregator_prompt(template_text: str, findings: list[Finding]) -> str:
    payload = [f.model_dump() for f in findings]
    return _replace_many(
        template_text,
        {"__VERIFIED_FINDINGS_JSON__": json.dumps(payload, indent=2)},
    )

