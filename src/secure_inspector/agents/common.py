from __future__ import annotations

from hashlib import sha1
from typing import Any, Callable

from secure_inspector.chunker import CodeChunk
from secure_inspector.llm_client import LLMClient
from secure_inspector.models import Finding, FindingStatus
from secure_inspector.prompts import render_specialist_prompt


ChunkProgressCallback = Callable[[int, int], None]


def _candidate_id(
    *,
    source_agent: str,
    file_path: str,
    line_start: int,
    line_end: int,
    owasp_category: str,
) -> str:
    raw = f"{source_agent}|{file_path}|{line_start}|{line_end}|{owasp_category}".lower()
    digest = sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"C-{digest}"


def _safe_int(value: Any, default_value: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default_value


def _safe_float(value: Any, default_value: float) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default_value
    if out < 0.0:
        return 0.0
    if out > 1.0:
        return 1.0
    return out


def parse_specialist_findings(
    *,
    payload: dict[str, Any],
    source_agent: str,
    chunk: CodeChunk,
    allowed_categories: list[str],
    candidate_min_confidence: float,
) -> list[Finding]:
    rows = payload.get("findings", [])
    if not isinstance(rows, list):
        return []

    findings: list[Finding] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        file_path = str(row.get("file_path") or chunk.file_path)
        line_start = _safe_int(row.get("line_start"), chunk.start_line)
        line_end = _safe_int(row.get("line_end"), chunk.end_line)
        if line_end < line_start:
            line_start, line_end = line_end, line_start
        category = str(row.get("owasp_category") or "").strip()
        if not category:
            continue
        if allowed_categories and category not in allowed_categories:
            continue
        confidence = _safe_float(row.get("confidence"), 0.5)
        if confidence < candidate_min_confidence:
            continue
        finding = Finding(
            id=_candidate_id(
                source_agent=source_agent,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                owasp_category=category,
            ),
            file_path=file_path,
            line_start=max(1, line_start),
            line_end=max(1, line_end),
            owasp_category=category,
            risk_summary=str(row.get("risk_summary") or "").strip()[:600],
            fix_recommendation=str(row.get("fix_recommendation") or "").strip()[:600],
            confidence=confidence,
            evidence=str(row.get("evidence") or "").strip()[:600],
            source_agent=source_agent,
            status=FindingStatus.CANDIDATE,
        )
        findings.append(finding)
    return findings


def run_specialist_over_chunks(
    *,
    agent_name: str,
    categories: list[str],
    chunks: list[CodeChunk],
    llm_client: LLMClient,
    template_text: str,
    owasp_reference: str,
    secure_rules: str,
    few_shot_examples: list[dict[str, Any]],
    candidate_min_confidence: float,
    progress_callback: ChunkProgressCallback | None = None,
) -> list[Finding]:
    if not categories:
        return []

    findings: list[Finding] = []
    total_chunks = len(chunks)
    for idx, chunk in enumerate(chunks, start=1):
        prompt = render_specialist_prompt(
            template_text=template_text,
            categories=categories,
            chunk=chunk,
            owasp_reference=owasp_reference,
            secure_rules=secure_rules,
            few_shot_examples=few_shot_examples,
        )
        try:
            payload = llm_client.ask_json(prompt=prompt, system=agent_name)
            findings.extend(
                parse_specialist_findings(
                    payload=payload,
                    source_agent=agent_name,
                    chunk=chunk,
                    allowed_categories=categories,
                    candidate_min_confidence=candidate_min_confidence,
                )
            )
        except Exception:  # noqa: BLE001
            continue
        finally:
            if progress_callback is not None:
                progress_callback(idx, total_chunks)
    if progress_callback is not None and total_chunks == 0:
        progress_callback(0, 0)
    return findings
