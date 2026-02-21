from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from secure_inspector.models import Finding, FindingStatus

MIN_SEMANTIC_MATCH_CONFIDENCE = 0.6
MAX_CANDIDATE_REFS = 12
ProgressCallback = Callable[[int, str], None]


@dataclass
class MatchResult:
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    false_positives: list[dict[str, str]]
    misses: list[dict[str, str]]


class JSONAsker(Protocol):
    def ask_json(
        self,
        *,
        prompt: str,
        system: str = "You are a secure code analysis assistant.",
    ) -> dict[str, Any]:
        ...


@dataclass
class AIAssistedDecision:
    ai_id: str
    best_match_id: str | None
    is_match: bool
    match_confidence: float
    reason: str


def _normalized_path(path: str) -> str:
    return path.replace("\\", "/").strip().lower()


def _line_midpoint(start: int, end: int) -> float:
    return (start + end) / 2.0


def _line_distance(a: Finding, b: Finding) -> float:
    return abs(
        _line_midpoint(a.line_start, a.line_end) - _line_midpoint(b.line_start, b.line_end)
    )


def _line_distance_ranges(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    if b_end < a_start:
        return a_start - b_end
    if a_end < b_start:
        return b_start - a_end
    return 0


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))


def _safe_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _emit_progress(
    progress_callback: ProgressCallback | None,
    percent: int,
    message: str,
) -> None:
    if progress_callback is None:
        return
    bounded = max(0, min(100, int(percent)))
    progress_callback(bounded, message)


def _candidate_refs_for_pred(pred: Finding, refs: list[Finding]) -> list[Finding]:
    pred_path = _normalized_path(pred.file_path)
    same_file = [ref for ref in refs if _normalized_path(ref.file_path) == pred_path]

    if same_file:
        pool = same_file
    else:
        pred_name = Path(pred_path).name
        same_filename = [ref for ref in refs if Path(_normalized_path(ref.file_path)).name == pred_name]
        pool = same_filename if same_filename else refs

    same_category = [ref for ref in pool if ref.owasp_category == pred.owasp_category]
    other_categories = [ref for ref in pool if ref.owasp_category != pred.owasp_category]

    ordered = same_category + other_categories
    ordered.sort(key=lambda ref: (_line_distance(pred, ref), ref.file_path, ref.line_start))
    return ordered[:MAX_CANDIDATE_REFS]


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "owasp_category": finding.owasp_category,
        "risk_summary": finding.risk_summary,
        "evidence": finding.evidence,
    }


def _build_match_prompt(pred: Finding, candidates: list[Finding]) -> str:
    payload = {
        "ai_finding": _finding_payload(pred),
        "candidate_semgrep_findings": [_finding_payload(item) for item in candidates],
        "instructions": {
            "goal": "Decide whether one candidate Semgrep finding is the same vulnerability instance as the AI finding.",
            "matching_rules": [
                "Use semantic equivalence, not exact text matching.",
                "Prefer same file and nearby lines; minor line drift is acceptable.",
                "For repeated patterns in adjacent lines/routes within the same file, allow equivalence when root cause and impact are the same.",
                "Treat OWASP category as a strong signal but not absolute if evidence clearly indicates the same issue.",
                "Return no match if uncertain.",
            ],
            "output_schema": {
                "ai_id": "string",
                "best_match_id": "string or null",
                "is_match": "boolean",
                "match_confidence": "number between 0 and 1",
                "reason": "short explanation",
            },
        },
    }
    return json.dumps(payload, indent=2)


def _validate_decision(
    *,
    pred: Finding,
    candidates: list[Finding],
    raw: dict[str, Any],
) -> AIAssistedDecision:
    candidate_ids = {item.id for item in candidates}
    best_raw = raw.get("best_match_id")
    best_match_id = None
    if best_raw is not None:
        parsed = str(best_raw).strip()
        if parsed and parsed.lower() not in {"null", "none"}:
            best_match_id = parsed

    reason = str(raw.get("reason", "")).strip() or "No reason provided by AI matcher."
    confidence = _safe_float(raw.get("match_confidence"), default=0.0)
    is_match = _safe_bool(raw.get("is_match"))

    if best_match_id and best_match_id not in candidate_ids:
        return AIAssistedDecision(
            ai_id=pred.id,
            best_match_id=None,
            is_match=False,
            match_confidence=0.0,
            reason="Matcher returned an invalid Semgrep ID outside candidate set.",
        )

    if not best_match_id:
        is_match = False

    if confidence < MIN_SEMANTIC_MATCH_CONFIDENCE:
        is_match = False
        reason = (
            f"Low semantic match confidence ({confidence:.2f}) below threshold "
            f"{MIN_SEMANTIC_MATCH_CONFIDENCE:.2f}. {reason}"
        )

    return AIAssistedDecision(
        ai_id=pred.id,
        best_match_id=best_match_id,
        is_match=is_match,
        match_confidence=confidence,
        reason=reason,
    )


def _load_findings(report_path: str | Path) -> list[Finding]:
    p = Path(report_path)
    data = json.loads(p.read_text(encoding="utf-8"))
    rows = data.get("findings", [])
    out: list[Finding] = []
    for row in rows:
        try:
            out.append(Finding(**row))
        except Exception:  # noqa: BLE001
            continue
    return out


def _verified_findings(findings: list[Finding]) -> list[Finding]:
    return [finding for finding in findings if finding.status == FindingStatus.VERIFIED]


def _equivalence_key(finding: Finding) -> tuple[str, int, int, str]:
    line_start, line_end = finding.normalized_line_range()
    return (
        _normalized_path(finding.file_path),
        line_start,
        line_end,
        finding.owasp_category.strip(),
    )


def _normalized_tokens(text: str) -> set[str]:
    parts = re.findall(r"[a-z0-9_/.-]+", text.lower())
    return {p for p in parts if len(p) >= 4}


def _finding_text_tokens(finding: Finding) -> set[str]:
    return _normalized_tokens(f"{finding.risk_summary} {finding.evidence}")


def _richness_score(finding: Finding) -> int:
    return len(finding.evidence or "") + len(finding.risk_summary or "")


def _deduplicate_equivalent_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    deduped: dict[tuple[str, int, int, str], Finding] = {}
    order: list[tuple[str, int, int, str]] = []
    removed = 0
    for finding in findings:
        key = _equivalence_key(finding)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = finding
            order.append(key)
            continue
        removed += 1
        if _richness_score(finding) > _richness_score(existing):
            deduped[key] = finding
    return [deduped[key] for key in order], removed


def _is_near_equivalent_ai(a: Finding, b: Finding) -> bool:
    if _normalized_path(a.file_path) != _normalized_path(b.file_path):
        return False
    if a.owasp_category != b.owasp_category:
        return False

    a_start, a_end = a.normalized_line_range()
    b_start, b_end = b.normalized_line_range()
    distance = _line_distance_ranges(a_start, a_end, b_start, b_end)
    tokens_a = _finding_text_tokens(a)
    tokens_b = _finding_text_tokens(b)
    shared = len(tokens_a & tokens_b)

    if distance <= 6:
        return True

    if (
        _normalized_path(a.file_path).endswith("server.ts")
        and a.owasp_category.startswith("A01:")
        and distance <= 30
        and shared >= 3
    ):
        return True

    if (
        _normalized_path(a.file_path).endswith("lib/insecurity.ts")
        and a.owasp_category.startswith("A07:")
        and distance <= 25
        and shared >= 4
    ):
        return True

    return False


def _deduplicate_equivalent_ai_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    ordered = sorted(
        findings,
        key=lambda f: (
            _normalized_path(f.file_path),
            f.owasp_category,
            f.line_start,
            f.line_end,
            -_richness_score(f),
        ),
    )
    kept: list[Finding] = []
    removed = 0
    for candidate in ordered:
        replaced = False
        for idx, existing in enumerate(kept):
            if not _is_near_equivalent_ai(existing, candidate):
                continue
            removed += 1
            if _richness_score(candidate) > _richness_score(existing):
                kept[idx] = candidate
            replaced = True
            break
        if not replaced:
            kept.append(candidate)
    return kept, removed


def _semantic_match_against_baseline(
    predicted: list[Finding],
    baseline: list[Finding],
    llm_client: JSONAsker,
    progress_callback: ProgressCallback | None = None,
    progress_start: int = 20,
    progress_end: int = 90,
) -> MatchResult:
    preds = [item for item in predicted if item.status == FindingStatus.VERIFIED]
    refs = [item for item in baseline if item.status == FindingStatus.VERIFIED]
    ref_indexes_by_id: dict[str, list[int]] = {}
    for ref_index, ref in enumerate(refs):
        ref_indexes_by_id.setdefault(ref.id, []).append(ref_index)

    decisions: dict[int, AIAssistedDecision] = {}
    selected_matches: list[tuple[int, AIAssistedDecision]] = []

    total_preds = len(preds)
    if total_preds == 0:
        _emit_progress(progress_callback, progress_end, "No verified AI findings to compare")

    for pred_index, pred in enumerate(preds, start=1):
        candidates = _candidate_refs_for_pred(pred, refs)
        if not candidates:
            decisions[pred_index - 1] = AIAssistedDecision(
                ai_id=pred.id,
                best_match_id=None,
                is_match=False,
                match_confidence=0.0,
                reason="No Semgrep candidate available for semantic evaluation.",
            )
            step = progress_start + int((progress_end - progress_start) * (pred_index / total_preds))
            _emit_progress(
                progress_callback,
                step,
                f"Matching finding {pred_index}/{total_preds}",
            )
            continue

        prompt = _build_match_prompt(pred, candidates)
        try:
            raw = llm_client.ask_json(
                system=(
                    "You are a strict security-finding matcher. "
                    "Return JSON only and avoid optimistic matching."
                ),
                prompt=prompt,
            )
            decision = _validate_decision(pred=pred, candidates=candidates, raw=raw)
        except Exception as exc:  # noqa: BLE001
            decision = AIAssistedDecision(
                ai_id=pred.id,
                best_match_id=None,
                is_match=False,
                match_confidence=0.0,
                reason=f"AI-assisted matcher failed for this finding: {exc}",
            )

        decisions[pred_index - 1] = decision
        if decision.is_match and decision.best_match_id and decision.best_match_id in ref_indexes_by_id:
            selected_matches.append((pred_index - 1, decision))

        step = progress_start + int((progress_end - progress_start) * (pred_index / total_preds))
        _emit_progress(
            progress_callback,
            step,
            f"Matching finding {pred_index}/{total_preds}",
        )

    selected_matches.sort(key=lambda item: item[1].match_confidence, reverse=True)
    matched_pred_indexes: set[int] = set()
    matched_ref_indexes: set[int] = set()

    for pred_index, decision in selected_matches:
        if pred_index in matched_pred_indexes:
            continue
        if decision.best_match_id is None:
            continue

        candidate_ref_indexes = ref_indexes_by_id.get(decision.best_match_id, [])
        chosen_ref_index: int | None = None
        for ref_index in candidate_ref_indexes:
            if ref_index not in matched_ref_indexes:
                chosen_ref_index = ref_index
                break

        if chosen_ref_index is None:
            continue
        matched_pred_indexes.add(pred_index)
        matched_ref_indexes.add(chosen_ref_index)

    tp = len(matched_pred_indexes)
    fp = len(preds) - tp
    fn = len(refs) - tp
    precision = tp / len(preds) if preds else 0.0
    recall = tp / len(refs) if refs else 0.0

    false_positives: list[dict[str, str]] = []
    for pred_index, pred in enumerate(preds):
        if pred_index in matched_pred_indexes:
            continue
        decision = decisions.get(pred_index)
        reason = "No semantic Semgrep match accepted."
        if decision is not None:
            if decision.best_match_id:
                competing_ref_indexes = ref_indexes_by_id.get(decision.best_match_id, [])
                is_competing = any(idx in matched_ref_indexes for idx in competing_ref_indexes)
            else:
                is_competing = False
            if is_competing:
                reason = (
                    "Predicted issue competed for an already matched Semgrep finding with lower confidence. "
                    + decision.reason
                )
            else:
                reason = decision.reason
        false_positives.append(
            {
                "id": pred.id,
                "file_path": pred.file_path,
                "owasp_category": pred.owasp_category,
                "reason": reason,
            }
        )

    misses: list[dict[str, str]] = []
    for ref_index, ref in enumerate(refs):
        if ref_index in matched_ref_indexes:
            continue
        misses.append(
            {
                "id": ref.id,
                "file_path": ref.file_path,
                "owasp_category": ref.owasp_category,
                "reason": "No AI finding was semantically matched to this Semgrep reference.",
            }
        )

    return MatchResult(
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        false_positives=false_positives,
        misses=misses,
    )


def compare_reports(
    *,
    ai_report_path: str | Path,
    baseline_report_path: str | Path,
    llm_client: JSONAsker,
    progress_callback: ProgressCallback | None = None,
    progress_start: int = 10,
    progress_end: int = 95,
) -> dict[str, MatchResult | int]:
    start = max(0, min(100, int(progress_start)))
    end = max(start, min(100, int(progress_end)))
    load_phase = start
    filter_phase = start + int((end - start) * 0.1)
    semantic_start = start + int((end - start) * 0.15)
    semantic_end = start + int((end - start) * 0.95)

    _emit_progress(progress_callback, load_phase, "Loading AI and baseline reports")
    ai_findings = _load_findings(ai_report_path)
    baseline_findings = _load_findings(baseline_report_path)
    ai_verified_raw = _verified_findings(ai_findings)
    ai_verified_exact, ai_duplicates_removed_exact = _deduplicate_equivalent_findings(ai_verified_raw)
    ai_verified, ai_duplicates_removed_near = _deduplicate_equivalent_ai_findings(ai_verified_exact)
    ai_duplicates_removed = ai_duplicates_removed_exact + ai_duplicates_removed_near
    baseline_verified_raw = _verified_findings(baseline_findings)
    baseline_verified, baseline_duplicates_removed = _deduplicate_equivalent_findings(
        baseline_verified_raw
    )
    _emit_progress(progress_callback, filter_phase, "Filtering verified findings")
    ai_score = _semantic_match_against_baseline(
        ai_verified,
        baseline_verified,
        llm_client,
        progress_callback=progress_callback,
        progress_start=semantic_start,
        progress_end=semantic_end,
    )
    _emit_progress(progress_callback, end, "Finalizing metrics")
    return {
        "ai": ai_score,
        "ai_total": len(ai_verified),
        "ai_duplicates_removed": ai_duplicates_removed,
        "baseline_total": len(baseline_verified),
        "baseline_duplicates_removed": baseline_duplicates_removed,
        "matched": ai_score.tp,
    }


def write_comparison_markdown(
    *,
    out_path: str | Path,
    ai_score: MatchResult,
    ai_total: int,
    baseline_total: int,
    ai_duplicates_removed: int = 0,
    baseline_duplicates_removed: int = 0,
) -> None:
    match_rate = ai_score.tp / baseline_total if baseline_total else 0.0
    ai_only_rate = ai_score.fp / ai_total if ai_total else 0.0
    semgrep_only_rate = ai_score.fn / baseline_total if baseline_total else 0.0

    lines: list[str] = []
    lines.append("# AI vs Semgrep Baseline Comparison")
    lines.append("")
    lines.append("Evaluation method: **AI-assisted semantic matching** (strict metric removed).")
    lines.append("")
    lines.append(
        "| Reference | AI Verified | Semgrep Verified | Matched | AI-only | Semgrep-only | Precision | Recall |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(
        f"| Semgrep | {ai_total} | {baseline_total} | {ai_score.tp} | {ai_score.fp} | {ai_score.fn} | {ai_score.precision:.2f} | {ai_score.recall:.2f} |"
    )
    lines.append("")
    lines.append("## Analysis Summary")
    lines.append("")
    lines.append(
        f"- Baseline coverage match rate: **{match_rate:.2%}** ({ai_score.tp}/{baseline_total if baseline_total else 0})."
    )
    lines.append(
        f"- AI-only finding rate: **{ai_only_rate:.2%}** ({ai_score.fp}/{ai_total if ai_total else 0})."
    )
    lines.append(
        f"- Semgrep-only finding rate: **{semgrep_only_rate:.2%}** ({ai_score.fn}/{baseline_total if baseline_total else 0})."
    )
    if ai_duplicates_removed > 0:
        lines.append(
            f"- AI normalization: removed **{ai_duplicates_removed}** equivalent AI duplicate(s) before scoring."
        )
    if baseline_duplicates_removed > 0:
        lines.append(
            f"- Baseline normalization: removed **{baseline_duplicates_removed}** equivalent Semgrep duplicate(s) before scoring."
        )
    if ai_total > 0 and ai_score.precision < 0.2:
        lines.append(
            "- Interpretation: AI output is currently over-sensitive compared to Semgrep and likely includes many false positives."
        )
    if baseline_total > 0 and ai_score.recall < 0.5:
        lines.append(
            "- Interpretation: AI misses a notable subset of Semgrep findings under semantic matching, so category/rule coverage should be improved."
        )
    lines.append(
        "- Recommended tuning: improve specialist/verifier prompts, strengthen evidence requirements, and refine category routing."
    )
    lines.append("")
    lines.append("## False Positives (AI)")
    lines.append("")
    if ai_score.false_positives:
        for fp in ai_score.false_positives:
            lines.append(
                f"- `{fp['id']}` `{fp['file_path']}` `{fp['owasp_category']}`: {fp['reason']}"
            )
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Misses (AI)")
    lines.append("")
    if ai_score.misses:
        for miss in ai_score.misses:
            lines.append(
                f"- `{miss['id']}` `{miss['file_path']}` `{miss['owasp_category']}`: {miss['reason']}"
            )
    else:
        lines.append("- None")
    lines.append("")
    lines.append("## Why False Positives Happen")
    lines.append("")
    lines.append(
        "- AI findings can still over-interpret code context, even when semantic matching is used for evaluation."
    )
    lines.append("")
    lines.append("## Why Misses Happen")
    lines.append("")
    lines.append(
        "- Limited scan scope/chunk boundaries and conservative verifier thresholds can still hide true issues."
    )
    Path(out_path).write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
