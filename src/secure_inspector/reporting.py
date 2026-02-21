from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from secure_inspector.models import Finding, FindingStatus, ReportPayload, RunMetadata


def compute_stats(findings: list[Finding]) -> dict[str, object]:
    status_counts = Counter(f.status.value for f in findings)
    category_counts = Counter(f.owasp_category for f in findings)
    return {
        "total_findings": len(findings),
        "status_counts": dict(status_counts),
        "category_counts": dict(category_counts),
        "verified_count": status_counts.get(FindingStatus.VERIFIED.value, 0),
    }


def write_json_report(
    *,
    out_path: str | Path,
    metadata: RunMetadata,
    findings: list[Finding],
) -> None:
    payload = ReportPayload(
        run_metadata=metadata,
        findings=findings,
        stats=compute_stats(findings),
    )
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(payload.model_dump_json(indent=2), encoding="utf-8")


def write_markdown_report(
    *,
    out_path: str | Path,
    metadata: RunMetadata,
    findings: list[Finding],
) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    stats = compute_stats(findings)

    verified = [f for f in findings if f.status == FindingStatus.VERIFIED]
    lines: list[str] = []
    lines.append("# Secure Code Inspector Report")
    lines.append("")
    lines.append(f"- Timestamp: `{metadata.timestamp}`")
    lines.append(f"- Target path: `{metadata.target_path}`")
    lines.append(f"- Model: `{metadata.model}`")
    lines.append(f"- Enabled agents: `{', '.join(metadata.enabled_agents)}`")
    lines.append(f"- Scope files: `{len(metadata.scope_files)}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: **{stats['total_findings']}**")
    lines.append(f"- Verified findings: **{stats['verified_count']}**")
    lines.append("")
    lines.append("## Verified Findings")
    lines.append("")

    if not verified:
        lines.append("No verified findings were produced.")
    else:
        for finding in verified:
            lines.append(f"### {finding.id} - {finding.owasp_category}")
            lines.append("")
            lines.append(f"- File: `{finding.file_path}`")
            lines.append(f"- Lines: `{finding.line_start}-{finding.line_end}`")
            lines.append(f"- Confidence: `{finding.confidence:.2f}`")
            lines.append(f"- Source agent(s): `{finding.source_agent}`")
            lines.append(f"- Risk summary: {finding.risk_summary}")
            lines.append(f"- Fix recommendation: {finding.fix_recommendation}")
            if finding.evidence:
                lines.append(f"- Evidence: {finding.evidence}")
            lines.append("")

    p.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")

