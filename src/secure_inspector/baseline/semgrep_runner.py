from __future__ import annotations

import json
import os
import subprocess
from hashlib import sha1
from pathlib import Path
from typing import Any, Callable

from secure_inspector.config import ScopeConfig
from secure_inspector.models import Finding, FindingStatus, RunMetadata
from secure_inspector.reporting import write_json_report
from secure_inspector.scanner import collect_scope_files


ProgressCallback = Callable[[int, str], None]


def _emit_progress(
    progress_callback: ProgressCallback | None,
    percent: int,
    message: str,
) -> None:
    if progress_callback is None:
        return
    bounded = max(0, min(100, int(percent)))
    progress_callback(bounded, message)


def _run_semgrep_command(command: list[str]) -> dict[str, Any]:
    # Force UTF-8 to avoid Windows codepage encoding failures on Semgrep rule content.
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(  # noqa: S603
        command,
        capture_output=True,
        text=True,
        check=False,
        env=env,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep command failed (code {result.returncode}): {result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse Semgrep JSON output: {exc}") from exc


def _map_to_owasp(result: dict[str, Any]) -> str:
    text = " ".join(
        [
            str(result.get("check_id", "")),
            str(result.get("extra", {}).get("message", "")),
            str(result.get("extra", {}).get("metadata", {})),
        ]
    ).lower()

    if any(token in text for token in ["sql", "nosql", "command injection", "injection"]):
        return "A03:2021-Injection"
    if any(token in text for token in ["access control", "idor", "authorization"]):
        return "A01:2021-Broken Access Control"
    if any(token in text for token in ["crypto", "cipher", "hash", "encryption", "tls"]):
        return "A02:2021-Cryptographic Failures"
    if any(token in text for token in ["auth", "session", "jwt", "password"]):
        return "A07:2021-Identification and Authentication Failures"
    return "A05:2021-Security Misconfiguration"


def _semgrep_finding_id(file_path: str, line_start: int, line_end: int, category: str) -> str:
    raw = f"semgrep|{file_path}|{line_start}|{line_end}|{category}".lower()
    return f"S-{sha1(raw.encode('utf-8')).hexdigest()[:12]}"


def run_semgrep_baseline(
    *,
    target_path: str | Path,
    scope: ScopeConfig,
    out_json_path: str | Path,
    progress_callback: ProgressCallback | None = None,
) -> list[Finding]:
    _emit_progress(progress_callback, 30, "Collecting files in scope")
    root = Path(target_path).resolve()
    scoped_files = collect_scope_files(root, scope)
    scoped_rel = {p.relative_to(root).as_posix() for p in scoped_files}

    command_variants = [
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(root)],
        ["semgrep", "--config", "auto", "--json", str(root)],
    ]

    semgrep_data: dict[str, Any] | None = None
    last_error: Exception | None = None
    for idx, command in enumerate(command_variants, start=1):
        _emit_progress(progress_callback, 45, f"Running Semgrep scan (attempt {idx})")
        try:
            semgrep_data = _run_semgrep_command(command)
            break
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    if semgrep_data is None:
        raise RuntimeError(f"Unable to run Semgrep baseline: {last_error}")

    _emit_progress(progress_callback, 70, "Normalizing Semgrep results")
    findings: list[Finding] = []
    for result in semgrep_data.get("results", []):
        if not isinstance(result, dict):
            continue

        raw_path = str(result.get("path", ""))
        if not raw_path:
            continue
        abs_path = Path(raw_path).resolve()
        try:
            rel_path = abs_path.relative_to(root).as_posix()
        except ValueError:
            # semgrep may emit relative paths depending on invocation
            rel_path = raw_path.replace("\\", "/")
        if rel_path not in scoped_rel:
            continue

        start = int(result.get("start", {}).get("line", 1))
        end = int(result.get("end", {}).get("line", start))
        category = _map_to_owasp(result)
        message = str(result.get("extra", {}).get("message", "Semgrep finding")).strip()
        fix = (
            str(result.get("extra", {}).get("fix", "")).strip()
            or "Apply secure coding remediation for the indicated pattern."
        )

        findings.append(
            Finding(
                id=_semgrep_finding_id(rel_path, start, end, category),
                file_path=rel_path,
                line_start=max(1, start),
                line_end=max(1, end),
                owasp_category=category,
                risk_summary=message[:600],
                fix_recommendation=fix[:600],
                confidence=0.7,
                evidence=message[:600],
                source_agent="Semgrep",
                status=FindingStatus.VERIFIED,
            )
        )

    metadata = RunMetadata.new(
        target_path=str(root),
        scope_files=sorted(scoped_rel),
        enabled_categories=sorted({f.owasp_category for f in findings}),
        enabled_agents=["Semgrep"],
        model="semgrep-auto",
        prompt_versions={},
    )
    _emit_progress(progress_callback, 90, "Writing baseline report")
    write_json_report(out_path=out_json_path, metadata=metadata, findings=findings)
    return findings
