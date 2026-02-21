from __future__ import annotations

import json

from secure_inspector.services import run_compare_pipeline


class _StubMatcher:
    def ask_json(self, *, prompt: str, system: str = "") -> dict[str, object]:
        _ = (prompt, system)
        return {
            "ai_id": "F-0001",
            "best_match_id": "S-0001",
            "is_match": True,
            "match_confidence": 0.95,
            "reason": "Same vulnerability instance.",
        }


def test_run_compare_pipeline_generates_markdown(tmp_path):
    ai_report = {
        "run_metadata": {},
        "stats": {},
        "findings": [
            {
                "id": "F-0001",
                "file_path": "routes/login.ts",
                "line_start": 10,
                "line_end": 12,
                "owasp_category": "A03:2021-Injection",
                "risk_summary": "risk",
                "fix_recommendation": "fix",
                "confidence": 0.8,
                "evidence": "evidence",
                "source_agent": "InjectionSpecialistAgent",
                "status": "verified",
            }
        ],
    }
    baseline_report = {
        "run_metadata": {},
        "stats": {},
        "findings": [
            {
                "id": "S-0001",
                "file_path": "routes/login.ts",
                "line_start": 11,
                "line_end": 14,
                "owasp_category": "A03:2021-Injection",
                "risk_summary": "risk",
                "fix_recommendation": "fix",
                "confidence": 0.7,
                "evidence": "evidence",
                "source_agent": "Semgrep",
                "status": "verified",
            }
        ],
    }
    ai_path = tmp_path / "ai.json"
    bl_path = tmp_path / "baseline.json"
    out_path = tmp_path / "comparison.md"
    ai_path.write_text(json.dumps(ai_report), encoding="utf-8")
    bl_path.write_text(json.dumps(baseline_report), encoding="utf-8")

    result = run_compare_pipeline(
        ai_report=ai_path,
        baseline_report=bl_path,
        out_path=out_path,
        llm_client=_StubMatcher(),
    )

    assert out_path.exists()
    assert result["ai"]["tp"] == 1
    assert result["ai"]["precision"] == 1.0
    assert result["summary"]["ai_duplicates_removed"] == 0
    assert result["summary"]["baseline_duplicates_removed"] == 0
    assert result["summary"]["matched"] == 1
