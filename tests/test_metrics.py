import json

from secure_inspector.eval.metrics import compare_reports


class _StubMatcher:
    def ask_json(self, *, prompt: str, system: str = "") -> dict[str, object]:
        _ = (prompt, system)
        return {
            "ai_id": "F-0001",
            "best_match_id": "S-0001",
            "is_match": True,
            "match_confidence": 0.95,
            "reason": "Same vulnerable SQL query sink and source.",
        }


def test_compare_reports_scores_basic_match(tmp_path):
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
                "line_end": 15,
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
    baseline_path = tmp_path / "baseline.json"
    ai_path.write_text(json.dumps(ai_report), encoding="utf-8")
    baseline_path.write_text(json.dumps(baseline_report), encoding="utf-8")

    out = compare_reports(
        ai_report_path=ai_path,
        baseline_report_path=baseline_path,
        llm_client=_StubMatcher(),
    )
    assert out["ai"].tp == 1
    assert out["ai"].fp == 0
    assert out["ai"].fn == 0
    assert out["ai"].precision == 1.0
    assert out["ai"].recall == 1.0
    assert out["ai_total"] == 1
    assert out["ai_duplicates_removed"] == 0
    assert out["baseline_total"] == 1
    assert out["baseline_duplicates_removed"] == 0
    assert out["matched"] == 1


def test_compare_reports_deduplicates_equivalent_baseline_findings(tmp_path):
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
                "line_end": 15,
                "owasp_category": "A03:2021-Injection",
                "risk_summary": "short",
                "fix_recommendation": "fix",
                "confidence": 0.7,
                "evidence": "short",
                "source_agent": "Semgrep",
                "status": "verified",
            },
            {
                "id": "S-0002",
                "file_path": "routes/login.ts",
                "line_start": 11,
                "line_end": 15,
                "owasp_category": "A03:2021-Injection",
                "risk_summary": "longer message",
                "fix_recommendation": "fix",
                "confidence": 0.7,
                "evidence": "longer evidence",
                "source_agent": "Semgrep",
                "status": "verified",
            },
        ],
    }

    ai_path = tmp_path / "ai.json"
    baseline_path = tmp_path / "baseline.json"
    ai_path.write_text(json.dumps(ai_report), encoding="utf-8")
    baseline_path.write_text(json.dumps(baseline_report), encoding="utf-8")

    out = compare_reports(
        ai_report_path=ai_path,
        baseline_report_path=baseline_path,
        llm_client=_StubMatcher(),
    )
    assert out["ai_duplicates_removed"] == 0
    assert out["baseline_total"] == 1
    assert out["baseline_duplicates_removed"] == 1
