from __future__ import annotations

from typing import Any

from secure_inspector.llm_client import LLMClient
from secure_inspector.models import Finding, FindingStatus
from secure_inspector.prompts import render_verifier_prompt


class VerifierAgent:
    NAME = "VerifierAgent"
    MAX_LINE_SPAN = 80

    def __init__(self, *, template_text: str) -> None:
        self.template_text = template_text

    @staticmethod
    def _local_sanity_filter(
        findings: list[Finding], scope_index: dict[str, int]
    ) -> tuple[list[Finding], list[Finding]]:
        valid: list[Finding] = []
        rejected: list[Finding] = []
        for finding in findings:
            max_line = scope_index.get(finding.file_path)
            if max_line is None:
                rejected.append(finding.model_copy(update={"status": FindingStatus.REJECTED}))
                continue
            if finding.line_start < 1 or finding.line_end < finding.line_start:
                rejected.append(finding.model_copy(update={"status": FindingStatus.REJECTED}))
                continue
            if finding.line_start > max_line or finding.line_end > max_line:
                rejected.append(finding.model_copy(update={"status": FindingStatus.REJECTED}))
                continue
            valid.append(finding)
        return valid, rejected

    @classmethod
    def _category_precision_guard(cls, finding: Finding) -> bool:
        span = finding.line_end - finding.line_start + 1
        if span > cls.MAX_LINE_SPAN:
            return False

        category = finding.owasp_category
        text = f"{finding.risk_summary} {finding.evidence}".lower()
        path = finding.file_path.replace("\\", "/").lower()

        if category.startswith("A07:"):
            required_tokens = [
                "password",
                "credential",
                "token",
                "jwt",
                "session",
                "cookie",
                "secret",
                "login",
                "auth",
            ]
            if not any(token in text for token in required_tokens):
                return False
            a01_style_tokens = [
                "ownership",
                "access control",
                "directory listing",
                "serveindex",
                "express.static",
                "req.params.id",
                "basket",
                "route uses req.params.id",
            ]
            if any(token in text for token in a01_style_tokens):
                return False

        if category.startswith("A03:"):
            sink_tokens = [
                "sequelize.query",
                "db.query",
                "eval(",
                "raw sql",
                "command execution",
                "query(",
            ]
            if not any(token in text for token in sink_tokens):
                return False

        if category.startswith("A01:"):
            if path.endswith("server.ts"):
                concrete_server_patterns = [
                    "serveindex",
                    "express.static",
                    "directory listing",
                    "/ftp",
                    "/encryptionkeys",
                    "/support/logs",
                ]
                if not any(token in text for token in concrete_server_patterns):
                    return False
                speculative_server_patterns = [
                    "no visible authorization",
                    "authorization middleware or checks are shown",
                    "without visible authorization",
                    "not shown",
                ]
                if any(token in text for token in speculative_server_patterns):
                    return False
            else:
                subject_tokens = [
                    "req.user",
                    "authenticated user",
                    "user.id",
                    "user?.bid",
                ]
                object_tokens = [
                    "owner",
                    "userid",
                    "basketid",
                    "belongs to",
                    "basket.userid",
                    "order.userid",
                ]
                if not any(token in text for token in subject_tokens):
                    return False
                if not any(token in text for token in object_tokens):
                    return False

        return True

    def run(
        self,
        *,
        findings: list[Finding],
        scope_index: dict[str, int],
        llm_client: LLMClient,
        owasp_reference: str,
        secure_rules: str,
        verified_min_confidence: float,
    ) -> list[Finding]:
        valid, rejected = self._local_sanity_filter(findings, scope_index)
        if not valid:
            return rejected

        prompt = render_verifier_prompt(
            template_text=self.template_text,
            findings=valid,
            scope_index=scope_index,
            owasp_reference=owasp_reference,
            secure_rules=secure_rules,
        )

        verified_ids: set[str] = set()
        normalized_categories: dict[str, str] = {}
        rejected_by_llm: set[str] = set()

        try:
            payload = llm_client.ask_json(prompt=prompt, system=self.NAME)
            verified_raw = payload.get("verified_ids", [])
            if isinstance(verified_raw, list):
                verified_ids = {str(x) for x in verified_raw}
            normalized_raw = payload.get("normalized_categories", {})
            if isinstance(normalized_raw, dict):
                normalized_categories = {str(k): str(v) for k, v in normalized_raw.items()}
            rejected_raw = payload.get("rejected", [])
            if isinstance(rejected_raw, list):
                for item in rejected_raw:
                    if isinstance(item, dict) and "id" in item:
                        rejected_by_llm.add(str(item["id"]))
        except Exception:  # noqa: BLE001
            # Fail-safe: confidence threshold fallback.
            pass

        out: list[Finding] = []
        for finding in valid:
            updated_category = normalized_categories.get(finding.id, finding.owasp_category)

            # LLM decision has priority if present.
            if finding.id in verified_ids:
                candidate = finding.model_copy(
                    update={
                        "owasp_category": updated_category,
                        "status": FindingStatus.VERIFIED,
                    }
                )
                if not self._category_precision_guard(candidate):
                    out.append(candidate.model_copy(update={"status": FindingStatus.REJECTED}))
                    continue
                out.append(
                    candidate
                )
                continue
            if finding.id in rejected_by_llm:
                out.append(
                    finding.model_copy(
                        update={
                            "owasp_category": updated_category,
                            "status": FindingStatus.REJECTED,
                        }
                    )
                )
                continue

            # Confidence fallback.
            status = (
                FindingStatus.VERIFIED
                if finding.confidence >= verified_min_confidence
                else FindingStatus.REJECTED
            )
            candidate = finding.model_copy(
                update={
                    "owasp_category": updated_category,
                    "status": status,
                }
            )
            if candidate.status == FindingStatus.VERIFIED and not self._category_precision_guard(
                candidate
            ):
                candidate = candidate.model_copy(update={"status": FindingStatus.REJECTED})
            out.append(
                candidate
            )

        out.extend(rejected)
        return out
