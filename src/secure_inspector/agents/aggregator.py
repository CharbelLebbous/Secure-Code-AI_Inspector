from __future__ import annotations

from collections import defaultdict
from typing import Any

from secure_inspector.llm_client import LLMClient
from secure_inspector.models import Finding, FindingStatus
from secure_inspector.prompts import render_aggregator_prompt


class AggregatorAgent:
    NAME = "AggregatorAgent"

    def __init__(self, *, template_text: str) -> None:
        self.template_text = template_text

    @staticmethod
    def _dedup_verified(findings: list[Finding]) -> list[Finding]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            if f.status != FindingStatus.VERIFIED:
                continue
            grouped[f.fingerprint()].append(f)

        merged: list[Finding] = []
        for _, group in grouped.items():
            top = max(group, key=lambda x: x.confidence)
            source_agents = sorted({item.source_agent for item in group})
            merged.append(
                top.model_copy(
                    update={
                        "source_agent": ",".join(source_agents),
                        "evidence": " | ".join(
                            [x.evidence for x in group if x.evidence][:3]
                        )[:700],
                    }
                )
            )

        merged.sort(key=lambda x: (-x.confidence, x.file_path, x.line_start))
        final: list[Finding] = []
        for idx, finding in enumerate(merged, start=1):
            final.append(finding.model_copy(update={"id": f"F-{idx:04d}"}))
        return final

    @staticmethod
    def _parse_aggregator_payload(payload: dict[str, Any]) -> list[Finding]:
        rows = payload.get("final_findings", [])
        if not isinstance(rows, list):
            return []
        parsed: list[Finding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                parsed.append(Finding(**row))
            except Exception:  # noqa: BLE001
                continue
        return parsed

    def run(self, *, findings: list[Finding], llm_client: LLMClient) -> list[Finding]:
        local = self._dedup_verified(findings)
        if not local:
            return []

        prompt = render_aggregator_prompt(self.template_text, local)
        try:
            payload = llm_client.ask_json(prompt=prompt, system=self.NAME)
            parsed = self._parse_aggregator_payload(payload)
            if parsed:
                # enforce verified-only and deterministic ids.
                verified = [
                    p.model_copy(update={"status": FindingStatus.VERIFIED}) for p in parsed
                ]
                verified.sort(key=lambda x: (-x.confidence, x.file_path, x.line_start))
                out: list[Finding] = []
                for idx, finding in enumerate(verified, start=1):
                    out.append(finding.model_copy(update={"id": f"F-{idx:04d}"}))
                return out
        except Exception:  # noqa: BLE001
            pass
        return local

