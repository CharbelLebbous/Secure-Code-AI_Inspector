from __future__ import annotations

from typing import Any, Callable

from secure_inspector.agents.common import run_specialist_over_chunks
from secure_inspector.chunker import CodeChunk
from secure_inspector.llm_client import LLMClient
from secure_inspector.models import Finding


class AccessControlSpecialistAgent:
    NAME = "AccessControlSpecialistAgent"

    def __init__(self, *, template_text: str) -> None:
        self.template_text = template_text

    def run(
        self,
        *,
        categories: list[str],
        chunks: list[CodeChunk],
        llm_client: LLMClient,
        owasp_reference: str,
        secure_rules: str,
        few_shot_examples: list[dict[str, Any]],
        candidate_min_confidence: float,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[Finding]:
        return run_specialist_over_chunks(
            agent_name=self.NAME,
            categories=categories,
            chunks=chunks,
            llm_client=llm_client,
            template_text=self.template_text,
            owasp_reference=owasp_reference,
            secure_rules=secure_rules,
            few_shot_examples=few_shot_examples,
            candidate_min_confidence=candidate_min_confidence,
            progress_callback=progress_callback,
        )
