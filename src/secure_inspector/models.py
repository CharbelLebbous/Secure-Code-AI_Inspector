from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from hashlib import sha1
from typing import Any

from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    REJECTED = "rejected"


class Finding(BaseModel):
    id: str
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    owasp_category: str
    risk_summary: str
    fix_recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""
    source_agent: str
    status: FindingStatus = FindingStatus.CANDIDATE

    def fingerprint(self) -> str:
        raw = (
            f"{self.file_path}|{self.line_start}|{self.line_end}|"
            f"{self.owasp_category}".lower()
        )
        return sha1(raw.encode("utf-8")).hexdigest()

    def normalized_line_range(self) -> tuple[int, int]:
        if self.line_end < self.line_start:
            return self.line_end, self.line_start
        return self.line_start, self.line_end


class RunMetadata(BaseModel):
    timestamp: str
    target_path: str
    scope_files: list[str]
    enabled_categories: list[str]
    enabled_agents: list[str]
    model: str
    prompt_versions: dict[str, str]

    @staticmethod
    def new(
        *,
        target_path: str,
        scope_files: list[str],
        enabled_categories: list[str],
        enabled_agents: list[str],
        model: str,
        prompt_versions: dict[str, str],
    ) -> "RunMetadata":
        return RunMetadata(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            target_path=target_path,
            scope_files=scope_files,
            enabled_categories=enabled_categories,
            enabled_agents=enabled_agents,
            model=model,
            prompt_versions=prompt_versions,
        )


class ReportPayload(BaseModel):
    run_metadata: RunMetadata
    findings: list[Finding]
    stats: dict[str, Any]


class GroundTruthLabel(BaseModel):
    id: str
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    owasp_category: str
    notes: str = ""


class GroundTruthPayload(BaseModel):
    scope_name: str
    notes: str = ""
    labels: list[GroundTruthLabel]

