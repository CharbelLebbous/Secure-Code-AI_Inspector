from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


CORE_AGENT_INJECTION = "InjectionSpecialistAgent"
CORE_AGENT_ACCESS_CONTROL = "AccessControlSpecialistAgent"
EXTRA_AGENT = "ExtraCategorySpecialistAgent"
VERIFIER_AGENT = "VerifierAgent"
AGGREGATOR_AGENT = "AggregatorAgent"


class ScopeConfig(BaseModel):
    include_globs: list[str]
    exclude_globs: list[str] = []
    max_files: int = Field(default=10, ge=1)
    max_chunk_lines: int = Field(default=120, ge=20)


class CategoryGroup(BaseModel):
    categories: list[str] = []


class ConfidenceThresholds(BaseModel):
    candidate_min: float = Field(default=0.25, ge=0.0, le=1.0)
    verified_min: float = Field(default=0.55, ge=0.0, le=1.0)


class ProfileConfig(BaseModel):
    core_categories: dict[str, CategoryGroup]
    extra_categories: list[str] = []
    confidence_thresholds: ConfidenceThresholds = ConfidenceThresholds()


class PipelineConfig(BaseModel):
    model: str = "gpt-4.1-mini"
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_retries: int = Field(default=2, ge=0, le=10)
    max_tokens: int = Field(default=1800, ge=256)
    parallel_specialists: bool = True
    allow_extra_agent: bool = True
    strict_json: bool = True


def _load_yaml_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML object in {p}")
    return data


def load_scope_config(path: str | Path) -> ScopeConfig:
    return ScopeConfig(**_load_yaml_file(path))


def load_profile_config(path: str | Path) -> ProfileConfig:
    return ProfileConfig(**_load_yaml_file(path))


def load_pipeline_config(path: str | Path) -> PipelineConfig:
    return PipelineConfig(**_load_yaml_file(path))


def specialist_category_map(profile: ProfileConfig) -> dict[str, list[str]]:
    injection = profile.core_categories.get("injection", CategoryGroup()).categories
    access_control = profile.core_categories.get(
        "access_control", CategoryGroup()
    ).categories
    return {
        CORE_AGENT_INJECTION: injection,
        CORE_AGENT_ACCESS_CONTROL: access_control,
        EXTRA_AGENT: profile.extra_categories,
    }


def enabled_categories(profile: ProfileConfig) -> list[str]:
    mapping = specialist_category_map(profile)
    ordered: list[str] = []
    for categories in mapping.values():
        for cat in categories:
            if cat not in ordered:
                ordered.append(cat)
    return ordered


def should_enable_extra_agent(profile: ProfileConfig, pipeline: PipelineConfig) -> bool:
    return pipeline.allow_extra_agent and len(profile.extra_categories) > 0


def enabled_agents(profile: ProfileConfig, pipeline: PipelineConfig) -> list[str]:
    agents = [CORE_AGENT_INJECTION, CORE_AGENT_ACCESS_CONTROL]
    if should_enable_extra_agent(profile, pipeline):
        agents.append(EXTRA_AGENT)
    agents.extend([VERIFIER_AGENT, AGGREGATOR_AGENT])
    return agents

