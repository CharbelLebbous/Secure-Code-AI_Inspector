from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from secure_inspector.agents.access_control_specialist import AccessControlSpecialistAgent
from secure_inspector.agents.aggregator import AggregatorAgent
from secure_inspector.agents.extra_category_specialist import ExtraCategorySpecialistAgent
from secure_inspector.agents.injection_specialist import InjectionSpecialistAgent
from secure_inspector.agents.verifier import VerifierAgent
from secure_inspector.baseline.semgrep_runner import run_semgrep_baseline
from secure_inspector.chunker import build_chunks
from secure_inspector.config import (
    CORE_AGENT_ACCESS_CONTROL,
    CORE_AGENT_INJECTION,
    EXTRA_AGENT,
    enabled_agents,
    enabled_categories,
    load_pipeline_config,
    load_profile_config,
    load_scope_config,
    should_enable_extra_agent,
    specialist_category_map,
)
from secure_inspector.eval.metrics import JSONAsker, MatchResult, compare_reports, write_comparison_markdown
from secure_inspector.llm_client import LLMClient
from secure_inspector.models import Finding, RunMetadata
from secure_inspector.prompts import load_few_shot_examples, load_owasp_reference, read_text_file
from secure_inspector.reporting import write_json_report, write_markdown_report
from secure_inspector.scanner import load_scoped_files


ProgressCallback = Callable[[int, str], None]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _emit_progress(
    progress_callback: ProgressCallback | None,
    percent: int,
    message: str,
) -> None:
    if progress_callback is None:
        return
    bounded = max(0, min(100, int(percent)))
    progress_callback(bounded, message)


def _load_prompt_bundle(root: Path) -> dict[str, str]:
    return {
        CORE_AGENT_INJECTION: read_text_file(root / "prompts/agents/injection_specialist.md"),
        CORE_AGENT_ACCESS_CONTROL: read_text_file(
            root / "prompts/agents/access_control_specialist.md"
        ),
        EXTRA_AGENT: read_text_file(root / "prompts/agents/extra_category_specialist.md"),
        "VerifierAgent": read_text_file(root / "prompts/agents/verifier.md"),
        "AggregatorAgent": read_text_file(root / "prompts/agents/aggregator.md"),
    }


def _run_specialists(
    *,
    chunks,
    categories_map: dict[str, list[str]],
    pipeline_parallel: bool,
    llm_client: LLMClient,
    templates: dict[str, str],
    owasp_reference: str,
    secure_rules: str,
    few_shot_examples: list[dict],
    candidate_min: float,
    enable_extra: bool,
    progress_callback: ProgressCallback | None = None,
    progress_start: int = 40,
    progress_end: int = 68,
) -> list[Finding]:
    tasks: list[tuple[str, Callable[[Callable[[int, int], None] | None], list[Finding]]]] = []

    injection = InjectionSpecialistAgent(template_text=templates[CORE_AGENT_INJECTION])
    access = AccessControlSpecialistAgent(template_text=templates[CORE_AGENT_ACCESS_CONTROL])

    tasks.append(
        (
            CORE_AGENT_INJECTION,
            lambda chunk_progress: injection.run(
                categories=categories_map[CORE_AGENT_INJECTION],
                chunks=chunks,
                llm_client=llm_client,
                owasp_reference=owasp_reference,
                secure_rules=secure_rules,
                few_shot_examples=few_shot_examples,
                candidate_min_confidence=candidate_min,
                progress_callback=chunk_progress,
            ),
        )
    )
    tasks.append(
        (
            CORE_AGENT_ACCESS_CONTROL,
            lambda chunk_progress: access.run(
                categories=categories_map[CORE_AGENT_ACCESS_CONTROL],
                chunks=chunks,
                llm_client=llm_client,
                owasp_reference=owasp_reference,
                secure_rules=secure_rules,
                few_shot_examples=few_shot_examples,
                candidate_min_confidence=candidate_min,
                progress_callback=chunk_progress,
            ),
        )
    )

    if enable_extra:
        extra = ExtraCategorySpecialistAgent(template_text=templates[EXTRA_AGENT])
        tasks.append(
            (
                EXTRA_AGENT,
                lambda chunk_progress: extra.run(
                    categories=categories_map[EXTRA_AGENT],
                    chunks=chunks,
                    llm_client=llm_client,
                    owasp_reference=owasp_reference,
                    secure_rules=secure_rules,
                    few_shot_examples=few_shot_examples,
                    candidate_min_confidence=candidate_min,
                    progress_callback=chunk_progress,
                ),
            )
        )

    collected: list[Finding] = []
    total = len(tasks)
    if total == 0:
        return collected

    # If a UI callback is active, keep specialist execution sequential so progress updates
    # stay in the main thread and can reflect chunk-by-chunk advancement safely.
    run_parallel = pipeline_parallel and len(tasks) > 1 and progress_callback is None
    completed = 0
    if run_parallel:
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            future_map = {executor.submit(func, None): name for name, func in tasks}
            for future in as_completed(future_map):
                completed += 1
                name = future_map[future]
                try:
                    collected.extend(future.result())
                except Exception:  # noqa: BLE001
                    continue
                step = (progress_end - progress_start) * (completed / total)
                _emit_progress(
                    progress_callback,
                    progress_start + int(step),
                    f"Specialist completed: {name}",
                )
    else:
        span = max(1, progress_end - progress_start)
        for agent_index, (name, func) in enumerate(tasks):
            agent_start = progress_start + int(span * (agent_index / total))
            agent_end = progress_start + int(span * ((agent_index + 1) / total))

            def _chunk_progress(
                processed: int,
                total_chunks: int,
                _name: str = name,
                _start: int = agent_start,
                _end: int = agent_end,
            ) -> None:
                if total_chunks <= 0:
                    _emit_progress(progress_callback, _end, f"{_name} completed")
                    return
                ratio = max(0.0, min(1.0, processed / total_chunks))
                pct = _start + int((_end - _start) * ratio)
                _emit_progress(progress_callback, pct, f"{_name}: chunk {processed}/{total_chunks}")

            try:
                collected.extend(func(_chunk_progress))
            except Exception:  # noqa: BLE001
                _emit_progress(progress_callback, agent_end, f"{name} completed with warnings")
                continue
            _emit_progress(
                progress_callback,
                agent_end,
                f"Specialist completed: {name}",
            )
    return collected


def run_ai_pipeline(
    *,
    target_path: str | Path,
    scope_config: str | Path,
    profile_config: str | Path,
    pipeline_config: str | Path,
    out_dir: str | Path,
    api_key_override: str | None = None,
    project_root: str | Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    _emit_progress(progress_callback, 5, "Loading configuration")
    root = Path(project_root).resolve() if project_root else repo_root()
    scope = load_scope_config(scope_config)
    profile = load_profile_config(profile_config)
    pipeline = load_pipeline_config(pipeline_config)

    _emit_progress(progress_callback, 12, "Collecting scoped files")
    scoped_files = load_scoped_files(target_path, scope)
    if not scoped_files:
        raise RuntimeError("Scope is empty; adjust scope config or target path.")

    _emit_progress(progress_callback, 20, "Chunking source files")
    chunks = build_chunks(scoped_files, max_chunk_lines=scope.max_chunk_lines)
    _emit_progress(progress_callback, 28, "Initializing model client")
    llm_client = LLMClient(
        model=pipeline.model,
        temperature=pipeline.temperature,
        max_tokens=pipeline.max_tokens,
        max_retries=pipeline.max_retries,
        strict_json=pipeline.strict_json,
        api_key=api_key_override,
    )

    _emit_progress(progress_callback, 34, "Loading prompts and references")
    templates = _load_prompt_bundle(root)
    few_shot = load_few_shot_examples(root / "prompts/few_shot_examples.json")
    owasp_reference = load_owasp_reference(root / "data/owasp_top10.yaml")
    secure_rules = read_text_file(root / "data/secure_coding_rules.md")
    categories_map = specialist_category_map(profile)
    enable_extra = should_enable_extra_agent(profile, pipeline)

    _emit_progress(progress_callback, 40, "Running specialist agents")
    candidates = _run_specialists(
        chunks=chunks,
        categories_map=categories_map,
        pipeline_parallel=pipeline.parallel_specialists,
        llm_client=llm_client,
        templates=templates,
        owasp_reference=owasp_reference,
        secure_rules=secure_rules,
        few_shot_examples=few_shot,
        candidate_min=profile.confidence_thresholds.candidate_min,
        enable_extra=enable_extra,
        progress_callback=progress_callback,
        progress_start=40,
        progress_end=68,
    )

    _emit_progress(progress_callback, 72, "Running verifier")
    scope_index = {sf.relative_path: sf.line_count for sf in scoped_files}
    verifier = VerifierAgent(template_text=templates["VerifierAgent"])
    verified_or_rejected = verifier.run(
        findings=candidates,
        scope_index=scope_index,
        llm_client=llm_client,
        owasp_reference=owasp_reference,
        secure_rules=secure_rules,
        verified_min_confidence=profile.confidence_thresholds.verified_min,
    )

    _emit_progress(progress_callback, 84, "Running aggregator")
    aggregator = AggregatorAgent(template_text=templates["AggregatorAgent"])
    final_findings = aggregator.run(findings=verified_or_rejected, llm_client=llm_client)

    _emit_progress(progress_callback, 92, "Writing reports")
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = output_dir / "report.json"
    report_md_path = output_dir / "report.md"

    metadata = RunMetadata.new(
        target_path=str(Path(target_path).resolve()),
        scope_files=[sf.relative_path for sf in scoped_files],
        enabled_categories=enabled_categories(profile),
        enabled_agents=enabled_agents(profile, pipeline),
        model=pipeline.model,
        prompt_versions={
            CORE_AGENT_INJECTION: "v1",
            CORE_AGENT_ACCESS_CONTROL: "v1",
            EXTRA_AGENT: "v1",
            "VerifierAgent": "v1",
            "AggregatorAgent": "v1",
        },
    )

    write_json_report(out_path=report_json_path, metadata=metadata, findings=final_findings)
    write_markdown_report(out_path=report_md_path, metadata=metadata, findings=final_findings)
    _emit_progress(progress_callback, 100, "Completed")

    return {
        "report_json_path": str(report_json_path),
        "report_md_path": str(report_md_path),
        "findings_count": len(final_findings),
        "findings": [f.model_dump() for f in final_findings],
        "run_metadata": metadata.model_dump(),
    }


def run_baseline_pipeline(
    *,
    target_path: str | Path,
    scope_config: str | Path,
    out_dir: str | Path,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    _emit_progress(progress_callback, 10, "Loading scope configuration")
    scope = load_scope_config(scope_config)
    _emit_progress(progress_callback, 20, "Preparing output location")
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = output_dir / "baseline.semgrep.json"
    findings = run_semgrep_baseline(
        target_path=target_path,
        scope=scope,
        out_json_path=baseline_path,
        progress_callback=progress_callback,
    )
    _emit_progress(progress_callback, 100, "Completed")
    return {
        "baseline_json_path": str(baseline_path),
        "findings_count": len(findings),
        "findings": [f.model_dump() for f in findings],
    }


def _score_to_dict(score: MatchResult) -> dict[str, object]:
    return {
        "tp": score.tp,
        "fp": score.fp,
        "fn": score.fn,
        "precision": score.precision,
        "recall": score.recall,
        "false_positives": score.false_positives,
        "misses": score.misses,
    }


def run_compare_pipeline(
    *,
    ai_report: str | Path,
    baseline_report: str | Path,
    out_path: str | Path,
    pipeline_config: str | Path | None = None,
    api_key_override: str | None = None,
    project_root: str | Path | None = None,
    llm_client: JSONAsker | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, object]:
    _emit_progress(progress_callback, 5, "Preparing comparison")
    resolved_root = Path(project_root).resolve() if project_root else repo_root()

    if llm_client is None:
        if pipeline_config is None:
            pipeline_path = resolved_root / "configs/pipeline.yaml"
        else:
            candidate = Path(pipeline_config)
            pipeline_path = candidate if candidate.is_absolute() else resolved_root / candidate
        _emit_progress(progress_callback, 8, "Loading pipeline configuration")
        pipeline = load_pipeline_config(pipeline_path)
        _emit_progress(progress_callback, 12, "Initializing AI matcher")
        llm_client = LLMClient(
            model=pipeline.model,
            temperature=pipeline.temperature,
            max_tokens=pipeline.max_tokens,
            max_retries=pipeline.max_retries,
            strict_json=pipeline.strict_json,
            api_key=api_key_override,
        )
    else:
        _emit_progress(progress_callback, 12, "Using injected AI matcher")

    scores = compare_reports(
        ai_report_path=ai_report,
        baseline_report_path=baseline_report,
        llm_client=llm_client,
        progress_callback=progress_callback,
        progress_start=20,
        progress_end=92,
    )
    ai_score = scores["ai"]
    if not isinstance(ai_score, MatchResult):
        raise RuntimeError("Invalid comparison result for AI score.")

    ai_total = int(scores.get("ai_total", 0))
    ai_duplicates_removed = int(scores.get("ai_duplicates_removed", 0))
    baseline_total = int(scores.get("baseline_total", 0))
    baseline_duplicates_removed = int(scores.get("baseline_duplicates_removed", 0))

    _emit_progress(progress_callback, 96, "Writing comparison markdown")
    write_comparison_markdown(
        out_path=out_path,
        ai_score=ai_score,
        ai_total=ai_total,
        baseline_total=baseline_total,
        ai_duplicates_removed=ai_duplicates_removed,
        baseline_duplicates_removed=baseline_duplicates_removed,
    )
    _emit_progress(progress_callback, 100, "Completed")
    return {
        "comparison_path": str(Path(out_path)),
        "ai": _score_to_dict(ai_score),
        "summary": {
            "ai_total": ai_total,
            "ai_duplicates_removed": ai_duplicates_removed,
            "baseline_total": baseline_total,
            "baseline_duplicates_removed": baseline_duplicates_removed,
            "matched": int(scores.get("matched", ai_score.tp)),
        },
    }
