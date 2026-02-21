from __future__ import annotations

import argparse

from secure_inspector.services import (
    run_ai_pipeline,
    run_baseline_pipeline,
    run_compare_pipeline,
)


def cmd_run(args: argparse.Namespace) -> int:
    result = run_ai_pipeline(
        target_path=args.target_path,
        scope_config=args.scope_config,
        profile_config=args.profile_config,
        pipeline_config=args.pipeline_config,
        out_dir=args.out_dir,
    )

    print(f"Run completed: {result['findings_count']} verified findings")
    print(f"- JSON: {result['report_json_path']}")
    print(f"- Markdown: {result['report_md_path']}")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    result = run_baseline_pipeline(
        target_path=args.target_path,
        scope_config=args.scope_config,
        out_dir=args.out_dir,
    )
    print(f"Baseline completed: {result['findings_count']} findings")
    print(f"- JSON: {result['baseline_json_path']}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    result = run_compare_pipeline(
        ai_report=args.ai_report,
        baseline_report=args.baseline,
        out_path=args.out,
    )
    print(f"Comparison generated: {result['comparison_path']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure_inspector",
        description="Prompt-engineering secure code inspector with OWASP mapping",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Run AI inspector pipeline")
    run_parser.add_argument("--target-path", required=True)
    run_parser.add_argument("--scope-config", default="configs/scope.juiceshop.yaml")
    run_parser.add_argument("--profile-config", default="configs/profile.yaml")
    run_parser.add_argument("--pipeline-config", default="configs/pipeline.yaml")
    run_parser.add_argument("--out-dir", default="outputs")
    run_parser.set_defaults(func=cmd_run)

    baseline_parser = sub.add_parser("baseline", help="Run Semgrep baseline")
    baseline_parser.add_argument("--target-path", required=True)
    baseline_parser.add_argument("--scope-config", default="configs/scope.juiceshop.yaml")
    baseline_parser.add_argument("--out-dir", default="outputs")
    baseline_parser.set_defaults(func=cmd_baseline)

    compare_parser = sub.add_parser("compare", help="Compute comparison metrics")
    compare_parser.add_argument("--ai-report", default="outputs/report.json")
    compare_parser.add_argument("--baseline", default="outputs/baseline.semgrep.json")
    compare_parser.add_argument("--out", default="comparison.md")
    compare_parser.set_defaults(func=cmd_compare)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}")
        return 1
