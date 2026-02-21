from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import streamlit as st

from secure_inspector.services import (
    repo_root,
    run_ai_pipeline,
    run_baseline_pipeline,
    run_compare_pipeline,
)
from secure_inspector.web_utils import (
    DEFAULT_MAX_ZIP_BYTES,
    create_session_workspace,
    safe_extract_zip,
    save_zip_bytes,
    validate_zip_size,
)


def _ensure_workspace() -> None:
    if "workspace_root" not in st.session_state or not st.session_state.get("workspace_root"):
        workspace = create_session_workspace(prefix="secure_inspector_ui_")
        st.session_state.workspace_root = str(workspace)
    else:
        workspace = Path(st.session_state.workspace_root)

    st.session_state.setdefault("target_repo_path", "")
    st.session_state.setdefault("session_api_key", "")
    if "output_dir" not in st.session_state or not st.session_state.get("output_dir"):
        st.session_state.output_dir = str(workspace / "outputs")
    Path(st.session_state.output_dir).mkdir(parents=True, exist_ok=True)

    st.session_state.setdefault("ai_result", None)
    st.session_state.setdefault("baseline_result", None)
    st.session_state.setdefault("compare_result", None)


def _config_options(root: Path) -> dict[str, list[str]]:
    configs_dir = root / "configs"
    options = sorted(str(p.relative_to(root)) for p in configs_dir.glob("*.yaml"))
    return {
        "scope": [x for x in options if "scope" in x] or options,
        "profile": [x for x in options if "profile" in x] or options,
        "pipeline": [x for x in options if "pipeline" in x] or options,
    }


def _default_option(options: list[str], preferred: str) -> str:
    if preferred in options:
        return preferred
    return options[0]


def _download_artifact(label: str, path: Path, mime: str) -> None:
    if not path.exists():
        st.info(f"{label}: not generated yet")
        return
    st.download_button(
        label=label,
        data=path.read_bytes(),
        file_name=path.name,
        mime=mime,
    )


def _run_with_progress(
    task_label: str,
    task: Callable[[Callable[[int, str], None]], dict[str, object]],
) -> dict[str, object]:
    progress_bar = st.progress(0, text=f"{task_label}: starting")

    def on_progress(percent: int, message: str) -> None:
        bounded = max(0, min(100, int(percent)))
        label = message.strip() if message.strip() else "in progress"
        progress_bar.progress(bounded, text=f"{task_label}: {label} ({bounded}%)")

    try:
        result = task(on_progress)
        on_progress(100, "Completed")
        return result
    finally:
        progress_bar.empty()


def _run_ai_tab(root: Path, options: dict[str, list[str]]) -> None:
    st.subheader("Run AI")
    st.caption("Upload a ZIP of the target repository or fixed-scope files, then run the AI pipeline.")

    api_key = st.text_input(
        "OpenAI API key (session only)",
        type="password",
        key="session_api_key",
        help="Used only in memory for this session and not written to disk.",
    )
    uploaded_zip = st.file_uploader("Repository ZIP", type=["zip"], key="repo_zip")

    max_zip_mb = DEFAULT_MAX_ZIP_BYTES // (1024 * 1024)
    scope_cfg = _default_option(options["scope"], "configs/scope.juiceshop.yaml")
    profile_cfg = _default_option(options["profile"], "configs/profile.yaml")
    pipeline_cfg = _default_option(options["pipeline"], "configs/pipeline.yaml")

    if uploaded_zip is None and not st.session_state.get("target_repo_path", ""):
        st.info("Start here: upload a ZIP file, then click `Prepare ZIP`.")

    if st.button(
        "Prepare ZIP",
        type="secondary",
        disabled=uploaded_zip is None,
        help="Upload a ZIP file to enable this action.",
    ):
        try:
            validate_zip_size(uploaded_zip.size or 0, int(max_zip_mb) * 1024 * 1024)
            workspace = Path(st.session_state.workspace_root)
            upload_path = save_zip_bytes(uploaded_zip.getvalue(), workspace / "upload.zip")
            extract_dir = workspace / "repo"
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)
            extracted = safe_extract_zip(upload_path, extract_dir)
            st.session_state.target_repo_path = str(extract_dir)
            st.success(f"ZIP prepared successfully. Extracted {len(extracted)} files.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Failed to prepare ZIP: {exc}")

    target_repo_path = st.session_state.get("target_repo_path", "")
    if target_repo_path:
        st.success("Repository ZIP is prepared and ready.")
    else:
        st.caption("`Run AI Pipeline` will be enabled after ZIP preparation.")

    if target_repo_path and not api_key:
        st.info("Enter your OpenAI API key to enable AI analysis.")

    run_ai_disabled = (not target_repo_path) or (not api_key)
    run_ai_help = (
        "Prepare ZIP and enter OpenAI API key to enable this action."
        if run_ai_disabled
        else "Run the AI analysis pipeline."
    )
    if st.button(
        "Run AI Pipeline",
        type="primary",
        disabled=run_ai_disabled,
        help=run_ai_help,
    ):

        try:
            result = _run_with_progress(
                "Running AI pipeline",
                lambda on_progress: run_ai_pipeline(
                    target_path=target_repo_path,
                    scope_config=root / scope_cfg,
                    profile_config=root / profile_cfg,
                    pipeline_config=root / pipeline_cfg,
                    out_dir=st.session_state.output_dir,
                    api_key_override=api_key,
                    project_root=root,
                    progress_callback=on_progress,
                ),
            )
            st.session_state.ai_result = result
            st.success(f"AI pipeline completed with {result['findings_count']} verified findings.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"AI pipeline failed: {exc}")

    result = st.session_state.get("ai_result")
    if result:
        st.metric("Verified findings", result["findings_count"])
        findings = result.get("findings", [])
        if findings:
            st.dataframe(findings, use_container_width=True)


def _run_baseline_tab(root: Path, options: dict[str, list[str]]) -> None:
    st.subheader("Run Baseline")
    st.caption("Runs Semgrep baseline on the same prepared repository ZIP.")

    target_repo_path = st.session_state.get("target_repo_path", "")

    scope_cfg = _default_option(options["scope"], "configs/scope.juiceshop.yaml")
    st.caption(f"Using default baseline scope: `{scope_cfg}`")
    if not target_repo_path:
        st.info("Prepare a ZIP in `Run AI` first to enable baseline scanning.")

    if st.button(
        "Run Semgrep Baseline",
        type="primary",
        disabled=not target_repo_path,
        help="Prepare ZIP in Run AI tab to enable this action.",
    ):
        try:
            result = _run_with_progress(
                "Running Semgrep baseline",
                lambda on_progress: run_baseline_pipeline(
                    target_path=target_repo_path,
                    scope_config=root / scope_cfg,
                    out_dir=st.session_state.output_dir,
                    progress_callback=on_progress,
                ),
            )
            st.session_state.baseline_result = result
            st.success(f"Baseline completed with {result['findings_count']} findings.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Baseline failed: {exc}")

    result = st.session_state.get("baseline_result")
    if result:
        st.metric("Baseline findings", result["findings_count"])
        findings = result.get("findings", [])
        if findings:
            st.dataframe(findings, use_container_width=True)


def _run_compare_tab(root: Path) -> None:
    st.subheader("Compare")
    st.caption("Compute AI precision/recall using Semgrep as the reference baseline.")
    st.caption("Evaluation method: AI-assisted semantic matching.")

    out_dir = Path(st.session_state.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ai_report = out_dir / "report.json"
    baseline_report = out_dir / "baseline.semgrep.json"
    api_key = str(st.session_state.get("session_api_key", ""))
    st.caption("Reference source: `baseline.semgrep.json`")
    if not api_key:
        st.info("Enter your OpenAI API key in the `Run AI` tab to enable comparison.")

    run_compare_disabled = not api_key
    if st.button(
        "Run Comparison",
        type="primary",
        disabled=run_compare_disabled,
        help="Enter API key in Run AI tab to enable this action." if run_compare_disabled else "",
    ):
        if not ai_report.exists():
            st.error("Missing AI report. Run AI pipeline first.")
            return
        if not baseline_report.exists():
            st.error("Missing baseline report. Run baseline first.")
            return
        try:
            result = _run_with_progress(
                "Running comparison",
                lambda on_progress: run_compare_pipeline(
                    ai_report=ai_report,
                    baseline_report=baseline_report,
                    out_path=Path(st.session_state.output_dir) / "comparison.md",
                    pipeline_config=root / "configs/pipeline.yaml",
                    api_key_override=api_key,
                    project_root=root,
                    progress_callback=on_progress,
                ),
            )
            st.session_state.compare_result = result
            st.success("Comparison generated successfully.")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Comparison failed: {exc}")

    result = st.session_state.get("compare_result")
    if result:
        st.markdown("### Metrics")
        summary = result.get("summary", {})
        ai_duplicates_removed = int(summary.get("ai_duplicates_removed", 0))
        baseline_duplicates_removed = int(summary.get("baseline_duplicates_removed", 0))
        table = [
            {
                "reference": "Semgrep",
                "ai_verified": summary.get("ai_total", 0),
                "semgrep_verified": summary.get("baseline_total", 0),
                "matched": summary.get("matched", 0),
                "ai_only": result["ai"]["fp"],
                "semgrep_only": result["ai"]["fn"],
                "precision": result["ai"]["precision"],
                "recall": result["ai"]["recall"],
            },
        ]
        st.table(table)
        if ai_duplicates_removed > 0:
            st.caption(
                f"AI normalization removed {ai_duplicates_removed} equivalent AI duplicate(s) before scoring."
            )
        if baseline_duplicates_removed > 0:
            st.caption(
                f"Baseline normalization removed {baseline_duplicates_removed} equivalent Semgrep duplicate(s) before scoring."
            )


def _artifacts_tab() -> None:
    st.subheader("Artifacts")
    st.caption(
        "Downloaded files are saved by your browser to its default download location "
        "(usually your Downloads folder)."
    )
    st.caption("After download, move them to your project `outputs/` folder if needed.")
    st.table(
        [
            {"artifact": "report.json", "recommended_destination": "outputs/report.json"},
            {"artifact": "report.md", "recommended_destination": "outputs/report.md"},
            {
                "artifact": "baseline.semgrep.json",
                "recommended_destination": "outputs/baseline.semgrep.json",
            },
            {"artifact": "comparison.md", "recommended_destination": "outputs/comparison.md"},
        ]
    )
    out_dir = Path(st.session_state.output_dir)
    _download_artifact("Download report.json", out_dir / "report.json", "application/json")
    _download_artifact("Download report.md", out_dir / "report.md", "text/markdown")
    _download_artifact(
        "Download baseline.semgrep.json",
        out_dir / "baseline.semgrep.json",
        "application/json",
    )
    _download_artifact("Download comparison.md", out_dir / "comparison.md", "text/markdown")


def _help_tab() -> None:
    st.subheader("Settings / Help")
    st.markdown("### Juice Shop Preset")
    st.markdown(
        "- Official repo: https://github.com/juice-shop/juice-shop\n"
        "- Recommended: upload a ZIP of a fixed scope for reproducible evaluation."
    )
    st.markdown("- Fixed scope preset file: `configs/scope.juiceshop.yaml`.")
    st.markdown("### Privacy and Security")
    st.markdown(
        "- Your API key is used only in this session and is not stored on disk.\n"
        "- Uploaded ZIPs are extracted with path traversal protection.\n"
        "- If your code contains secrets, remove or mask them before upload."
    )


def main() -> None:
    st.set_page_config(
        page_title="Secure Code Inspector",
        layout="wide",
    )
    _ensure_workspace()
    root = repo_root()
    options = _config_options(root)

    st.title("Secure Code Inspector")
    st.caption(
        "AI Workflow: Secure Code Analysis, Semgrep Baseline, and OWASP Comparison."
    )

    tab_run_ai, tab_baseline, tab_compare, tab_artifacts, tab_help = st.tabs(
        ["Run AI", "Run Baseline", "Compare", "Artifacts", "Settings / Help"]
    )
    with tab_run_ai:
        _run_ai_tab(root, options)
    with tab_baseline:
        _run_baseline_tab(root, options)
    with tab_compare:
        _run_compare_tab(root)
    with tab_artifacts:
        _artifacts_tab()
    with tab_help:
        _help_tab()


if __name__ == "__main__":
    main()

