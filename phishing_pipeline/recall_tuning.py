from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError

from .shortlisting import normalize_url

logger = logging.getLogger(__name__)


DEFAULT_SHORTLISTING_DIR = Path("data") / "holdout_sets"
DEFAULT_WHITELIST = Path("data") / "whitelists" / "Stage_2_Legitimate_Domains_80.xlsx"
DEFAULT_GT_WORKBOOK = DEFAULT_SHORTLISTING_DIR / "AIGR-S66270_Ground_Truth.xlsx"
DEFAULT_CONTROLLER = Path("main_controller.py")
DEFAULT_TUNING_ROOT = Path("output") / "tuning_runs"

STAGE_FILES = {
    "stage1": ("stage1_lexical_debug.csv", "normalized_url"),
    "dns_audit": ("dns_gate_audit.csv", "target_url"),
    "holdout": ("holdout.csv", "Identified Phishing/Suspected Domain Name"),
    "stage3": ("stage3_classification_debug.csv", "url"),
    "output": ("output_file.csv", "Identified Phishing/Suspected Domain Name"),
    "filtered": ("output_file_filtered.csv", "Identified Phishing/Suspected Domain Name"),
    "review": ("hash_review_queue.csv", "Identified Phishing/Suspected Domain Name"),
}

GT_FLAG_COLUMNS = [
    "in_stage1",
    "in_dns_audit",
    "in_holdout",
    "in_stage3",
    "in_output",
    "in_filtered",
    "in_review",
]


def get_iteration_presets() -> list[dict]:
    return [
        {"name": "baseline", "args": {}},
        {
            "name": "stage1_relaxed",
            "args": {
                "stage1_escalate_total_threshold": 48,
                "stage1_brand_min": 12,
                "stage1_credential_min": 10,
                "stage1_low_band_min": 12,
                "stage1_hard_trigger_brand_min": 8,
                "keep_stage1_suspected": True,
            },
        },
        {
            "name": "shortlist_relaxed",
            "args": {
                "hashing_threshold": 54.0,
                "domain_sim_threshold": 0.72,
                "typo_min_score": 0.65,
                "lexical_pass_min_score": 0.80,
            },
        },
        {
            "name": "recall_mix",
            "args": {
                "hashing_threshold": 54.0,
                "domain_sim_threshold": 0.72,
                "typo_min_score": 0.65,
                "lexical_pass_min_score": 0.80,
                "stage1_escalate_total_threshold": 48,
                "stage1_brand_min": 12,
                "stage1_credential_min": 10,
                "stage1_low_band_min": 12,
                "stage1_hard_trigger_brand_min": 8,
                "keep_stage1_suspected": True,
            },
        },
        {
            "name": "dns_fetch_guarded",
            "args": {
                "hashing_threshold": 54.0,
                "domain_sim_threshold": 0.72,
                "typo_min_score": 0.65,
                "lexical_pass_min_score": 0.80,
                "stage1_escalate_total_threshold": 48,
                "stage1_brand_min": 12,
                "stage1_credential_min": 10,
                "stage1_low_band_min": 12,
                "stage1_hard_trigger_brand_min": 8,
                "keep_stage1_suspected": True,
                "keep_dns_rejected_strict_lexical": True,
                "keep_fetch_failed_strict_lexical": True,
                "failed_fetch_suspected_min": 0.90,
                "failed_fetch_review_min": 0.82,
            },
        },
        {
            "name": "dns_fetch_open",
            "args": {
                "hashing_threshold": 54.0,
                "domain_sim_threshold": 0.72,
                "typo_min_score": 0.65,
                "lexical_pass_min_score": 0.80,
                "stage1_escalate_total_threshold": 48,
                "stage1_brand_min": 12,
                "stage1_credential_min": 10,
                "stage1_low_band_min": 12,
                "stage1_hard_trigger_brand_min": 8,
                "keep_stage1_suspected": True,
                "keep_dns_rejected_strict_lexical": True,
                "keep_fetch_failed_strict_lexical": True,
                "failed_fetch_suspected_min": 0.85,
                "failed_fetch_review_min": 0.78,
            },
        },
        {
            "name": "combined_candidate",
            "args": {
                "hashing_threshold": 56.0,
                "domain_sim_threshold": 0.75,
                "typo_min_score": 0.65,
                "lexical_pass_min_score": 0.80,
                "stage1_escalate_total_threshold": 48,
                "stage1_brand_min": 12,
                "stage1_credential_min": 10,
                "stage1_low_band_min": 12,
                "stage1_hard_trigger_brand_min": 8,
                "keep_stage1_suspected": True,
                "keep_dns_rejected_strict_lexical": True,
                "keep_fetch_failed_strict_lexical": True,
                "failed_fetch_suspected_min": 0.85,
                "failed_fetch_review_min": 0.80,
            },
        },
    ]


def _discover_workbook_names(folder_path: Path) -> list[str]:
    files = sorted(folder_path.glob("*.xlsx")) + sorted(folder_path.glob("*.xls"))
    return [path.name for path in files if not path.name.startswith("~$")]


def _parse_source_workbooks(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = value
    else:
        items = str(value or "").split("|")
    ordered = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _merge_source_workbooks(*values) -> str:
    ordered = []
    seen = set()
    for value in values:
        for item in _parse_source_workbooks(value):
            if item in seen:
                continue
            seen.add(item)
            ordered.append(item)
    return "|".join(ordered)


def _normalize_stage_url(value) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return ""
    return normalize_url(text)


def _read_optional_csv(path: Path) -> pd.DataFrame:
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except EmptyDataError:
        return pd.DataFrame()


def _find_gt_column(columns: list[str]) -> str:
    preferred = [
        "Identified Domain Name",
        "Identified Phishing/Suspected Domain Name",
        "domain_name",
        "Domain",
        "URL",
        "url",
    ]
    for candidate in preferred:
        if candidate in columns:
            return candidate
    for column in columns:
        lowered = str(column).lower()
        if "domain" in lowered or "url" in lowered:
            return column
    raise ValueError("Could not find a GT domain column in the workbook")


def load_gt_targets(gt_workbook: Path) -> list[dict]:
    df = pd.read_excel(gt_workbook)
    column = _find_gt_column(list(df.columns))
    seen = set()
    targets = []
    for raw_value in df[column].dropna().tolist():
        raw_text = str(raw_value).strip()
        normalized = _normalize_stage_url(raw_text)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        targets.append(
            {
                "gt_domain": raw_text,
                "normalized_url": normalized,
            }
        )
    return targets


def _load_stage_frames(iteration_dir: Path) -> dict[str, pd.DataFrame]:
    frames = {}
    for stage_name, (filename, url_column) in STAGE_FILES.items():
        frame = _read_optional_csv(iteration_dir / filename)
        if frame.empty:
            frame = pd.DataFrame(columns=["normalized_url", "source_workbook"])
        else:
            if url_column not in frame.columns:
                frame["normalized_url"] = ""
            else:
                frame["normalized_url"] = frame[url_column].map(_normalize_stage_url)
            if "source_workbook" not in frame.columns:
                frame["source_workbook"] = ""
            else:
                frame["source_workbook"] = frame["source_workbook"].fillna("").astype(str)
        frames[stage_name] = frame
    return frames


def _build_url_source_map(frames: dict[str, pd.DataFrame]) -> dict[str, str]:
    url_source_map: dict[str, str] = {}
    for frame in frames.values():
        if frame.empty:
            continue
        for _, row in frame.iterrows():
            normalized_url = str(row.get("normalized_url", "") or "").strip()
            if not normalized_url:
                continue
            merged = _merge_source_workbooks(
                url_source_map.get(normalized_url, ""),
                row.get("source_workbook", ""),
            )
            if merged:
                url_source_map[normalized_url] = merged
    return url_source_map


def _enrich_frame_sources(frames: dict[str, pd.DataFrame], url_source_map: dict[str, str]) -> dict[str, pd.DataFrame]:
    enriched = {}
    for stage_name, frame in frames.items():
        current = frame.copy()
        if "source_workbook" not in current.columns:
            current["source_workbook"] = ""
        current["source_workbook"] = [
            _merge_source_workbooks(existing, url_source_map.get(normalized_url, ""))
            for existing, normalized_url in zip(
                current["source_workbook"].tolist(),
                current["normalized_url"].tolist(),
            )
        ]
        enriched[stage_name] = current
    return enriched


def _stage_sets(frames: dict[str, pd.DataFrame]) -> dict[str, set[str]]:
    return {
        stage_name: {
            str(value).strip()
            for value in frame.get("normalized_url", pd.Series(dtype=str)).tolist()
            if str(value or "").strip()
        }
        for stage_name, frame in frames.items()
    }


def _annotate_stage_frames(
    frames: dict[str, pd.DataFrame],
    stage_sets: dict[str, set[str]],
    gt_urls: set[str],
) -> dict[str, pd.DataFrame]:
    annotated = {}
    for stage_name, frame in frames.items():
        current = frame.copy()
        normalized_values = current.get("normalized_url", pd.Series(dtype=str)).fillna("").astype(str)
        current["is_gt_domain"] = normalized_values.isin(gt_urls)
        current["in_stage1"] = normalized_values.isin(stage_sets["stage1"])
        current["in_dns_audit"] = normalized_values.isin(stage_sets["dns_audit"])
        current["in_holdout"] = normalized_values.isin(stage_sets["holdout"])
        current["in_stage3"] = normalized_values.isin(stage_sets["stage3"])
        current["in_output"] = normalized_values.isin(stage_sets["output"])
        current["in_filtered"] = normalized_values.isin(stage_sets["filtered"])
        current["in_review"] = normalized_values.isin(stage_sets["review"])
        annotated[stage_name] = current
    return annotated


def _write_annotated_stage_files(iteration_dir: Path, frames: dict[str, pd.DataFrame]) -> None:
    for stage_name, (filename, _url_column) in STAGE_FILES.items():
        annotated_name = f"{Path(filename).stem}_annotated.csv"
        frames[stage_name].to_csv(iteration_dir / annotated_name, index=False, encoding="utf-8")


def _matching_row(frame: pd.DataFrame, normalized_url: str) -> dict:
    if frame.empty:
        return {}
    matches = frame.loc[frame["normalized_url"] == normalized_url]
    if matches.empty:
        return {}
    return matches.iloc[0].to_dict()


def _unique_url_count(frame: pd.DataFrame) -> int:
    if frame.empty or "normalized_url" not in frame.columns:
        return 0
    return int(frame["normalized_url"].replace("", pd.NA).dropna().nunique())


def _count_urls_for_workbook(frame: pd.DataFrame, workbook_name: str) -> int:
    if frame.empty:
        return 0
    urls = set()
    for _, row in frame.iterrows():
        normalized_url = str(row.get("normalized_url", "") or "").strip()
        if not normalized_url:
            continue
        workbooks = _parse_source_workbooks(row.get("source_workbook", ""))
        if workbook_name in workbooks:
            urls.add(normalized_url)
    return len(urls)


def _write_workbook_funnel_counts(
    iteration_dir: Path,
    workbook_names: list[str],
    frames: dict[str, pd.DataFrame],
) -> list[dict]:
    rows = []
    for workbook_name in workbook_names:
        row = {"source_workbook": workbook_name}
        for stage_name in STAGE_FILES:
            row[f"{stage_name}_count"] = _count_urls_for_workbook(frames[stage_name], workbook_name)
        rows.append(row)
    pd.DataFrame(rows).to_csv(iteration_dir / "source_workbook_funnel_counts.csv", index=False, encoding="utf-8")
    return rows


def _write_gt_trace(
    iteration_dir: Path,
    gt_targets: list[dict],
    frames: dict[str, pd.DataFrame],
    stage_sets: dict[str, set[str]],
    url_source_map: dict[str, str],
) -> list[dict]:
    trace_rows = []
    for target in gt_targets:
        normalized_url = target["normalized_url"]
        stage1_row = _matching_row(frames["stage1"], normalized_url)
        stage3_row = _matching_row(frames["stage3"], normalized_url)
        review_row = _matching_row(frames["review"], normalized_url)
        holdout_row = _matching_row(frames["holdout"], normalized_url)
        output_row = _matching_row(frames["output"], normalized_url)
        filtered_row = _matching_row(frames["filtered"], normalized_url)
        dns_row = _matching_row(frames["dns_audit"], normalized_url)
        trace_rows.append(
            {
                "gt_domain": target["gt_domain"],
                "normalized_url": normalized_url,
                "source_workbook": _merge_source_workbooks(
                    url_source_map.get(normalized_url, ""),
                    stage1_row.get("source_workbook", ""),
                    stage3_row.get("source_workbook", ""),
                    holdout_row.get("source_workbook", ""),
                    review_row.get("source_workbook", ""),
                ),
                "in_stage1": normalized_url in stage_sets["stage1"],
                "in_dns_audit": normalized_url in stage_sets["dns_audit"],
                "in_holdout": normalized_url in stage_sets["holdout"],
                "in_stage3": normalized_url in stage_sets["stage3"],
                "in_output": normalized_url in stage_sets["output"],
                "in_filtered": normalized_url in stage_sets["filtered"],
                "in_review": normalized_url in stage_sets["review"],
                "dns_status": dns_row.get("dns_status", ""),
                "dns_decision": dns_row.get("decision", ""),
                "stage1_reason": stage1_row.get("reason", ""),
                "stage1_survival_path": stage1_row.get("survival_path", ""),
                "stage1_drop_path": stage1_row.get("drop_path", ""),
                "holdout_fetch_status": holdout_row.get("fetch_status", ""),
                "holdout_admission_path": holdout_row.get("admission_path", ""),
                "stage3_classification": stage3_row.get("classification", output_row.get("Phishing/Suspected Domains (i.e. Class Label)", "")),
                "stage3_gate_reason": stage3_row.get("classification_gate_reason", ""),
                "stage3_review_only_reason": stage3_row.get("review_only_reason", review_row.get("review_reason", "")),
                "stage3_survival_path": stage3_row.get("survival_path", ""),
                "stage3_drop_path": stage3_row.get("drop_path", ""),
            }
        )
    pd.DataFrame(trace_rows).to_csv(iteration_dir / "gt_domain_trace.csv", index=False, encoding="utf-8")
    return trace_rows


def summarize_iteration_artifacts(
    iteration_dir: Path,
    gt_targets: list[dict],
    workbook_names: list[str],
) -> dict:
    frames = _load_stage_frames(iteration_dir)
    url_source_map = _build_url_source_map(frames)
    frames = _enrich_frame_sources(frames, url_source_map)
    url_source_map = _build_url_source_map(frames)
    stage_sets = _stage_sets(frames)
    gt_urls = {target["normalized_url"] for target in gt_targets}
    annotated_frames = _annotate_stage_frames(frames, stage_sets, gt_urls)
    _write_annotated_stage_files(iteration_dir, annotated_frames)
    workbook_rows = _write_workbook_funnel_counts(iteration_dir, workbook_names, annotated_frames)
    gt_trace = _write_gt_trace(iteration_dir, gt_targets, annotated_frames, stage_sets, url_source_map)

    summary = {
        "gt_final_output_count": sum(1 for row in gt_trace if row["in_output"]),
        "gt_stage3_count": sum(1 for row in gt_trace if row["in_stage3"]),
        "gt_review_count": sum(1 for row in gt_trace if row["in_review"]),
        "gt_holdout_count": sum(1 for row in gt_trace if row["in_holdout"]),
        "flagged_output_count": _unique_url_count(annotated_frames["filtered"]),
        "total_output_count": _unique_url_count(annotated_frames["output"]),
        "stage1_count": _unique_url_count(annotated_frames["stage1"]),
        "dns_audit_count": _unique_url_count(annotated_frames["dns_audit"]),
        "holdout_count": _unique_url_count(annotated_frames["holdout"]),
        "stage3_count": _unique_url_count(annotated_frames["stage3"]),
        "review_count": _unique_url_count(annotated_frames["review"]),
        "missing_gt_domains": [row["gt_domain"] for row in gt_trace if not row["in_output"] and not row["in_review"]],
        "workbook_funnel_counts": workbook_rows,
    }
    (iteration_dir / "iteration_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    return summary


def rank_iteration_summaries(summaries: list[dict]) -> list[dict]:
    ranked = sorted(
        summaries,
        key=lambda row: (
            -int(row.get("gt_final_output_count", 0)),
            -int(row.get("gt_stage3_count", 0)),
            -int(row.get("gt_review_count", 0)),
            -int(row.get("gt_holdout_count", 0)),
            int(row.get("flagged_output_count", 0)),
            int(row.get("total_output_count", 0)),
            int(row.get("iteration_index", 0)),
        ),
    )
    for index, row in enumerate(ranked, start=1):
        row["rank"] = index
    return ranked


def _copy_tree_contents(source_dir: Path, destination_dir: Path) -> None:
    destination_dir.mkdir(parents=True, exist_ok=True)
    for child in source_dir.iterdir():
        if child.name == "tuning_runs":
            continue
        destination = destination_dir / child.name
        if child.is_dir():
            shutil.copytree(child, destination, dirs_exist_ok=True)
        else:
            shutil.copy2(child, destination)


def _stream_process_output(command: list[str], cwd: Path, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            log_handle.write(line)
        return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, command)


def _flag_to_cli_args(flag_name: str, value) -> list[str]:
    cli_flag = "--" + flag_name.replace("_", "-")
    if isinstance(value, bool):
        return [cli_flag] if value else []
    if value is None:
        return []
    return [cli_flag, str(value)]


def build_controller_command(
    python_executable: str,
    controller_path: Path,
    shortlisting: Path,
    whitelist: Path,
    pipeline_mode: str,
    limit: int | None,
    target_limit: int | None,
    preset_args: dict,
) -> list[str]:
    command = [
        python_executable,
        str(controller_path),
        "--shortlisting",
        str(shortlisting),
        "--whitelist",
        str(whitelist),
        "--pipeline-mode",
        pipeline_mode,
    ]
    if limit is not None:
        command.extend(["--limit", str(limit)])
    if target_limit is not None:
        command.extend(["--target-limit", str(target_limit)])
    for key, value in preset_args.items():
        command.extend(_flag_to_cli_args(key, value))
    return command


def run_tuning_iterations(
    repo_root: Path,
    controller_path: Path,
    shortlisting: Path,
    whitelist: Path,
    gt_workbook: Path,
    tuning_root: Path,
    python_executable: str = sys.executable,
    pipeline_mode: str = "hash_only",
    limit: int | None = None,
    target_limit: int | None = None,
    continue_on_error: bool = False,
    skip_existing: bool = False,
) -> list[dict]:
    gt_targets = load_gt_targets(gt_workbook)
    workbook_names = _discover_workbook_names(shortlisting)
    output_dir = repo_root / "output"
    tuning_root.mkdir(parents=True, exist_ok=True)
    summaries = []
    presets = get_iteration_presets()

    for iteration_index, preset in enumerate(presets, start=1):
        iteration_name = f"iter_{iteration_index:02d}_{preset['name']}"
        iteration_dir = tuning_root / iteration_name
        if iteration_dir.exists() and not skip_existing:
            shutil.rmtree(iteration_dir)
        iteration_dir.mkdir(parents=True, exist_ok=True)

        summary_payload = {
            "iteration_index": iteration_index,
            "preset_name": preset["name"],
            "preset_args": dict(preset["args"]),
            "iteration_dir": str(iteration_dir),
            "status": "pending",
        }
        command = build_controller_command(
            python_executable=python_executable,
            controller_path=controller_path,
            shortlisting=shortlisting,
            whitelist=whitelist,
            pipeline_mode=pipeline_mode,
            limit=limit,
            target_limit=target_limit,
            preset_args=preset["args"],
        )
        summary_payload["command"] = command

        if skip_existing and any((iteration_dir / filename).exists() for filename, _ in STAGE_FILES.values()):
            logger.info("Skipping existing iteration snapshot: %s", iteration_name)
            summary_payload["status"] = "reused"
            summary_payload["duration_seconds"] = 0.0
        else:
            logger.info("Starting tuning iteration %d/%d: %s", iteration_index, len(presets), preset["name"])
            started_at = time.time()
            try:
                _stream_process_output(
                    command=command,
                    cwd=repo_root,
                    log_path=iteration_dir / "controller_run.log",
                )
                _copy_tree_contents(output_dir, iteration_dir)
                summary_payload["status"] = "completed"
            except Exception as exc:
                summary_payload["status"] = "failed"
                summary_payload["error"] = str(exc)
                if not any((iteration_dir / filename).exists() for filename, _ in STAGE_FILES.values()) and output_dir.exists():
                    _copy_tree_contents(output_dir, iteration_dir)
                if not continue_on_error:
                    summary_payload["duration_seconds"] = round(time.time() - started_at, 2)
                    summaries.append(summary_payload)
                    raise
            finally:
                summary_payload["duration_seconds"] = round(time.time() - started_at, 2)

        summary_payload.update(
            summarize_iteration_artifacts(
                iteration_dir=iteration_dir,
                gt_targets=gt_targets,
                workbook_names=workbook_names,
            )
        )
        summaries.append(summary_payload)

    ranked = rank_iteration_summaries(summaries)
    summary_csv = tuning_root / "summary.csv"
    summary_json = tuning_root / "summary.json"
    pd.DataFrame(ranked).to_csv(summary_csv, index=False, encoding="utf-8")
    summary_json.write_text(
        json.dumps(
            {
                "generated_at_epoch": int(time.time()),
                "shortlisting": str(shortlisting),
                "gt_workbook": str(gt_workbook),
                "best_iteration": ranked[0] if ranked else None,
                "iterations": ranked,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return ranked


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Recall-first 7-iteration tuning runner")
    parser.add_argument("--controller", type=Path, default=DEFAULT_CONTROLLER, help="Path to main_controller.py")
    parser.add_argument("--shortlisting", type=Path, default=DEFAULT_SHORTLISTING_DIR, help="Holdout folder to run on")
    parser.add_argument("--whitelist", type=Path, default=DEFAULT_WHITELIST, help="Whitelist workbook passed to the controller")
    parser.add_argument("--gt-workbook", type=Path, default=DEFAULT_GT_WORKBOOK, help="Ground-truth workbook used for recall ranking")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_TUNING_ROOT, help="Directory where per-iteration snapshots and summaries are written")
    parser.add_argument("--python-executable", type=str, default=sys.executable, help="Python executable used to launch controller runs")
    parser.add_argument("--pipeline-mode", type=str, default="hash_only", help="Pipeline mode forwarded to main_controller.py")
    parser.add_argument("--limit", type=int, default=None, help="Optional whitelist limit forwarded to the controller")
    parser.add_argument("--target-limit", type=int, default=None, help="Optional target URL limit forwarded to the controller")
    parser.add_argument("--continue-on-error", action="store_true", help="Continue remaining iterations if one preset fails")
    parser.add_argument("--skip-existing", action="store_true", help="Reuse existing iteration snapshot folders when they already exist")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    args = _build_parser().parse_args(argv)
    repo_root = Path.cwd()
    summaries = run_tuning_iterations(
        repo_root=repo_root,
        controller_path=args.controller,
        shortlisting=args.shortlisting,
        whitelist=args.whitelist,
        gt_workbook=args.gt_workbook,
        tuning_root=args.output_root,
        python_executable=args.python_executable,
        pipeline_mode=args.pipeline_mode,
        limit=args.limit,
        target_limit=args.target_limit,
        continue_on_error=args.continue_on_error,
        skip_existing=args.skip_existing,
    )
    if summaries:
        logger.info(
            "Best iteration: %s (gt_final_output_count=%d, gt_stage3_count=%d, gt_review_count=%d, gt_holdout_count=%d)",
            summaries[0]["preset_name"],
            summaries[0].get("gt_final_output_count", 0),
            summaries[0].get("gt_stage3_count", 0),
            summaries[0].get("gt_review_count", 0),
            summaries[0].get("gt_holdout_count", 0),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
