"""Utilities for recall-tuning experiment summaries.

These helpers operate on per-iteration output artifacts and deliberately avoid
changing pipeline classification or scoring behavior.
"""

from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any, Iterable

import pandas as pd

from ._shortlisting_legacy import normalize_url


def _normalize_stage_url(value: Any) -> str:
    return normalize_url(str(value or "").strip())


def _copy_tree_contents(src_dir: str | Path, dst_dir: str | Path) -> None:
    src_path = Path(src_dir)
    dst_path = Path(dst_dir)
    dst_path.mkdir(parents=True, exist_ok=True)
    if not src_path.exists():
        return
    for child in src_path.iterdir():
        if child.name == "tuning_runs":
            continue
        target = dst_path / child.name
        if child.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(child, target, ignore=shutil.ignore_patterns("tuning_runs"))
        else:
            shutil.copy2(child, target)


def _read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, dtype=str, keep_default_na=False)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


def _normalized_series(df: pd.DataFrame, candidates: Iterable[str]) -> pd.Series:
    for column in candidates:
        if column in df.columns:
            return df[column].map(_normalize_stage_url)
    return pd.Series([], dtype=str)


def _count_gt_rows(df: pd.DataFrame, gt_urls: set[str], columns: Iterable[str]) -> int:
    if df.empty:
        return 0
    urls = _normalized_series(df, columns)
    if urls.empty:
        return 0
    return int(urls.isin(gt_urls).sum())


def summarize_iteration_artifacts(
    *,
    iteration_dir: str | Path,
    gt_targets: list[dict[str, Any]],
    workbook_names: list[str],
) -> dict[str, Any]:
    iteration_path = Path(iteration_dir)
    gt_urls = {
        _normalize_stage_url(target.get("normalized_url") or target.get("gt_domain"))
        for target in gt_targets
        if target
    }

    stage1_df = _read_csv(iteration_path / "stage1_lexical_debug.csv")
    if stage1_df.empty:
        stage1_df = _read_csv(iteration_path / "stage0_lexical_decisions.csv")
    holdout_df = _read_csv(iteration_path / "holdout.csv")
    stage3_df = _read_csv(iteration_path / "stage3_classification_debug.csv")
    output_df = _read_csv(iteration_path / "output_file.csv")
    filtered_df = _read_csv(iteration_path / "output_file_filtered.csv")
    review_df = _read_csv(iteration_path / "hash_review_queue.csv")

    output_source = output_df if not output_df.empty else filtered_df
    output_columns = ["Identified Phishing/Suspected Domain Name", "url", "normalized_url"]
    stage3_columns = ["url", "Identified Phishing/Suspected Domain Name", "normalized_url"]
    holdout_columns = ["Identified Phishing/Suspected Domain Name", "url", "normalized_url"]

    gt_output_count = _count_gt_rows(output_source, gt_urls, output_columns)
    gt_stage3_count = _count_gt_rows(stage3_df, gt_urls, stage3_columns)
    gt_review_count = _count_gt_rows(review_df, gt_urls, holdout_columns)
    gt_holdout_count = _count_gt_rows(holdout_df, gt_urls, holdout_columns)

    workbook_rows = []
    for workbook_name in workbook_names:
        workbook_text = str(workbook_name or "")
        workbook_rows.append(
            {
                "source_workbook": workbook_text,
                "stage1_count": _count_workbook(stage1_df, workbook_text),
                "holdout_count": _count_workbook(holdout_df, workbook_text),
                "stage3_count": _count_workbook(stage3_df, workbook_text),
                "review_count": _count_workbook(review_df, workbook_text),
                "output_count": _count_workbook_output(
                    output_source,
                    workbook_text,
                    source_frames=(stage3_df, holdout_df, stage1_df),
                    url_columns=output_columns,
                ),
            }
        )
    pd.DataFrame(workbook_rows).to_csv(
        iteration_path / "source_workbook_funnel_counts.csv",
        index=False,
    )

    stage3_gate_by_url = {}
    if not stage3_df.empty:
        urls = _normalized_series(stage3_df, stage3_columns)
        for idx, normalized in urls.items():
            if normalized:
                stage3_gate_by_url[normalized] = str(
                    stage3_df.loc[idx, "classification_gate_reason"]
                    if "classification_gate_reason" in stage3_df.columns
                    else ""
                )

    output_urls = set(_normalized_series(output_source, output_columns).tolist())
    holdout_urls = set(_normalized_series(holdout_df, holdout_columns).tolist())
    stage3_urls = set(_normalized_series(stage3_df, stage3_columns).tolist())
    review_urls = set(_normalized_series(review_df, holdout_columns).tolist())

    trace_rows = []
    for target in gt_targets:
        normalized = _normalize_stage_url(target.get("normalized_url") or target.get("gt_domain"))
        trace_rows.append(
            {
                "gt_domain": str(target.get("gt_domain", "")),
                "normalized_url": normalized,
                "in_stage1": normalized in set(_normalized_series(stage1_df, ["normalized_url", "input_url"]).tolist()),
                "in_holdout": normalized in holdout_urls,
                "in_stage3": normalized in stage3_urls,
                "in_review": normalized in review_urls,
                "in_output": normalized in output_urls,
                "stage3_gate_reason": stage3_gate_by_url.get(normalized, ""),
            }
        )
    pd.DataFrame(trace_rows).to_csv(iteration_path / "gt_domain_trace.csv", index=False)

    return {
        "gt_final_output_count": gt_output_count,
        "gt_stage3_count": gt_stage3_count,
        "gt_review_count": gt_review_count,
        "gt_holdout_count": gt_holdout_count,
        "flagged_output_count": int(len(output_source)),
        "total_output_count": int(len(output_df) if not output_df.empty else len(filtered_df)),
    }


def _count_workbook(df: pd.DataFrame, workbook_name: str) -> int:
    if df.empty or "source_workbook" not in df.columns:
        return 0
    return int(
        df["source_workbook"]
        .astype(str)
        .map(lambda value: workbook_name in [part.strip() for part in value.split("|")])
        .sum()
    )


def _count_workbook_output(
    output_df: pd.DataFrame,
    workbook_name: str,
    *,
    source_frames: tuple[pd.DataFrame, ...],
    url_columns: Iterable[str],
) -> int:
    direct_count = _count_workbook(output_df, workbook_name)
    if direct_count or output_df.empty:
        return direct_count

    workbook_urls: set[str] = set()
    for frame in source_frames:
        if frame.empty or "source_workbook" not in frame.columns:
            continue
        urls = _normalized_series(frame, ["url", "Identified Phishing/Suspected Domain Name", "normalized_url", "input_url"])
        for idx, normalized in urls.items():
            source_value = str(frame.loc[idx, "source_workbook"] or "")
            source_workbooks = [part.strip() for part in source_value.split("|")]
            if workbook_name in source_workbooks and normalized:
                workbook_urls.add(normalized)

    output_urls = _normalized_series(output_df, url_columns)
    if output_urls.empty:
        return 0
    return int(output_urls.isin(workbook_urls).sum())


def rank_iteration_summaries(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = sorted(
        (dict(summary) for summary in summaries),
        key=lambda item: (
            -int(item.get("gt_final_output_count", 0) or 0),
            -int(item.get("gt_stage3_count", 0) or 0),
            -int(item.get("gt_review_count", 0) or 0),
            -int(item.get("gt_holdout_count", 0) or 0),
            int(item.get("flagged_output_count", 0) or 0),
            int(item.get("total_output_count", 0) or 0),
            int(item.get("iteration_index", 0) or 0),
            str(item.get("preset_name", "")),
        ),
    )
    for index, summary in enumerate(ranked, start=1):
        summary["rank"] = index
    return ranked
