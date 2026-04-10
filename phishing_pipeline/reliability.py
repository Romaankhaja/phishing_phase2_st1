from __future__ import annotations

import asyncio
import csv
import errno
import hashlib
import json
import logging
import os
import random
import shutil
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

_CSV_WRITE_RETRY_ATTEMPTS = 12
_CSV_WRITE_RETRY_BASE_SECONDS = 0.2
_CSV_WRITE_RETRY_CAP_SECONDS = 2.0
_EXPORT_WARNING_INTERVAL_SECONDS = 30.0
_DEFAULT_TELEMETRY_MODE = "sampled"
_ALLOWED_TELEMETRY_MODES = {"sampled", "full", "debug"}

RUN_RESULT_COLUMNS = (
    "run_id",
    "record_key",
    "source_workbook",
    "raw_url",
    "normalized_url",
    "current_stage",
    "stage_status",
    "stage_error_type",
    "stage_error_message",
    "retry_count",
    "timeout_hit",
    "skipped_due_to_previous_failure",
    "fallback_taken",
    "worker_id",
    "stage_started_at",
    "stage_finished_at",
    "duration_ms",
    "stage0_status",
    "stage1_status",
    "dns_stage_status",
    "hash_stage_status",
    "classify_stage_status",
    "final_pipeline_status",
    "final_decision",
    "failure_reason",
    "processing_time_ms",
    "submission_record_json",
    "last_updated_at",
)

STAGE_EVENT_COLUMNS = (
    "run_id",
    "record_key",
    "source_workbook",
    "normalized_url",
    "stage_name",
    "attempt_index",
    "worker_id",
    "started_at",
    "finished_at",
    "duration_ms",
    "status",
    "error_type",
    "error_message",
    "retry_count",
    "timeout_flag",
    "fallback_taken",
)

RUN_MANIFEST_COLUMNS = (
    "run_id",
    "status",
    "started_at",
    "updated_at",
    "completed_at",
    "fatal_stage",
    "fatal_error_type",
    "fatal_error_message",
    "metadata_json",
    "checkpoint_dir",
    "checkpoints_csv",
    "url_result_events_csv",
    "stage_events_csv",
)

WORKER_HEARTBEAT_COLUMNS = (
    "stage_name",
    "worker_id",
    "record_key",
    "state",
    "task_kind",
    "item_age_s",
    "emitted_at",
    "last_seen_at",
    "details_json",
)

STAGE_METRIC_COLUMNS = (
    "run_id",
    "emitted_at",
    "label",
    "stage_name",
    "worker_id",
    "metric_kind",
    "counters_json",
    "gauges_json",
    "latency_json",
    "resource_snapshot_json",
    "details_json",
)

STALL_EVENT_COLUMNS = (
    "run_id",
    "emitted_at",
    "label",
    "stage_name",
    "severity",
    "message",
    "resource_snapshot_json",
    "details_json",
)

RUN_RESULT_INT_FIELDS = {
    "retry_count",
    "timeout_hit",
    "skipped_due_to_previous_failure",
    "duration_ms",
    "processing_time_ms",
}

STAGE_EVENT_INT_FIELDS = {
    "attempt_index",
    "duration_ms",
    "retry_count",
    "timeout_flag",
}

TERMINAL_PIPELINE_STATUSES = {
    "completed",
    "terminal_invalid_input",
    "classification_failed",
    "filtered_lexical_miss",
    "stage1_failed",
    "stage1_failed_fallback_dns",
    "hash_failed",
    "not_registered_domain",
    "review_only",
    "pre_hash_filtered",
    "failed",
}

STAGE_TO_STATUS_FIELD = {
    "stage0": "stage0_status",
    "stage1": "stage1_status",
    "dns": "dns_stage_status",
    "hash": "hash_stage_status",
    "classify": "classify_stage_status",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def make_record_key(normalized_url: str, source_workbook: str) -> str:
    seed = f"{str(normalized_url or '').strip().lower()}|{str(source_workbook or '').strip()}"
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()


def summarize_traceback(exc: BaseException | None, *, limit: int = 3) -> str:
    if exc is None:
        return ""
    try:
        tb_lines = traceback.format_exception(type(exc), exc, exc.__traceback__)
    except Exception:
        return exc.__class__.__name__
    trimmed = [line.strip() for line in tb_lines if line.strip()]
    return " | ".join(trimmed[-limit:])


def normalize_exception(exc: BaseException | None) -> dict[str, Any]:
    if exc is None:
        return {
            "error_type": "",
            "error_message": "",
            "traceback_summary": "",
        }
    message = str(exc).strip() or exc.__class__.__name__
    return {
        "error_type": exc.__class__.__name__,
        "error_message": message,
        "traceback_summary": summarize_traceback(exc),
    }


def classify_transient_exception(exc: BaseException | None) -> tuple[bool, bool]:
    if exc is None:
        return False, False
    if isinstance(exc, asyncio.TimeoutError):
        return True, True
    text = f"{exc.__class__.__name__}: {exc}".lower()
    timeout_flag = "timeout" in text
    retryable = any(
        marker in text
        for marker in (
            "timeout",
            "tempor",
            "connection reset",
            "reset by peer",
            "server disconnected",
            "network is unreachable",
            "name or service not known",
            "try again",
            "429",
            "502",
            "503",
            "504",
        )
    )
    return retryable, timeout_flag


def default_run_result(
    *,
    run_id: str,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "record_key": make_record_key(normalized_url, source_workbook),
        "source_workbook": str(source_workbook or ""),
        "raw_url": str(raw_url or ""),
        "normalized_url": str(normalized_url or ""),
        "current_stage": "",
        "stage_status": "",
        "stage_error_type": "",
        "stage_error_message": "",
        "retry_count": 0,
        "timeout_hit": 0,
        "skipped_due_to_previous_failure": 0,
        "fallback_taken": "",
        "worker_id": "",
        "stage_started_at": "",
        "stage_finished_at": "",
        "duration_ms": 0,
        "stage0_status": "pending",
        "stage1_status": "pending",
        "dns_stage_status": "pending",
        "hash_stage_status": "pending",
        "classify_stage_status": "pending",
        "final_pipeline_status": "pending",
        "final_decision": "",
        "failure_reason": "",
        "processing_time_ms": 0,
        "submission_record_json": "",
        "last_updated_at": utc_now_iso(),
    }


@dataclass
class RunContext:
    run_id: str
    output_dir: str
    run_output_dir: str
    latest_output_dir: str
    checkpoints_csv: str
    checkpoint_dir: str
    run_results_csv: str
    stage_events_csv: str
    run_manifest_csv: str
    run_manifest_json: str
    run_summary_json: str
    checkpoint_run_manifest_csv: str
    url_result_events_csv: str
    checkpoint_stage_events_csv: str
    worker_heartbeats_csv: str
    stage_metrics_csv: str
    stall_events_csv: str
    telemetry_mode: str = _DEFAULT_TELEMETRY_MODE
    trace_record_key: str = ""
    trace_url: str = ""
    artifact_paths: dict[str, str] = field(default_factory=dict)
    artifact_latest_paths: dict[str, str] = field(default_factory=dict)
    artifact_legacy_paths: dict[str, list[str]] = field(default_factory=dict)
    stall_threshold_seconds: int = 180
    watchdog_warning_seconds: int = 60
    append_flush_interval_seconds: int = 5
    append_flush_row_interval: int = 2000
    snapshot_flush_interval_seconds: int = 30
    snapshot_flush_row_interval: int = 5000
    stage0_progress_log_interval_seconds: int = 10
    stage1_failure_policy: str = "route_to_dns"
    max_worker_restarts: int = 2
    started_at: str = field(default_factory=utc_now_iso)
    started_monotonic: float = field(default_factory=time.monotonic)
    metadata: dict[str, Any] = field(default_factory=dict)


def build_run_context(
    *,
    output_dir: str,
    run_id: str | None = None,
    telemetry_mode: str = _DEFAULT_TELEMETRY_MODE,
    trace_record_key: str | None = None,
    trace_url: str | None = None,
    stall_threshold_seconds: int = 180,
    watchdog_warning_seconds: int = 60,
    append_flush_interval_seconds: int = 5,
    append_flush_row_interval: int = 2000,
    snapshot_flush_interval_seconds: int = 30,
    snapshot_flush_row_interval: int = 5000,
    stage0_progress_log_interval_seconds: int = 10,
    stage1_failure_policy: str = "route_to_dns",
    max_worker_restarts: int = 2,
    metadata: dict[str, Any] | None = None,
) -> RunContext:
    resolved_run_id = str(run_id or datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ"))
    os.makedirs(output_dir, exist_ok=True)
    normalized_telemetry_mode = str(telemetry_mode or _DEFAULT_TELEMETRY_MODE).strip().lower()
    if normalized_telemetry_mode not in _ALLOWED_TELEMETRY_MODES:
        normalized_telemetry_mode = _DEFAULT_TELEMETRY_MODE
    artifact_paths, artifact_latest_paths, artifact_legacy_paths = _build_run_artifact_maps(
        output_dir=output_dir,
        run_id=resolved_run_id,
    )
    run_output_dir = artifact_paths["run_root"]
    latest_output_dir = artifact_paths["latest_root"]
    checkpoints_csv = artifact_paths["checkpoints_csv"]
    return RunContext(
        run_id=resolved_run_id,
        output_dir=output_dir,
        run_output_dir=run_output_dir,
        latest_output_dir=latest_output_dir,
        checkpoints_csv=checkpoints_csv,
        checkpoint_dir="",
        run_results_csv=artifact_paths["run_results_csv"],
        stage_events_csv=artifact_paths["stage_events_csv"],
        run_manifest_csv=artifact_paths["run_manifest_csv"],
        run_manifest_json=artifact_paths["run_manifest_json"],
        run_summary_json=artifact_paths["run_summary_json"],
        checkpoint_run_manifest_csv=artifact_paths["run_manifest_csv"],
        url_result_events_csv=checkpoints_csv,
        checkpoint_stage_events_csv=artifact_paths["stage_events_csv"],
        worker_heartbeats_csv=artifact_paths["worker_heartbeats_csv"],
        stage_metrics_csv=artifact_paths["stage_metrics_csv"],
        stall_events_csv=artifact_paths["stall_events_csv"],
        telemetry_mode=normalized_telemetry_mode,
        trace_record_key=str(trace_record_key or ""),
        trace_url=str(trace_url or ""),
        artifact_paths=artifact_paths,
        artifact_latest_paths=artifact_latest_paths,
        artifact_legacy_paths=artifact_legacy_paths,
        stall_threshold_seconds=max(30, int(stall_threshold_seconds)),
        watchdog_warning_seconds=max(15, int(watchdog_warning_seconds)),
        append_flush_interval_seconds=max(1, int(append_flush_interval_seconds)),
        append_flush_row_interval=max(1, int(append_flush_row_interval)),
        snapshot_flush_interval_seconds=max(1, int(snapshot_flush_interval_seconds)),
        snapshot_flush_row_interval=max(1, int(snapshot_flush_row_interval)),
        stage0_progress_log_interval_seconds=max(1, int(stage0_progress_log_interval_seconds)),
        stage1_failure_policy=str(stage1_failure_policy or "route_to_dns"),
        max_worker_restarts=max(0, int(max_worker_restarts)),
        metadata=dict(metadata or {}),
    )


def _artifact_relpath(*parts: str) -> str:
    return os.path.join(*parts)


def _build_run_artifact_maps(
    *,
    output_dir: str,
    run_id: str,
) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
    run_root = os.path.join(output_dir, "runs", run_id)
    latest_root = os.path.join(output_dir, "latest")
    relpaths = {
        "run_root": "",
        "latest_root": "",
        "checkpoints_csv": _artifact_relpath("events", "checkpoints.csv"),
        "run_results_csv": _artifact_relpath("events", "pipeline_run_results.csv"),
        "stage_events_csv": _artifact_relpath("events", "pipeline_stage_events.csv"),
        "worker_heartbeats_csv": _artifact_relpath("events", "worker_heartbeats.csv"),
        "stage_metrics_csv": _artifact_relpath("events", "stage_metrics.csv"),
        "stall_events_csv": _artifact_relpath("events", "stall_events.csv"),
        "run_manifest_csv": "run_manifest.csv",
        "run_manifest_json": "run_manifest.json",
        "run_summary_json": "run_summary.json",
        "effective_args_json": _artifact_relpath("config", "effective_args.json"),
        "effective_runtime_json": _artifact_relpath("config", "effective_runtime.json"),
        "input_manifest_csv": _artifact_relpath("config", "input_manifest.csv"),
        "stage0_lexical_decisions_csv": _artifact_relpath("stage0", "stage0_lexical_decisions.csv"),
        "stage1_http_routing_csv": _artifact_relpath("stage1", "stage1_http_routing.csv"),
        "stage1_methods_csv": _artifact_relpath("stage1", "stage1_methods_debug.csv"),
        "stage1_deep_analysis_candidates_csv": _artifact_relpath("stage1", "stage1_deep_analysis_candidates.csv"),
        "stage1_review_queue_csv": _artifact_relpath("stage1", "review_queue.csv"),
        "fetch_failed_lexical_hits_csv": _artifact_relpath("stage1", "fetch_failed_lexical_hits.csv"),
        "hashing_excluded_urls_csv": _artifact_relpath("stage1", "hashing_shortlist_excluded_urls.csv"),
        "hashing_log": _artifact_relpath("hash", "hashing_shortlist.log"),
        "ray_render_trace_csv": _artifact_relpath("hash", "ray_shortlist_render_trace.csv"),
        "hash_export_dir": _artifact_relpath("hash", "hash_folder"),
        "holdout_csv": _artifact_relpath("final", "holdout.csv"),
        "hash_review_queue_csv": _artifact_relpath("classify", "hash_review_queue.csv"),
        "stage2_model_debug_csv": _artifact_relpath("classify", "stage2_model_debug.csv"),
        "stage3_classification_debug_csv": _artifact_relpath("classify", "stage3_classification_debug.csv"),
        "final_output_csv": _artifact_relpath("final", "output_file.csv"),
        "final_output_filtered_csv": _artifact_relpath("final", "output_file_filtered.csv"),
        "replay_dir": "replay",
    }
    artifact_paths = {
        key: (run_root if relpath == "" else os.path.join(run_root, relpath))
        for key, relpath in relpaths.items()
    }
    artifact_paths["run_root"] = run_root
    artifact_paths["latest_root"] = latest_root
    artifact_latest_paths = {
        key: (latest_root if relpath == "" else os.path.join(latest_root, relpath))
        for key, relpath in relpaths.items()
    }
    artifact_latest_paths["run_root"] = run_root
    artifact_latest_paths["latest_root"] = latest_root
    artifact_legacy_paths = {
        "checkpoints_csv": [os.path.join(output_dir, "checkpoints.csv")],
        "run_results_csv": [os.path.join(output_dir, "pipeline_run_results.csv")],
        "stage_events_csv": [os.path.join(output_dir, "pipeline_stage_events.csv")],
        "worker_heartbeats_csv": [os.path.join(output_dir, "worker_heartbeats.csv")],
        "stage_metrics_csv": [os.path.join(output_dir, "stage_metrics.csv")],
        "stall_events_csv": [os.path.join(output_dir, "stall_events.csv")],
        "run_manifest_csv": [os.path.join(output_dir, "run_manifest.csv")],
        "run_manifest_json": [os.path.join(output_dir, "run_manifest.json")],
        "run_summary_json": [os.path.join(output_dir, "run_summary.json")],
        "holdout_csv": [os.path.join(output_dir, "holdout.csv")],
        "stage0_lexical_decisions_csv": [
            os.path.join(output_dir, "stage0_lexical_decisions.csv"),
            os.path.join(output_dir, "stage1_lexical_debug.csv"),
        ],
        "stage1_http_routing_csv": [os.path.join(output_dir, "stage1_http_routing.csv")],
        "stage1_methods_csv": [os.path.join(output_dir, "stage1_methods_debug.csv")],
        "stage1_deep_analysis_candidates_csv": [os.path.join(output_dir, "stage1_deep_analysis_candidates.csv")],
        "stage1_review_queue_csv": [os.path.join(output_dir, "stage1_review_queue.csv")],
        "fetch_failed_lexical_hits_csv": [os.path.join(output_dir, "fetch_failed_lexical_hits.csv")],
        "hashing_excluded_urls_csv": [os.path.join(output_dir, "hashing_shortlist_excluded_urls.csv")],
        "hashing_log": [os.path.join(output_dir, "hashing_shortlist.log")],
        "hash_review_queue_csv": [os.path.join(output_dir, "hash_review_queue.csv")],
        "stage2_model_debug_csv": [os.path.join(output_dir, "stage2_model_debug.csv")],
        "stage3_classification_debug_csv": [os.path.join(output_dir, "stage3_classification_debug.csv")],
        "final_output_csv": [os.path.join(output_dir, "output_file.csv")],
        "final_output_filtered_csv": [os.path.join(output_dir, "output_file_filtered.csv")],
    }
    return artifact_paths, artifact_latest_paths, artifact_legacy_paths


def get_run_artifact_path(run_context: RunContext | None, key: str, fallback: str = "") -> str:
    if run_context is not None:
        resolved = str((run_context.artifact_paths or {}).get(key, "") or "")
        if resolved:
            return resolved
    return str(fallback or "")


def get_run_artifact_alias_paths(run_context: RunContext | None, key: str) -> list[str]:
    if run_context is None:
        return []
    aliases: list[str] = []
    latest_path = str((run_context.artifact_latest_paths or {}).get(key, "") or "")
    if latest_path:
        aliases.append(latest_path)
    aliases.extend(
        path
        for path in (run_context.artifact_legacy_paths or {}).get(key, [])
        if str(path or "").strip()
    )
    deduped: list[str] = []
    seen: set[str] = set()
    for path in aliases:
        normalized = os.path.normcase(os.path.abspath(path))
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(path)
    return deduped


def _is_retryable_filesystem_error(exc: BaseException | None) -> bool:
    if exc is None:
        return False
    if isinstance(exc, PermissionError):
        return True
    if not isinstance(exc, OSError):
        return False
    if getattr(exc, "winerror", None) in {5, 32}:
        return True
    return getattr(exc, "errno", None) in {errno.EACCES, errno.EPERM, errno.EBUSY}


def _retryable_write_delay(attempt_index: int) -> float:
    return min(
        _CSV_WRITE_RETRY_CAP_SECONDS,
        _CSV_WRITE_RETRY_BASE_SECONDS * (2 ** max(0, int(attempt_index))),
    )


def _replace_file_atomic(temp_path: str, path: str) -> None:
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        try:
            os.replace(temp_path, path)
            return
        except Exception as exc:
            last_exc = exc
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def _write_csv_atomic(path: str, fieldnames: tuple[str, ...] | list[str], rows: list[dict[str, Any]]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        temp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.{attempt_index}.tmp"
        try:
            with open(temp_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in fieldnames})
            _replace_file_atomic(temp_path, path)
            return
        except Exception as exc:
            last_exc = exc
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def _append_csv_rows(path: str, fieldnames: tuple[str, ...] | list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        file_exists = os.path.exists(path)
        try:
            with open(path, "a", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
                if not file_exists:
                    writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in fieldnames})
                fh.flush()
            return
        except Exception as exc:
            last_exc = exc
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def _copy_csv_atomic(src_path: str, dst_path: str, fieldnames: tuple[str, ...] | list[str]) -> None:
    if not os.path.exists(src_path):
        _write_csv_atomic(dst_path, fieldnames, [])
        return
    directory = os.path.dirname(dst_path) or "."
    os.makedirs(directory, exist_ok=True)
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        temp_path = f"{dst_path}.{os.getpid()}.{threading.get_ident()}.{attempt_index}.tmp"
        try:
            with open(src_path, "r", newline="", encoding="utf-8") as src, open(temp_path, "w", newline="", encoding="utf-8") as dst:
                shutil.copyfileobj(src, dst)
            _replace_file_atomic(temp_path, dst_path)
            return
        except Exception as exc:
            last_exc = exc
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def _write_json_atomic(path: str, payload: Any) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        temp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.{attempt_index}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=True, indent=2, sort_keys=True)
                fh.write("\n")
            _replace_file_atomic(temp_path, path)
            return
        except Exception as exc:
            last_exc = exc
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def _copy_file_atomic(src_path: str, dst_path: str) -> None:
    if not os.path.exists(src_path):
        return
    directory = os.path.dirname(dst_path) or "."
    os.makedirs(directory, exist_ok=True)
    last_exc: BaseException | None = None
    for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
        temp_path = f"{dst_path}.{os.getpid()}.{threading.get_ident()}.{attempt_index}.tmp"
        try:
            with open(src_path, "rb") as src, open(temp_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            _replace_file_atomic(temp_path, dst_path)
            return
        except Exception as exc:
            last_exc = exc
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
            if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
                raise
            time.sleep(_retryable_write_delay(attempt_index))
    if last_exc is not None:
        raise last_exc


def sync_run_artifact(
    run_context: RunContext | None,
    key: str,
    *,
    src_path: str | None = None,
    best_effort: bool = False,
) -> None:
    if run_context is None:
        return
    source_path = str(src_path or get_run_artifact_path(run_context, key))
    if not source_path:
        return
    for alias_path in get_run_artifact_alias_paths(run_context, key):
        if os.path.normcase(os.path.abspath(alias_path)) == os.path.normcase(os.path.abspath(source_path)):
            continue
        try:
            _copy_file_atomic(source_path, alias_path)
        except Exception:
            if best_effort and _is_retryable_filesystem_error(_safe_current_exception()):
                continue
            raise


def write_run_artifact_json(
    run_context: RunContext | None,
    key: str,
    payload: Any,
    *,
    best_effort: bool = False,
) -> str:
    target_path = get_run_artifact_path(run_context, key)
    if not target_path:
        raise ValueError(f"Unknown run artifact key: {key}")
    try:
        _write_json_atomic(target_path, payload)
        sync_run_artifact(run_context, key, src_path=target_path, best_effort=best_effort)
    except Exception:
        if best_effort and _is_retryable_filesystem_error(_safe_current_exception()):
            return target_path
        raise
    return target_path


def write_run_artifact_csv(
    run_context: RunContext | None,
    key: str,
    fieldnames: tuple[str, ...] | list[str],
    rows: list[dict[str, Any]],
    *,
    best_effort: bool = False,
) -> str:
    target_path = get_run_artifact_path(run_context, key)
    if not target_path:
        raise ValueError(f"Unknown run artifact key: {key}")
    try:
        _write_csv_atomic(target_path, fieldnames, rows)
        sync_run_artifact(run_context, key, src_path=target_path, best_effort=best_effort)
    except Exception:
        if best_effort and _is_retryable_filesystem_error(_safe_current_exception()):
            return target_path
        raise
    return target_path


def _safe_current_exception() -> BaseException | None:
    try:
        return sys.exc_info()[1]
    except Exception:
        return None


def _coerce_int_fields(row: dict[str, Any], fields: set[str]) -> dict[str, Any]:
    normalized = dict(row)
    for field in fields:
        value = normalized.get(field, 0)
        if value in ("", None):
            normalized[field] = 0
            continue
        try:
            normalized[field] = int(value)
        except Exception:
            normalized[field] = 0
    return normalized


def _parse_json_field(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    text = str(value or "").strip()
    if not text:
        return fallback
    try:
        return json.loads(text)
    except Exception:
        return fallback


class CheckpointStore:
    def __init__(self, context: RunContext):
        self.context = context
        self._lock = threading.RLock()
        self._url_results: dict[str, dict[str, Any]] = {}
        self._worker_heartbeats: dict[tuple[str, str], dict[str, Any]] = {}
        self._stage_events: list[dict[str, Any]] = []
        self._stage_metrics: list[dict[str, Any]] = []
        self._stall_events: list[dict[str, Any]] = []
        self._manifest: dict[str, Any] = {
            "run_id": self.context.run_id,
            "status": "running",
            "started_at": self.context.started_at,
            "updated_at": self.context.started_at,
            "completed_at": "",
            "fatal_stage": "",
            "fatal_error_type": "",
            "fatal_error_message": "",
            "metadata_json": dict(self.context.metadata),
            "checkpoint_dir": "",
            "checkpoints_csv": self.context.checkpoints_csv,
            "url_result_events_csv": self.context.checkpoints_csv,
            "stage_events_csv": self.context.stage_events_csv,
            "worker_heartbeats_csv": self.context.worker_heartbeats_csv,
            "stage_metrics_csv": self.context.stage_metrics_csv,
            "stall_events_csv": self.context.stall_events_csv,
            "run_manifest_json": self.context.run_manifest_json,
            "run_summary_json": self.context.run_summary_json,
            "run_output_dir": self.context.run_output_dir,
            "latest_output_dir": self.context.latest_output_dir,
            "telemetry_mode": self.context.telemetry_mode,
        }
        self._pending_result_events: list[dict[str, Any]] = []
        self._pending_stage_events: list[dict[str, Any]] = []
        self._pending_event_count = 0
        self._append_dirty = False
        self._snapshot_dirty = False
        self._dirty_snapshot_updates = 0
        self._heartbeat_dirty = False
        self._last_append_flush_monotonic = time.monotonic()
        self._last_snapshot_flush_monotonic = time.monotonic()
        self._last_export_warning_monotonic = 0.0
        self._load_existing_state()
        self.start_run(status="running", metadata=self.context.metadata)

    def _log_deferred_export_warning(self, operation: str, exc: BaseException) -> None:
        now = time.monotonic()
        if (now - self._last_export_warning_monotonic) < _EXPORT_WARNING_INTERVAL_SECONDS:
            return
        self._last_export_warning_monotonic = now
        logger.warning(
            "Deferred checkpoint export due to transient file lock | run_id=%s | operation=%s | error=%s",
            self.context.run_id,
            operation,
            exc,
        )

    def _load_existing_state(self) -> None:
        with self._lock:
            if self.context.run_manifest_json and os.path.exists(self.context.run_manifest_json):
                try:
                    with open(self.context.run_manifest_json, encoding="utf-8") as fh:
                        manifest = json.load(fh)
                    if isinstance(manifest, dict):
                        manifest["metadata_json"] = _parse_json_field(manifest.get("metadata_json"), {})
                        self._manifest.update(manifest)
                except Exception:
                    logger.exception("Failed to load existing run manifest JSON")
            if self.context.run_manifest_csv and os.path.exists(self.context.run_manifest_csv):
                try:
                    with open(self.context.run_manifest_csv, newline="", encoding="utf-8") as fh:
                        rows = list(csv.DictReader(fh))
                    if rows:
                        manifest = dict(rows[-1])
                        manifest["metadata_json"] = _parse_json_field(manifest.get("metadata_json"), {})
                        self._manifest.update(manifest)
                except Exception:
                    logger.exception("Failed to load existing run manifest CSV")

            if self.context.checkpoints_csv and os.path.exists(self.context.checkpoints_csv):
                try:
                    with open(self.context.checkpoints_csv, newline="", encoding="utf-8") as fh:
                        for row in csv.DictReader(fh):
                            normalized = _coerce_int_fields(row, RUN_RESULT_INT_FIELDS)
                            if str(normalized.get("run_id", "") or "") != self.context.run_id:
                                continue
                            record_key = str(normalized.get("record_key", "") or "")
                            if record_key:
                                self._url_results[record_key] = normalized
                except Exception:
                    logger.exception("Failed to load checkpoints CSV")

            if self.context.stage_events_csv and os.path.exists(self.context.stage_events_csv):
                try:
                    with open(self.context.stage_events_csv, newline="", encoding="utf-8") as fh:
                        for row in csv.DictReader(fh):
                            item = _coerce_int_fields(dict(row), STAGE_EVENT_INT_FIELDS)
                            if str(item.get("run_id", "") or "") != self.context.run_id:
                                continue
                            self._stage_events.append(item)
                except Exception:
                    logger.exception("Failed to load stage events CSV")
            if self.context.worker_heartbeats_csv and os.path.exists(self.context.worker_heartbeats_csv):
                try:
                    with open(self.context.worker_heartbeats_csv, newline="", encoding="utf-8") as fh:
                        for row in csv.DictReader(fh):
                            stage_name = str(row.get("stage_name", "") or "")
                            worker_id = str(row.get("worker_id", "") or "")
                            if not stage_name or not worker_id:
                                continue
                            item = dict(row)
                            item["details_json"] = _parse_json_field(item.get("details_json"), {})
                            self._worker_heartbeats[(stage_name, worker_id)] = item
                except Exception:
                    logger.exception("Failed to load worker heartbeats CSV")
            if self.context.stage_metrics_csv and os.path.exists(self.context.stage_metrics_csv):
                try:
                    with open(self.context.stage_metrics_csv, newline="", encoding="utf-8") as fh:
                        for row in csv.DictReader(fh):
                            if str(row.get("run_id", "") or "") != self.context.run_id:
                                continue
                            self._stage_metrics.append(dict(row))
                except Exception:
                    logger.exception("Failed to load stage metrics CSV")
            if self.context.stall_events_csv and os.path.exists(self.context.stall_events_csv):
                try:
                    with open(self.context.stall_events_csv, newline="", encoding="utf-8") as fh:
                        for row in csv.DictReader(fh):
                            if str(row.get("run_id", "") or "") != self.context.run_id:
                                continue
                            self._stall_events.append(dict(row))
                except Exception:
                    logger.exception("Failed to load stall events CSV")

    def start_run(self, *, status: str = "running", metadata: dict[str, Any] | None = None) -> None:
        now = utc_now_iso()
        with self._lock:
            self._manifest.update(
                {
                    "run_id": self.context.run_id,
                    "status": status,
                    "started_at": self._manifest.get("started_at") or self.context.started_at,
                    "updated_at": now,
                    "metadata_json": dict(metadata or self.context.metadata or {}),
                    "checkpoint_dir": "",
                    "checkpoints_csv": self.context.checkpoints_csv,
                    "url_result_events_csv": self.context.checkpoints_csv,
                    "stage_events_csv": self.context.stage_events_csv,
                    "worker_heartbeats_csv": self.context.worker_heartbeats_csv,
                    "stage_metrics_csv": self.context.stage_metrics_csv,
                    "stall_events_csv": self.context.stall_events_csv,
                    "run_manifest_json": self.context.run_manifest_json,
                    "run_summary_json": self.context.run_summary_json,
                    "run_output_dir": self.context.run_output_dir,
                    "latest_output_dir": self.context.latest_output_dir,
                    "telemetry_mode": self.context.telemetry_mode,
                }
            )
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1
        self._write_manifest_files(best_effort=True)
        self._write_summary_files(best_effort=True)

    def get_manifest(self) -> dict[str, Any]:
        with self._lock:
            manifest = dict(self._manifest)
        manifest["metadata_json"] = _parse_json_field(manifest.get("metadata_json"), {})
        return manifest

    def update_manifest(self, **patch: Any) -> None:
        now = utc_now_iso()
        with self._lock:
            merged = dict(self._manifest)
            for key, value in patch.items():
                if value is not None:
                    merged[key] = value
            merged["updated_at"] = now
            if not isinstance(merged.get("metadata_json"), (dict, list)):
                merged["metadata_json"] = _parse_json_field(merged.get("metadata_json"), {})
            self._manifest = merged
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1
        self._write_manifest_files(best_effort=True)
        self._write_summary_files(best_effort=True)

    def mark_completed(self) -> None:
        self.update_manifest(
            status="completed",
            completed_at=utc_now_iso(),
            fatal_stage="",
            fatal_error_type="",
            fatal_error_message="",
        )

    def mark_failed(self, *, stage: str, exc: BaseException | None = None) -> None:
        error = normalize_exception(exc)
        self.update_manifest(
            status="failed",
            completed_at=utc_now_iso(),
            fatal_stage=stage,
            fatal_error_type=error["error_type"],
            fatal_error_message=error["error_message"],
        )

    def _build_manifest_row(self) -> dict[str, Any]:
        manifest = self.get_manifest()
        return {
            "run_id": manifest.get("run_id", self.context.run_id),
            "status": manifest.get("status", "running"),
            "started_at": manifest.get("started_at", self.context.started_at),
            "updated_at": manifest.get("updated_at", utc_now_iso()),
            "completed_at": manifest.get("completed_at", ""),
            "fatal_stage": manifest.get("fatal_stage", ""),
            "fatal_error_type": manifest.get("fatal_error_type", ""),
            "fatal_error_message": manifest.get("fatal_error_message", ""),
            "metadata_json": json.dumps(manifest.get("metadata_json") or {}, ensure_ascii=True, sort_keys=True),
            "checkpoint_dir": "",
            "checkpoints_csv": manifest.get("checkpoints_csv", self.context.checkpoints_csv),
            "url_result_events_csv": manifest.get("url_result_events_csv", self.context.checkpoints_csv),
            "stage_events_csv": manifest.get("stage_events_csv", self.context.stage_events_csv),
        }

    def _build_summary_payload(self) -> dict[str, Any]:
        manifest = self.get_manifest()
        with self._lock:
            rows = list(self._url_results.values())
            stage_event_count = len(self._stage_events)
            heartbeat_count = len(self._worker_heartbeats)
            stage_metric_count = len(self._stage_metrics)
            stall_event_count = len(self._stall_events)
        final_decision_counts: dict[str, int] = {}
        pipeline_status_counts: dict[str, int] = {}
        for row in rows:
            final_decision = str(row.get("final_decision", "") or "").strip()
            final_status = str(row.get("final_pipeline_status", "") or "").strip()
            if final_decision:
                final_decision_counts[final_decision] = final_decision_counts.get(final_decision, 0) + 1
            if final_status:
                pipeline_status_counts[final_status] = pipeline_status_counts.get(final_status, 0) + 1
        return {
            "run_id": self.context.run_id,
            "status": manifest.get("status", "running"),
            "started_at": manifest.get("started_at", self.context.started_at),
            "updated_at": manifest.get("updated_at", utc_now_iso()),
            "completed_at": manifest.get("completed_at", ""),
            "fatal_stage": manifest.get("fatal_stage", ""),
            "fatal_error_type": manifest.get("fatal_error_type", ""),
            "fatal_error_message": manifest.get("fatal_error_message", ""),
            "run_output_dir": self.context.run_output_dir,
            "latest_output_dir": self.context.latest_output_dir,
            "telemetry_mode": self.context.telemetry_mode,
            "totals": {
                "tracked_records": len(rows),
                "terminal_records": sum(
                    1
                    for row in rows
                    if str(row.get("final_pipeline_status", "") or "") in TERMINAL_PIPELINE_STATUSES
                ),
                "stage_events": stage_event_count,
                "worker_heartbeats": heartbeat_count,
                "stage_metrics": stage_metric_count,
                "stall_events": stall_event_count,
            },
            "final_decision_counts": final_decision_counts,
            "pipeline_status_counts": pipeline_status_counts,
            "metadata_json": manifest.get("metadata_json") or {},
        }

    def _write_manifest_files(self, *, best_effort: bool = False) -> None:
        manifest = self.get_manifest()
        manifest_row = self._build_manifest_row()
        try:
            write_run_artifact_csv(self.context, "run_manifest_csv", RUN_MANIFEST_COLUMNS, [manifest_row], best_effort=best_effort)
            write_run_artifact_json(self.context, "run_manifest_json", manifest, best_effort=best_effort)
        except Exception as exc:
            if best_effort and _is_retryable_filesystem_error(exc):
                self._log_deferred_export_warning("manifest", exc)
                return
            raise

    def _write_summary_files(self, *, best_effort: bool = False) -> None:
        summary_payload = self._build_summary_payload()
        try:
            write_run_artifact_json(self.context, "run_summary_json", summary_payload, best_effort=best_effort)
        except Exception as exc:
            if best_effort and _is_retryable_filesystem_error(exc):
                self._log_deferred_export_warning("summary", exc)
                return
            raise

    def get_url_result(self, record_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._url_results.get(str(record_key or ""))
            return dict(row) if row is not None else None

    def upsert_url_result(self, patch: dict[str, Any]) -> dict[str, Any]:
        record_key = str(patch.get("record_key", "") or "")
        if not record_key:
            raise ValueError("record_key is required for url result upsert")
        with self._lock:
            existing = self._url_results.get(record_key)
            if existing is None:
                existing = default_run_result(
                    run_id=self.context.run_id,
                    raw_url=str(patch.get("raw_url", "") or ""),
                    normalized_url=str(patch.get("normalized_url", "") or ""),
                    source_workbook=str(patch.get("source_workbook", "") or ""),
                )
            merged = dict(existing)
            merged.update({key: value for key, value in patch.items() if value is not None})
            merged.setdefault("run_id", self.context.run_id)
            merged.setdefault("record_key", record_key)
            merged["last_updated_at"] = utc_now_iso()
            merged = _coerce_int_fields(merged, RUN_RESULT_INT_FIELDS)
            self._url_results[record_key] = merged
            self._pending_result_events.append(dict(merged))
            self._pending_event_count += 1
            self._append_dirty = True
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1
        return dict(merged)

    def ensure_url_result(
        self,
        *,
        raw_url: str,
        normalized_url: str,
        source_workbook: str,
    ) -> dict[str, Any]:
        record_key = make_record_key(normalized_url, source_workbook)
        with self._lock:
            existing = self._url_results.get(record_key)
            if existing is not None:
                return dict(existing)
            created = default_run_result(
                run_id=self.context.run_id,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
            )
            self._url_results[record_key] = created
            return dict(created)

    def append_stage_event(self, event: dict[str, Any]) -> None:
        normalized = _coerce_int_fields(dict(event), STAGE_EVENT_INT_FIELDS)
        with self._lock:
            self._stage_events.append(dict(normalized))
            self._dirty_snapshot_updates += 1
            self._snapshot_dirty = True

    def update_worker_heartbeat(
        self,
        *,
        stage_name: str,
        worker_id: str,
        record_key: str,
        state: str,
        task_kind: str = "",
        item_age_s: float | int = 0.0,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._worker_heartbeats[(stage_name, worker_id)] = {
                "stage_name": stage_name,
                "worker_id": worker_id,
                "record_key": record_key,
                "state": state,
                "task_kind": str(task_kind or ""),
                "item_age_s": f"{float(item_age_s or 0.0):.3f}",
                "emitted_at": utc_now_iso(),
                "last_seen_at": utc_now_iso(),
                "details_json": dict(details or {}),
            }
            self._heartbeat_dirty = True
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1

    def clear_worker_heartbeat(self, *, stage_name: str, worker_id: str) -> None:
        with self._lock:
            self._worker_heartbeats.pop((stage_name, worker_id), None)
            self._heartbeat_dirty = True
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1

    def append_stage_metric(self, snapshot: dict[str, Any]) -> None:
        item = {
            "run_id": self.context.run_id,
            "emitted_at": str(snapshot.get("emitted_at", "") or utc_now_iso()),
            "label": str(snapshot.get("label", "") or ""),
            "stage_name": str(snapshot.get("stage_name", "") or ""),
            "worker_id": str(snapshot.get("worker_id", "") or ""),
            "metric_kind": str(snapshot.get("metric_kind", "snapshot") or "snapshot"),
            "counters_json": json.dumps(snapshot.get("counters_json") or snapshot.get("counters") or {}, ensure_ascii=True, sort_keys=True),
            "gauges_json": json.dumps(snapshot.get("gauges_json") or snapshot.get("gauges") or {}, ensure_ascii=True, sort_keys=True),
            "latency_json": json.dumps(snapshot.get("latency_json") or snapshot.get("latency_ms") or {}, ensure_ascii=True, sort_keys=True),
            "resource_snapshot_json": json.dumps(snapshot.get("resource_snapshot_json") or snapshot.get("resource_snapshot") or {}, ensure_ascii=True, sort_keys=True),
            "details_json": json.dumps(snapshot.get("details_json") or snapshot.get("details") or {}, ensure_ascii=True, sort_keys=True),
        }
        with self._lock:
            self._stage_metrics.append(item)
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1

    def append_stall_event(self, event: dict[str, Any]) -> None:
        item = {
            "run_id": self.context.run_id,
            "emitted_at": str(event.get("emitted_at", "") or utc_now_iso()),
            "label": str(event.get("label", "") or ""),
            "stage_name": str(event.get("stage_name", "") or ""),
            "severity": str(event.get("severity", "warning") or "warning"),
            "message": str(event.get("message", "") or ""),
            "resource_snapshot_json": json.dumps(event.get("resource_snapshot_json") or event.get("resource_snapshot") or {}, ensure_ascii=True, sort_keys=True),
            "details_json": json.dumps(event.get("details_json") or event.get("details") or {}, ensure_ascii=True, sort_keys=True),
        }
        with self._lock:
            self._stall_events.append(item)
            self._snapshot_dirty = True
            self._dirty_snapshot_updates += 1

    def snapshot_backlog(self) -> dict[str, Any]:
        with self._lock:
            pending_result_events = len(self._pending_result_events)
            stage_event_rows = len(self._stage_events)
            worker_heartbeats = len(self._worker_heartbeats)
            stage_metric_rows = len(self._stage_metrics)
            stall_event_rows = len(self._stall_events)
            snapshot_dirty_updates = int(self._dirty_snapshot_updates)
            return {
                "append_dirty": bool(self._append_dirty),
                "snapshot_dirty": bool(self._snapshot_dirty),
                "heartbeat_dirty": bool(self._heartbeat_dirty),
                "pending_result_events": pending_result_events,
                "stage_event_rows": stage_event_rows,
                "worker_heartbeats": worker_heartbeats,
                "stage_metric_rows": stage_metric_rows,
                "stall_event_rows": stall_event_rows,
                "snapshot_dirty_updates": snapshot_dirty_updates,
                "pending_rows_total": pending_result_events + snapshot_dirty_updates,
            }

    def list_worker_heartbeats(self, *, stage_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = []
            for (heartbeat_stage, _), value in sorted(self._worker_heartbeats.items()):
                if stage_name and heartbeat_stage != stage_name:
                    continue
                item = dict(value)
                item["details_json"] = dict(item.get("details_json") or {})
                items.append(item)
        return items

    def get_completed_record_keys(self) -> set[str]:
        with self._lock:
            return {
                record_key
                for record_key, row in self._url_results.items()
                if str(row.get("final_pipeline_status", "") or "") in TERMINAL_PIPELINE_STATUSES
            }

    def get_terminal_submission_records(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        with self._lock:
            rows = list(self._url_results.values())
        for row in rows:
            payload = str(row.get("submission_record_json", "") or "").strip()
            if not payload:
                continue
            try:
                output.append(json.loads(payload))
            except Exception:
                continue
        output.sort(key=lambda item: (str(item.get("Identified Phishing/Suspected Domain Name", "")), str(item.get("Corresponding CSE Domain Name", ""))))
        return output

    def flush_appends(self, *, force: bool = False, best_effort: bool = False) -> None:
        with self._lock:
            now = time.monotonic()
            if not force:
                due_by_rows = self._pending_event_count >= self.context.append_flush_row_interval
                due_by_time = (now - self._last_append_flush_monotonic) >= self.context.append_flush_interval_seconds
                if not self._append_dirty:
                    return
                if not due_by_rows and not due_by_time:
                    return

            result_rows = list(self._pending_result_events)
            if not result_rows:
                self._append_dirty = False
                self._pending_event_count = 0
                self._last_append_flush_monotonic = now
                return
            try:
                _append_csv_rows(self.context.checkpoints_csv, RUN_RESULT_COLUMNS, result_rows)
                sync_run_artifact(self.context, "checkpoints_csv", src_path=self.context.checkpoints_csv, best_effort=best_effort)
            except Exception as exc:
                if best_effort and _is_retryable_filesystem_error(exc):
                    self._append_dirty = True
                    self._pending_event_count = len(self._pending_result_events)
                    self._log_deferred_export_warning("append_checkpoints", exc)
                    return
                raise
            del self._pending_result_events[: len(result_rows)]
            self._pending_event_count = len(self._pending_result_events)
            self._append_dirty = bool(self._pending_result_events)
            self._last_append_flush_monotonic = now

    def maybe_export(self, *, force: bool = False) -> None:
        self.flush_appends(force=force, best_effort=True)
        now = time.monotonic()
        if not force:
            with self._lock:
                due_by_rows = self._snapshot_dirty and self._dirty_snapshot_updates >= self.context.snapshot_flush_row_interval
                due_by_time = self._snapshot_dirty and (
                    (now - self._last_snapshot_flush_monotonic) >= self.context.snapshot_flush_interval_seconds
                )
                if not due_by_rows and not due_by_time:
                    return
        self.export_all(best_effort=True)

    def export_all(self, *, best_effort: bool = False) -> None:
        self.flush_appends(force=True, best_effort=best_effort)
        with self._lock:
            result_rows = [
                dict(row)
                for _, row in sorted(
                    self._url_results.items(),
                    key=lambda item: (
                        str(item[1].get("normalized_url", "")),
                        str(item[1].get("source_workbook", "")),
                        item[0],
                    ),
                )
            ]
            stage_rows = list(self._stage_events)
            worker_heartbeat_rows = []
            for _, row in sorted(self._worker_heartbeats.items()):
                item = dict(row)
                item["details_json"] = json.dumps(item.get("details_json") or {}, ensure_ascii=True, sort_keys=True)
                worker_heartbeat_rows.append(item)
            stage_metric_rows = list(self._stage_metrics)
            stall_event_rows = list(self._stall_events)
        try:
            write_run_artifact_csv(self.context, "run_results_csv", RUN_RESULT_COLUMNS, result_rows, best_effort=best_effort)
            write_run_artifact_csv(self.context, "stage_events_csv", STAGE_EVENT_COLUMNS, stage_rows, best_effort=best_effort)
            write_run_artifact_csv(self.context, "worker_heartbeats_csv", WORKER_HEARTBEAT_COLUMNS, worker_heartbeat_rows, best_effort=best_effort)
            write_run_artifact_csv(self.context, "stage_metrics_csv", STAGE_METRIC_COLUMNS, stage_metric_rows, best_effort=best_effort)
            write_run_artifact_csv(self.context, "stall_events_csv", STALL_EVENT_COLUMNS, stall_event_rows, best_effort=best_effort)
            self._write_manifest_files(best_effort=best_effort)
            self._write_summary_files(best_effort=best_effort)
        except Exception as exc:
            if best_effort and _is_retryable_filesystem_error(exc):
                with self._lock:
                    self._snapshot_dirty = True
                self._log_deferred_export_warning("snapshot", exc)
                return
            raise
        with self._lock:
            self._snapshot_dirty = False
            self._dirty_snapshot_updates = 0
            self._heartbeat_dirty = False
            self._last_snapshot_flush_monotonic = time.monotonic()

    def close(self) -> None:
        self.export_all(best_effort=True)


def stage_result_patch(
    *,
    run_id: str,
    raw_url: str,
    normalized_url: str,
    source_workbook: str,
    stage_name: str,
    stage_status: str,
    current_stage: str | None = None,
    retry_count: int = 0,
    timeout_hit: bool = False,
    fallback_taken: str = "",
    worker_id: str = "",
    error_type: str = "",
    error_message: str = "",
    final_pipeline_status: str | None = None,
    final_decision: str | None = None,
    failure_reason: str | None = None,
    submission_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = default_run_result(
        run_id=run_id,
        raw_url=raw_url,
        normalized_url=normalized_url,
        source_workbook=source_workbook,
    )
    record.update(
        {
            "current_stage": current_stage or stage_name,
            "stage_status": stage_status,
            "stage_error_type": error_type,
            "stage_error_message": error_message,
            "retry_count": int(retry_count),
            "timeout_hit": int(bool(timeout_hit)),
            "fallback_taken": fallback_taken,
            "worker_id": worker_id,
            "final_pipeline_status": final_pipeline_status if final_pipeline_status is not None else record["final_pipeline_status"],
            "final_decision": final_decision if final_decision is not None else record["final_decision"],
            "failure_reason": failure_reason if failure_reason is not None else record["failure_reason"],
            "submission_record_json": json.dumps(submission_record, ensure_ascii=True, sort_keys=True)
            if submission_record is not None
            else "",
        }
    )
    stage_field = STAGE_TO_STATUS_FIELD.get(stage_name)
    if stage_field:
        record[stage_field] = stage_status
    return record


async def async_with_timeout_and_retry(
    awaitable_factory: Callable[[], Awaitable[Any]],
    *,
    timeout: float | None,
    max_retries: int = 0,
    backoff_base_seconds: float = 0.25,
    backoff_cap_seconds: float = 2.0,
    retry_classifier: Callable[[BaseException], tuple[bool, bool]] = classify_transient_exception,
    before_retry: Callable[[int, BaseException], Awaitable[None] | None] | None = None,
) -> tuple[Any, int, bool]:
    last_exc: BaseException | None = None
    timeout_hit = False
    attempts = max(0, int(max_retries)) + 1
    for attempt_index in range(attempts):
        try:
            coro = awaitable_factory()
            if timeout is not None:
                result = await asyncio.wait_for(coro, timeout=float(timeout))
            else:
                result = await coro
            return result, attempt_index, timeout_hit
        except Exception as exc:
            last_exc = exc
            retryable, timed_out = retry_classifier(exc)
            timeout_hit = timeout_hit or bool(timed_out)
            if attempt_index >= attempts - 1 or not retryable:
                break
            delay = min(
                float(backoff_cap_seconds),
                float(backoff_base_seconds) * (2 ** attempt_index),
            ) + random.uniform(0.0, 0.1)
            if before_retry is not None:
                maybe_result = before_retry(attempt_index + 1, exc)
                if asyncio.iscoroutine(maybe_result):
                    await maybe_result
            await asyncio.sleep(delay)
    if last_exc is None:
        raise RuntimeError("async_with_timeout_and_retry failed without an exception")
    raise last_exc


class ProgressTracker:
    def __init__(self, *, total: int):
        self.total = max(0, int(total))
        self.completed = 0
        self.failed = 0
        self.skipped = 0
        self._last_progress_monotonic = time.monotonic()
        self._lock = threading.Lock()

    def mark_completed(self, *, final_status: str = "") -> None:
        with self._lock:
            self.completed += 1
            if str(final_status).startswith("failed") or final_status in {"classification_failed", "hash_failed", "stage1_failed"}:
                self.failed += 1
            if "skip" in str(final_status) or final_status in {"review_only", "filtered_lexical_miss"}:
                self.skipped += 1
            self._last_progress_monotonic = time.monotonic()

    def add_total(self, count: int = 1) -> None:
        with self._lock:
            self.total = max(0, self.total + max(0, int(count)))

    def seconds_since_progress(self) -> float:
        with self._lock:
            return max(0.0, time.monotonic() - self._last_progress_monotonic)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            processed = self.completed
            remaining = max(0, self.total - processed)
            return {
                "total": self.total,
                "processed": processed,
                "failed": self.failed,
                "skipped": self.skipped,
                "remaining": remaining,
                "last_progress_seconds": max(0.0, time.monotonic() - self._last_progress_monotonic),
            }


class StageWatchdog:
    def __init__(
        self,
        *,
        stage_name: str,
        progress_tracker: ProgressTracker,
        checkpoint_store: CheckpointStore | None = None,
        warn_after_seconds: int = 60,
        stall_after_seconds: int = 180,
        poll_interval_seconds: int = 15,
        queue_size_getter: Callable[[], int] | None = None,
        active_summary_getter: Callable[[], dict[str, Any]] | None = None,
        on_stall: Callable[[], Awaitable[None] | None] | None = None,
        logger_instance: logging.Logger | None = None,
    ):
        self.stage_name = stage_name
        self.progress_tracker = progress_tracker
        self.checkpoint_store = checkpoint_store
        self.warn_after_seconds = max(1, int(warn_after_seconds))
        self.stall_after_seconds = max(self.warn_after_seconds, int(stall_after_seconds))
        self.poll_interval_seconds = max(1, int(poll_interval_seconds))
        self.queue_size_getter = queue_size_getter
        self.active_summary_getter = active_summary_getter
        self.on_stall = on_stall
        self.logger = logger_instance or logger
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()
        self._warn_triggered = False
        self._stall_triggered = False

    async def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.poll_interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
            snapshot = self.progress_tracker.snapshot()
            seconds_stalled = float(snapshot.get("last_progress_seconds", 0.0) or 0.0)
            queue_depth = self.queue_size_getter() if self.queue_size_getter is not None else -1
            active = self.active_summary_getter() if self.active_summary_getter is not None else {}
            if seconds_stalled < self.warn_after_seconds:
                self._warn_triggered = False
                self._stall_triggered = False
                continue
            if not self._warn_triggered:
                self._warn_triggered = True
                self.logger.warning(
                    "Watchdog warning | stage=%s | stalled_for=%.1fs | processed=%s/%s | failed=%s | skipped=%s | queue_depth=%s | active=%s",
                    self.stage_name,
                    seconds_stalled,
                    snapshot.get("processed"),
                    snapshot.get("total"),
                    snapshot.get("failed"),
                    snapshot.get("skipped"),
                    queue_depth,
                    active,
                )
                if self.checkpoint_store is not None:
                    current_manifest = self.checkpoint_store.get_manifest()
                    metadata = dict(current_manifest.get("metadata_json") or {})
                    metadata["watchdog"] = {
                        "stage_name": self.stage_name,
                        "stalled_for_seconds": seconds_stalled,
                        "queue_depth": queue_depth,
                        "active": active,
                    }
                    self.checkpoint_store.update_manifest(metadata_json=metadata)
                    self.checkpoint_store.append_stall_event(
                        {
                            "label": "watchdog_warning",
                            "stage_name": self.stage_name,
                            "severity": "warning",
                            "message": f"{self.stage_name} made no progress for {seconds_stalled:.1f}s",
                            "details": {
                                "processed": snapshot.get("processed"),
                                "total": snapshot.get("total"),
                                "failed": snapshot.get("failed"),
                                "skipped": snapshot.get("skipped"),
                                "queue_depth": queue_depth,
                                "active": active,
                            },
                        }
                    )
            if seconds_stalled >= self.stall_after_seconds and not self._stall_triggered:
                self._stall_triggered = True
                self.logger.error(
                    "Watchdog stall detected | stage=%s | stalled_for=%.1fs | queue_depth=%s | active=%s",
                    self.stage_name,
                    seconds_stalled,
                    queue_depth,
                    active,
                )
                if self.checkpoint_store is not None:
                    self.checkpoint_store.append_stall_event(
                        {
                            "label": "watchdog_stall",
                            "stage_name": self.stage_name,
                            "severity": "error",
                            "message": f"{self.stage_name} stalled for {seconds_stalled:.1f}s",
                            "details": {
                                "processed": snapshot.get("processed"),
                                "total": snapshot.get("total"),
                                "failed": snapshot.get("failed"),
                                "skipped": snapshot.get("skipped"),
                                "queue_depth": queue_depth,
                                "active": active,
                            },
                        }
                    )
                if self.on_stall is not None:
                    maybe_result = self.on_stall()
                    if asyncio.iscoroutine(maybe_result):
                        await maybe_result

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task is not None:
            try:
                await self._task
            except Exception:
                pass
