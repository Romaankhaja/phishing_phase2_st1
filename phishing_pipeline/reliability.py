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

PIPELINE_MONITOR_COLUMNS = (
    "run_id",
    "emitted_at",
    "stage",
    "substage",
    "event_kind",
    "status",
    "worker_id",
    "record_key",
    "stage_elapsed_ms",
    "interval_ms",
    "items_total",
    "items_completed",
    "items_failed",
    "items_skipped",
    "items_pending",
    "queue_depth",
    "inflight",
    "rate_per_sec",
    "avg_latency_ms",
    "max_latency_ms",
    "cpu_percent",
    "process_cpu_percent",
    "rss_mb",
    "ram_percent",
    "used_cpu_cores",
    "available_cpu_cores",
    "bottleneck",
    "message",
    "details_json",
)

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

WORKER_HEARTBEAT_COLUMNS = (
    "run_id",
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
    "metric_kind",
    "counters_json",
    "gauges_json",
    "latency_ms_json",
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

RUN_MANIFEST_COLUMNS = (
    "run_id",
    "status",
    "started_at",
    "updated_at",
    "completed_at",
    "run_output_dir",
    "latest_output_dir",
    "telemetry_mode",
    "monitor_csv_path",
    "effective_args_json",
    "effective_runtime_json",
    "checkpoints_csv",
    "pipeline_run_results_csv",
    "pipeline_stage_events_csv",
    "worker_heartbeats_csv",
    "stage_metrics_csv",
    "stall_events_csv",
    "run_manifest_json",
    "run_manifest_csv",
    "run_summary_json",
    "submission_zip",
    "submission_dir",
    "fatal_stage",
    "fatal_error_type",
    "fatal_error_message",
    "mixed_run_bundle_detected",
    "consistency_guard_json",
    "metadata_json",
)

_RUN_CONTEXT_ARTIFACT_ATTR_ALIASES = {
    "checkpoints_csv": "checkpoints_csv",
    "run_results_csv": "pipeline_run_results_csv",
    "stage_events_csv": "pipeline_stage_events_csv",
    "run_manifest_json": "run_manifest_json",
    "run_manifest_csv": "run_manifest_csv",
    "run_summary_json": "run_summary_json",
    "worker_heartbeats_csv": "worker_heartbeats_csv",
    "stage_metrics_csv": "stage_metrics_csv",
    "stall_events_csv": "stall_events_csv",
    "submission_zip": "submission_zip",
    "submission_dir": "submission_dir",
}

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
    monitor_log_path: str
    monitor_csv_path: str
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

    def __getattr__(self, name: str) -> Any:
        artifact_key = _RUN_CONTEXT_ARTIFACT_ATTR_ALIASES.get(name, name)
        if artifact_key in (self.artifact_paths or {}):
            return self.artifact_paths[artifact_key]
        raise AttributeError(name)


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
    submission_basename: str | None = None,
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
        submission_basename=submission_basename,
    )
    run_output_dir = artifact_paths["run_root"]
    latest_output_dir = artifact_paths["latest_root"]
    return RunContext(
        run_id=resolved_run_id,
        output_dir=output_dir,
        run_output_dir=run_output_dir,
        latest_output_dir=latest_output_dir,
        monitor_log_path=artifact_paths.get("pipeline_monitor_log", ""),
        monitor_csv_path=artifact_paths.get("pipeline_monitor_csv", ""),
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
    submission_basename: str | None = None,
) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
    run_root = os.path.join(output_dir, "runs", run_id)
    latest_root = os.path.join(output_dir, "latest")
    resolved_submission_basename = str(submission_basename or "Submission.zip").strip() or "Submission.zip"
    relpaths = {
        "run_root": "",
        "latest_root": "",
        "pipeline_monitor_log": _artifact_relpath("monitor", "pipeline_monitor.log"),
        "pipeline_monitor_csv": _artifact_relpath("monitor", "pipeline_monitor.csv"),
        "effective_args_json": _artifact_relpath("config", "effective_args.json"),
        "effective_runtime_json": _artifact_relpath("config", "effective_runtime.json"),
        "input_manifest_csv": _artifact_relpath("config", "input_manifest.csv"),
        "run_manifest_json": "run_manifest.json",
        "run_manifest_csv": "run_manifest.csv",
        "run_summary_json": "run_summary.json",
        "checkpoints_csv": _artifact_relpath("events", "checkpoints.csv"),
        "pipeline_run_results_csv": _artifact_relpath("events", "pipeline_run_results.csv"),
        "pipeline_stage_events_csv": _artifact_relpath("events", "pipeline_stage_events.csv"),
        "worker_heartbeats_csv": _artifact_relpath("events", "worker_heartbeats.csv"),
        "stage_metrics_csv": _artifact_relpath("events", "stage_metrics.csv"),
        "stall_events_csv": _artifact_relpath("events", "stall_events.csv"),
        "stage0_lexical_decisions_csv": _artifact_relpath("stage0", "stage0_lexical_decisions.csv"),
        "hashing_log": _artifact_relpath("hash", "hashing_shortlist.log"),
        "ray_render_trace_csv": _artifact_relpath("hash", "ray_shortlist_render_trace.csv"),
        "hash_export_dir": _artifact_relpath("hash", "hash_folder"),
        "holdout_csv": _artifact_relpath("final", "holdout.csv"),
        "hash_review_queue_csv": _artifact_relpath("classify", "hash_review_queue.csv"),
        "stage2_model_debug_csv": _artifact_relpath("classify", "stage2_model_debug.csv"),
        "stage3_classification_debug_csv": _artifact_relpath("classify", "stage3_classification_debug.csv"),
        "final_output_csv": _artifact_relpath("final", "output_file.csv"),
        "final_output_filtered_csv": _artifact_relpath("final", "output_file_filtered.csv"),
        "submission_zip": _artifact_relpath("submission", resolved_submission_basename),
        "submission_dir": _artifact_relpath("submission", "PS-02_ISS_NLP_Submission"),
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
        "run_manifest_json": [os.path.join(output_dir, "run_manifest.json")],
        "run_manifest_csv": [os.path.join(output_dir, "run_manifest.csv")],
        "run_summary_json": [os.path.join(output_dir, "run_summary.json")],
        "checkpoints_csv": [os.path.join(output_dir, "checkpoints.csv")],
        "pipeline_run_results_csv": [os.path.join(output_dir, "pipeline_run_results.csv")],
        "pipeline_stage_events_csv": [os.path.join(output_dir, "pipeline_stage_events.csv")],
        "worker_heartbeats_csv": [os.path.join(output_dir, "worker_heartbeats.csv")],
        "stage_metrics_csv": [os.path.join(output_dir, "stage_metrics.csv")],
        "stall_events_csv": [os.path.join(output_dir, "stall_events.csv")],
        "holdout_csv": [os.path.join(output_dir, "holdout.csv")],
        "stage0_lexical_decisions_csv": [
            os.path.join(output_dir, "stage0_lexical_decisions.csv"),
            os.path.join(output_dir, "stage1_lexical_debug.csv"),
        ],
        "hashing_log": [os.path.join(output_dir, "hashing_shortlist.log")],
        "hash_review_queue_csv": [os.path.join(output_dir, "hash_review_queue.csv")],
        "stage2_model_debug_csv": [os.path.join(output_dir, "stage2_model_debug.csv")],
        "stage3_classification_debug_csv": [os.path.join(output_dir, "stage3_classification_debug.csv")],
        "final_output_csv": [os.path.join(output_dir, "output_file.csv")],
        "final_output_filtered_csv": [os.path.join(output_dir, "output_file_filtered.csv")],
        "submission_zip": [os.path.join(output_dir, resolved_submission_basename)],
        "submission_dir": [os.path.join(output_dir, "PS-02_ISS_NLP_Submission")],
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


# UNUSED_IN_CURRENT_WORKFLOW: definition-only private copy helper; current reliability writers
# use _write_csv_atomic(), sync_run_artifact(), and append/export paths instead.
# def _copy_csv_atomic(src_path: str, dst_path: str, fieldnames: tuple[str, ...] | list[str]) -> None:
#     if not os.path.exists(src_path):
#         _write_csv_atomic(dst_path, fieldnames, [])
#         return
#     directory = os.path.dirname(dst_path) or "."
#     os.makedirs(directory, exist_ok=True)
#     last_exc: BaseException | None = None
#     for attempt_index in range(_CSV_WRITE_RETRY_ATTEMPTS):
#         temp_path = f"{dst_path}.{os.getpid()}.{threading.get_ident()}.{attempt_index}.tmp"
#         try:
#             with open(src_path, "r", newline="", encoding="utf-8") as src, open(temp_path, "w", newline="", encoding="utf-8") as dst:
#                 shutil.copyfileobj(src, dst)
#             _replace_file_atomic(temp_path, dst_path)
#             return
#         except Exception as exc:
#             last_exc = exc
#             try:
#                 if os.path.exists(temp_path):
#                     os.remove(temp_path)
#             except Exception:
#                 pass
#             if attempt_index >= (_CSV_WRITE_RETRY_ATTEMPTS - 1) or not _is_retryable_filesystem_error(exc):
#                 raise
#             time.sleep(_retryable_write_delay(attempt_index))
#     if last_exc is not None:
#         raise last_exc


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


def archive_run_artifact_file(
    run_context: RunContext | None,
    key: str,
    src_path: str,
    *,
    best_effort: bool = False,
) -> str:
    target_path = get_run_artifact_path(run_context, key)
    if not target_path:
        raise ValueError(f"Unknown run artifact key: {key}")
    if not os.path.exists(src_path):
        raise FileNotFoundError(src_path)
    try:
        _copy_file_atomic(src_path, target_path)
        sync_run_artifact(run_context, key, src_path=target_path, best_effort=best_effort)
    except Exception:
        if best_effort and _is_retryable_filesystem_error(_safe_current_exception()):
            return target_path
        raise
    return target_path


def archive_run_artifact_tree(
    run_context: RunContext | None,
    key: str,
    src_path: str,
    *,
    best_effort: bool = False,
) -> str:
    target_path = get_run_artifact_path(run_context, key)
    if not target_path:
        raise ValueError(f"Unknown run artifact key: {key}")
    if not os.path.isdir(src_path):
        raise FileNotFoundError(src_path)
    alias_paths = get_run_artifact_alias_paths(run_context, key)
    try:
        _copy_tree(src_path, target_path)
        for alias_path in alias_paths:
            if os.path.normcase(os.path.abspath(alias_path)) == os.path.normcase(os.path.abspath(target_path)):
                continue
            _copy_tree(target_path, alias_path)
    except Exception:
        if best_effort and _is_retryable_filesystem_error(_safe_current_exception()):
            return target_path
        raise
    return target_path


def archive_submission_artifacts(
    run_context: RunContext | None,
    *,
    zip_path: str,
    submission_dir: str | None = None,
    best_effort: bool = False,
) -> dict[str, str]:
    archived = {
        "submission_zip": archive_run_artifact_file(
            run_context,
            "submission_zip",
            zip_path,
            best_effort=best_effort,
        )
    }
    if submission_dir and os.path.isdir(submission_dir):
        archived["submission_dir"] = archive_run_artifact_tree(
            run_context,
            "submission_dir",
            submission_dir,
            best_effort=best_effort,
        )
    return archived


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


def _stable_json_dumps(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _normalize_run_result_row(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    normalized = default_run_result(
        run_id=run_id,
        raw_url=str(row.get("raw_url", "") or ""),
        normalized_url=str(row.get("normalized_url", "") or ""),
        source_workbook=str(row.get("source_workbook", "") or ""),
    )
    normalized.update(dict(row or {}))
    normalized["run_id"] = run_id
    normalized["record_key"] = str(
        normalized.get("record_key", "")
        or make_record_key(str(normalized.get("normalized_url", "") or ""), str(normalized.get("source_workbook", "") or ""))
    )
    normalized["source_workbook"] = str(normalized.get("source_workbook", "") or "")
    normalized["raw_url"] = str(normalized.get("raw_url", "") or "")
    normalized["normalized_url"] = str(normalized.get("normalized_url", "") or "")
    normalized["submission_record_json"] = str(normalized.get("submission_record_json", "") or "")
    normalized["last_updated_at"] = str(normalized.get("last_updated_at", "") or utc_now_iso())
    return _coerce_int_fields(normalized, RUN_RESULT_INT_FIELDS)


def _normalize_stage_event_row(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    normalized = {
        "run_id": run_id,
        "record_key": str(row.get("record_key", "") or ""),
        "source_workbook": str(row.get("source_workbook", "") or ""),
        "normalized_url": str(row.get("normalized_url", "") or ""),
        "stage_name": str(row.get("stage_name", "") or ""),
        "attempt_index": row.get("attempt_index", 0),
        "worker_id": str(row.get("worker_id", "") or ""),
        "started_at": str(row.get("started_at", "") or ""),
        "finished_at": str(row.get("finished_at", "") or ""),
        "duration_ms": row.get("duration_ms", 0),
        "status": str(row.get("status", "") or ""),
        "error_type": str(row.get("error_type", "") or ""),
        "error_message": str(row.get("error_message", "") or ""),
        "retry_count": row.get("retry_count", 0),
        "timeout_flag": row.get("timeout_flag", 0),
        "fallback_taken": str(row.get("fallback_taken", "") or ""),
    }
    return _coerce_int_fields(normalized, STAGE_EVENT_INT_FIELDS)


def _normalize_worker_heartbeat_row(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    details_json = _parse_json_field(row.get("details_json", row.get("details", {})), {})
    return {
        "run_id": run_id,
        "stage_name": str(row.get("stage_name", "") or ""),
        "worker_id": str(row.get("worker_id", "") or ""),
        "record_key": str(row.get("record_key", "") or ""),
        "state": str(row.get("state", "") or ""),
        "task_kind": str(row.get("task_kind", "") or ""),
        "item_age_s": f"{float(row.get('item_age_s', 0.0) or 0.0):.3f}",
        "emitted_at": str(row.get("emitted_at", "") or utc_now_iso()),
        "last_seen_at": str(row.get("last_seen_at", "") or row.get("emitted_at", "") or utc_now_iso()),
        "details_json": _stable_json_dumps(details_json),
    }


def _normalize_stage_metric_row(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "emitted_at": str(row.get("emitted_at", "") or utc_now_iso()),
        "label": str(row.get("label", "") or ""),
        "stage_name": str(row.get("stage_name", "") or ""),
        "metric_kind": str(row.get("metric_kind", "snapshot") or "snapshot"),
        "counters_json": _stable_json_dumps(_parse_json_field(row.get("counters_json", row.get("counters", {})), {})),
        "gauges_json": _stable_json_dumps(_parse_json_field(row.get("gauges_json", row.get("gauges", {})), {})),
        "latency_ms_json": _stable_json_dumps(_parse_json_field(row.get("latency_ms_json", row.get("latency_ms", {})), {})),
        "resource_snapshot_json": _stable_json_dumps(
            _parse_json_field(row.get("resource_snapshot_json", row.get("resource_snapshot", {})), {})
        ),
        "details_json": _stable_json_dumps(_parse_json_field(row.get("details_json", row.get("details", {})), {})),
    }


def _normalize_stall_event_row(row: dict[str, Any], *, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "emitted_at": str(row.get("emitted_at", "") or utc_now_iso()),
        "label": str(row.get("label", "") or ""),
        "stage_name": str(row.get("stage_name", "") or ""),
        "severity": str(row.get("severity", "") or ""),
        "message": str(row.get("message", "") or ""),
        "resource_snapshot_json": _stable_json_dumps(
            _parse_json_field(row.get("resource_snapshot_json", row.get("resource_snapshot", {})), {})
        ),
        "details_json": _stable_json_dumps(_parse_json_field(row.get("details_json", row.get("details", {})), {})),
    }


def _copy_tree(path_src: str, path_dst: str) -> None:
    if not os.path.isdir(path_src):
        return
    directory = os.path.dirname(path_dst) or "."
    os.makedirs(directory, exist_ok=True)
    temp_dst = f"{path_dst}.{os.getpid()}.{threading.get_ident()}.tmp"
    if os.path.isdir(temp_dst):
        shutil.rmtree(temp_dst, ignore_errors=True)
    shutil.copytree(path_src, temp_dst)
    if os.path.isdir(path_dst):
        shutil.rmtree(path_dst, ignore_errors=True)
    os.replace(temp_dst, path_dst)


class CheckpointStore:
    def __init__(self, context: RunContext):
        self.context = context
        self._lock = threading.RLock()
        self._url_results: dict[str, dict[str, Any]] = {}
        self._worker_heartbeats: dict[tuple[str, str], dict[str, Any]] = {}
        self._stage_events: list[dict[str, Any]] = []
        self._stage_event_keys: set[tuple[Any, ...]] = set()
        self._stage_metrics: list[dict[str, Any]] = []
        self._stage_metric_keys: set[tuple[Any, ...]] = set()
        self._stall_events: list[dict[str, Any]] = []
        self._stall_event_keys: set[tuple[Any, ...]] = set()
        self._monitor_rows: list[dict[str, Any]] = []
        self._append_dirty = False
        self._snapshot_dirty = False
        self._manifest: dict[str, Any] = {
            "run_id": self.context.run_id,
            "status": "running",
            "started_at": self.context.started_at,
            "updated_at": self.context.started_at,
            "completed_at": "",
            "run_output_dir": self.context.run_output_dir,
            "latest_output_dir": self.context.latest_output_dir,
            "metadata_json": dict(self.context.metadata),
            "telemetry_mode": self.context.telemetry_mode,
            "fatal_stage": "",
            "fatal_error_type": "",
            "fatal_error_message": "",
        }
        self.start_run(status="running", metadata=self.context.metadata)

    @staticmethod
    def _stage_event_key(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            str(row.get("record_key", "") or ""),
            str(row.get("stage_name", "") or ""),
            str(row.get("worker_id", "") or ""),
            str(row.get("started_at", "") or ""),
            str(row.get("status", "") or ""),
            int(row.get("attempt_index", 0) or 0),
        )

    @staticmethod
    def _stage_metric_key(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            str(row.get("emitted_at", "") or ""),
            str(row.get("label", "") or ""),
            str(row.get("stage_name", "") or ""),
            str(row.get("metric_kind", "") or ""),
        )

    @staticmethod
    def _stall_event_key(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            str(row.get("emitted_at", "") or ""),
            str(row.get("label", "") or ""),
            str(row.get("stage_name", "") or ""),
            str(row.get("severity", "") or ""),
            str(row.get("message", "") or ""),
        )

    @staticmethod
    def _is_meaningful_run_result_value(field: str, value: Any) -> bool:
        if field in RUN_RESULT_INT_FIELDS:
            try:
                return int(value or 0) != 0
            except Exception:
                return False
        if field in {"timeout_hit", "skipped_due_to_previous_failure"}:
            try:
                return int(value or 0) != 0
            except Exception:
                return False
        if field in set(STAGE_TO_STATUS_FIELD.values()) | {"stage_status", "final_pipeline_status"}:
            return str(value or "").strip().lower() not in {"", "pending"}
        if field == "submission_record_json":
            return bool(str(value or "").strip())
        if field in {"current_stage", "stage_error_type", "stage_error_message", "failure_reason", "fallback_taken", "worker_id", "final_decision"}:
            return bool(str(value or "").strip())
        if field in {"raw_url", "normalized_url", "source_workbook", "stage_started_at", "stage_finished_at", "last_updated_at"}:
            return bool(str(value or "").strip())
        return value not in ("", None)

    @classmethod
    def _merge_run_result_rows(cls, base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for field, value in overlay.items():
            if field == "run_id":
                merged[field] = str(value or merged.get(field, "") or "")
                continue
            if field in RUN_RESULT_INT_FIELDS:
                try:
                    overlay_value = int(value or 0)
                except Exception:
                    overlay_value = 0
                try:
                    base_value = int(merged.get(field, 0) or 0)
                except Exception:
                    base_value = 0
                merged[field] = overlay_value if overlay_value != 0 else base_value
                continue
            if field in {"timeout_hit", "skipped_due_to_previous_failure"}:
                try:
                    overlay_value = int(value or 0)
                except Exception:
                    overlay_value = 0
                try:
                    base_value = int(merged.get(field, 0) or 0)
                except Exception:
                    base_value = 0
                merged[field] = 1 if (overlay_value or base_value) else 0
                continue
            if cls._is_meaningful_run_result_value(field, value):
                merged[field] = value
        merged["last_updated_at"] = str(overlay.get("last_updated_at", "") or merged.get("last_updated_at", "") or utc_now_iso())
        return _normalize_run_result_row(merged, run_id=str(merged.get("run_id", "") or ""))

    def _log_deferred_export_warning(self, operation: str, exc: BaseException) -> None:
        logger.warning(
            "Deferred export due to transient file lock | run_id=%s | operation=%s | error=%s",
            self.context.run_id,
            operation,
            exc,
        )

    def _append_monitor_event(self, row: dict[str, Any]) -> None:
        event = {
            "run_id": self.context.run_id,
            "emitted_at": str(row.get("emitted_at") or utc_now_iso()),
            "stage": str(row.get("stage", "")),
            "substage": str(row.get("substage", "")),
            "event_kind": str(row.get("event_kind", "")),
            "status": str(row.get("status", "")),
            "worker_id": str(row.get("worker_id", "")),
            "record_key": str(row.get("record_key", "")),
            "stage_elapsed_ms": row.get("stage_elapsed_ms", ""),
            "interval_ms": row.get("interval_ms", ""),
            "items_total": row.get("items_total", ""),
            "items_completed": row.get("items_completed", ""),
            "items_failed": row.get("items_failed", ""),
            "items_skipped": row.get("items_skipped", ""),
            "items_pending": row.get("items_pending", ""),
            "queue_depth": row.get("queue_depth", ""),
            "inflight": row.get("inflight", ""),
            "rate_per_sec": row.get("rate_per_sec", ""),
            "avg_latency_ms": row.get("avg_latency_ms", ""),
            "max_latency_ms": row.get("max_latency_ms", ""),
            "cpu_percent": row.get("cpu_percent", ""),
            "process_cpu_percent": row.get("process_cpu_percent", ""),
            "rss_mb": row.get("rss_mb", ""),
            "ram_percent": row.get("ram_percent", ""),
            "used_cpu_cores": row.get("used_cpu_cores", ""),
            "available_cpu_cores": row.get("available_cpu_cores", ""),
            "bottleneck": str(row.get("bottleneck", "")),
            "message": str(row.get("message", "")),
            "details_json": _parse_json_field(row.get("details_json"), {})
        }
        if isinstance(event["details_json"], dict):
            event["details_json"] = json.dumps(event["details_json"], ensure_ascii=True, sort_keys=True)
        self._monitor_rows.append(event)
        self._append_dirty = True

    def _export_csv_artifact(
        self,
        key: str,
        fieldnames: tuple[str, ...] | list[str],
        rows: list[dict[str, Any]],
        *,
        best_effort: bool,
    ) -> None:
        target_path = get_run_artifact_path(self.context, key)
        _write_csv_atomic(target_path, fieldnames, rows)
        sync_run_artifact(self.context, key, src_path=target_path, best_effort=best_effort)

    def _export_json_artifact(self, key: str, payload: Any, *, best_effort: bool) -> None:
        target_path = get_run_artifact_path(self.context, key)
        _write_json_atomic(target_path, payload)
        sync_run_artifact(self.context, key, src_path=target_path, best_effort=best_effort)

    def start_run(self, *, status: str = "running", metadata: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._manifest.update(
                {
                    "status": status,
                    "updated_at": utc_now_iso(),
                    "metadata_json": dict(metadata or self.context.metadata or {}),
                    "telemetry_mode": self.context.telemetry_mode,
                    "run_output_dir": self.context.run_output_dir,
                    "latest_output_dir": self.context.latest_output_dir,
                }
            )
            self._snapshot_dirty = True
            self._append_monitor_event({
                "stage": "run",
                "event_kind": "run_start",
                "status": status,
            })

    def get_manifest(self) -> dict[str, Any]:
        with self._lock:
            manifest = dict(self._manifest)
        return manifest

    def update_manifest(self, **patch: Any) -> None:
        with self._lock:
            for key, value in patch.items():
                if value is not None:
                    self._manifest[key] = value
            self._manifest["updated_at"] = utc_now_iso()
            self._snapshot_dirty = True

    def mark_completed(self) -> None:
        self.update_manifest(
            status="completed",
            completed_at=utc_now_iso(),
            fatal_stage="",
            fatal_error_type="",
            fatal_error_message="",
        )
        with self._lock:
            self._append_monitor_event({
                "stage": "run",
                "event_kind": "run_end",
                "status": "completed",
            })

    def mark_failed(self, *, stage: str, exc: BaseException | None = None) -> None:
        error = normalize_exception(exc)
        self.update_manifest(
            status="failed", completed_at=utc_now_iso(), fatal_stage=stage,
            fatal_error_type=error["error_type"], fatal_error_message=error["error_message"]
        )
        with self._lock:
            self._append_monitor_event({
                "stage": "run",
                "event_kind": "run_end",
                "status": "failed",
                "message": error["error_message"],
            })

    def get_url_result(self, record_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._url_results.get(str(record_key or ""))
            return dict(row) if row is not None else None

    def upsert_url_result(self, patch: dict[str, Any]) -> dict[str, Any]:
        normalized_patch = _normalize_run_result_row(dict(patch or {}), run_id=self.context.run_id)
        record_key = str(normalized_patch.get("record_key", "") or "")
        with self._lock:
            existing = self._url_results.get(record_key)
            if existing is None:
                existing = default_run_result(
                    run_id=self.context.run_id,
                    raw_url=str(normalized_patch.get("raw_url", "") or ""),
                    normalized_url=str(normalized_patch.get("normalized_url", "") or ""),
                    source_workbook=str(normalized_patch.get("source_workbook", "") or ""),
                )
            merged = self._merge_run_result_rows(existing, normalized_patch)
            self._url_results[record_key] = merged
            self._snapshot_dirty = True
        return dict(merged)

    def ensure_url_result(self, *, raw_url: str, normalized_url: str, source_workbook: str) -> dict[str, Any]:
        record_key = make_record_key(normalized_url, source_workbook)
        with self._lock:
            existing = self._url_results.get(record_key)
            if existing is not None:
                return dict(existing)
            created = default_run_result(run_id=self.context.run_id, raw_url=raw_url, normalized_url=normalized_url, source_workbook=source_workbook)
            self._url_results[record_key] = created
            self._snapshot_dirty = True
            return dict(created)

    def append_stage_event(self, event: dict[str, Any]) -> None:
        normalized = _normalize_stage_event_row(dict(event or {}), run_id=self.context.run_id)
        event_key = self._stage_event_key(normalized)
        with self._lock:
            if event_key not in self._stage_event_keys:
                self._stage_event_keys.add(event_key)
                self._stage_events.append(normalized)
                self._snapshot_dirty = True
            self._append_monitor_event({
                "stage": normalized.get("stage_name", ""),
                "event_kind": "stage_end" if normalized.get("status") in ("completed", "failed", "timeout") else "progress",
                "status": normalized.get("status", ""),
                "worker_id": normalized.get("worker_id", ""),
                "record_key": normalized.get("record_key", ""),
                "stage_elapsed_ms": normalized.get("duration_ms", ""),
                "message": normalized.get("error_message", ""),
            })

    def update_worker_heartbeat(self, *, stage_name: str, worker_id: str, record_key: str, state: str, task_kind: str = "", item_age_s: float | int = 0.0, details: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._worker_heartbeats[(stage_name, worker_id)] = _normalize_worker_heartbeat_row(
                {
                    "stage_name": stage_name,
                    "worker_id": worker_id,
                    "record_key": record_key,
                    "state": state,
                    "task_kind": task_kind,
                    "item_age_s": item_age_s,
                    "emitted_at": utc_now_iso(),
                    "last_seen_at": utc_now_iso(),
                    "details_json": dict(details or {}),
                },
                run_id=self.context.run_id,
            )
            self._snapshot_dirty = True

    def clear_worker_heartbeat(self, *, stage_name: str, worker_id: str) -> None:
        with self._lock:
            removed = self._worker_heartbeats.pop((stage_name, worker_id), None)
            if removed is not None:
                self._snapshot_dirty = True

    def append_stage_metric(self, snapshot: dict[str, Any]) -> None:
        normalized = _normalize_stage_metric_row(dict(snapshot or {}), run_id=self.context.run_id)
        metric_key = self._stage_metric_key(normalized)
        res = _parse_json_field(normalized.get("resource_snapshot_json", "{}"), {})
        with self._lock:
            if metric_key not in self._stage_metric_keys:
                self._stage_metric_keys.add(metric_key)
                self._stage_metrics.append(normalized)
                self._snapshot_dirty = True
            self._append_monitor_event({
                "stage": normalized.get("stage_name", ""),
                "substage": normalized.get("label", ""),
                "event_kind": "progress",
                "details_json": _parse_json_field(normalized.get("details_json", "{}"), {}),
                "cpu_percent": res.get("cpu_percent", ""),
                "process_cpu_percent": res.get("process_cpu_percent", ""),
                "rss_mb": res.get("rss_mb", ""),
            })

    def append_stall_event(self, event: dict[str, Any]) -> None:
        normalized = _normalize_stall_event_row(dict(event or {}), run_id=self.context.run_id)
        stall_key = self._stall_event_key(normalized)
        with self._lock:
            if stall_key not in self._stall_event_keys:
                self._stall_event_keys.add(stall_key)
                self._stall_events.append(normalized)
                self._snapshot_dirty = True
            self._append_monitor_event({
                "stage": normalized.get("stage_name", ""),
                "substage": normalized.get("label", ""),
                "event_kind": "stall" if normalized.get("severity") == "error" else "warning",
                "status": normalized.get("severity", ""),
                "message": normalized.get("message", ""),
                "details_json": _parse_json_field(normalized.get("details_json", "{}"), {}),
            })

    def snapshot_backlog(self) -> dict[str, Any]:
        with self._lock:
            return {
                "pending_rows_total": (
                    len(self._monitor_rows)
                    + len(self._url_results)
                    + len(self._stage_events)
                    + len(self._worker_heartbeats)
                    + len(self._stage_metrics)
                    + len(self._stall_events)
                ),
                "append_dirty": bool(self._append_dirty or self._monitor_rows),
                "snapshot_dirty": bool(self._snapshot_dirty),
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
                rk for rk, row in self._url_results.items()
                if str(row.get("final_pipeline_status", "") or "") in TERMINAL_PIPELINE_STATUSES
            }

    def get_terminal_submission_records(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        with self._lock:
            for row in self._url_results.values():
                payload = str(row.get("submission_record_json", "") or "").strip()
                if payload:
                    try:
                        output.append(json.loads(payload))
                    except:
                        pass
        output.sort(key=lambda x: (str(x.get("Identified Phishing/Suspected Domain Name", "")), str(x.get("Corresponding CSE Domain Name", ""))))
        return output

    def merge_exported_state(self) -> None:
        def _load_rows(path: str) -> list[dict[str, Any]]:
            if not path or not os.path.exists(path):
                return []
            try:
                with open(path, newline="", encoding="utf-8") as fh:
                    return [dict(row) for row in csv.DictReader(fh)]
            except Exception:
                logger.exception("Failed to load run artifact CSV for merge | run_id=%s | path=%s", self.context.run_id, path)
                return []

        run_results_path = get_run_artifact_path(self.context, "pipeline_run_results_csv")
        if not os.path.exists(run_results_path):
            run_results_path = get_run_artifact_path(self.context, "checkpoints_csv")
        for row in _load_rows(run_results_path):
            if str(row.get("run_id", "") or self.context.run_id) not in {"", self.context.run_id}:
                continue
            normalized = _normalize_run_result_row(row, run_id=self.context.run_id)
            record_key = str(normalized.get("record_key", "") or "")
            with self._lock:
                existing = self._url_results.get(record_key)
                self._url_results[record_key] = (
                    normalized
                    if existing is None
                    else self._merge_run_result_rows(normalized, existing)
                )
                self._snapshot_dirty = True

        for row in _load_rows(get_run_artifact_path(self.context, "pipeline_stage_events_csv")):
            if str(row.get("run_id", "") or self.context.run_id) not in {"", self.context.run_id}:
                continue
            normalized = _normalize_stage_event_row(row, run_id=self.context.run_id)
            event_key = self._stage_event_key(normalized)
            with self._lock:
                if event_key not in self._stage_event_keys:
                    self._stage_event_keys.add(event_key)
                    self._stage_events.append(normalized)
                    self._snapshot_dirty = True

        for row in _load_rows(get_run_artifact_path(self.context, "worker_heartbeats_csv")):
            if str(row.get("run_id", "") or self.context.run_id) not in {"", self.context.run_id}:
                continue
            normalized = _normalize_worker_heartbeat_row(row, run_id=self.context.run_id)
            with self._lock:
                self._worker_heartbeats[(normalized["stage_name"], normalized["worker_id"])] = normalized
                self._snapshot_dirty = True

        for row in _load_rows(get_run_artifact_path(self.context, "stage_metrics_csv")):
            if str(row.get("run_id", "") or self.context.run_id) not in {"", self.context.run_id}:
                continue
            normalized = _normalize_stage_metric_row(row, run_id=self.context.run_id)
            metric_key = self._stage_metric_key(normalized)
            with self._lock:
                if metric_key not in self._stage_metric_keys:
                    self._stage_metric_keys.add(metric_key)
                    self._stage_metrics.append(normalized)
                    self._snapshot_dirty = True

        for row in _load_rows(get_run_artifact_path(self.context, "stall_events_csv")):
            if str(row.get("run_id", "") or self.context.run_id) not in {"", self.context.run_id}:
                continue
            normalized = _normalize_stall_event_row(row, run_id=self.context.run_id)
            stall_key = self._stall_event_key(normalized)
            with self._lock:
                if stall_key not in self._stall_event_keys:
                    self._stall_event_keys.add(stall_key)
                    self._stall_events.append(normalized)
                    self._snapshot_dirty = True

        manifest_path = get_run_artifact_path(self.context, "run_manifest_json")
        if manifest_path and os.path.exists(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8") as fh:
                    manifest_payload = json.load(fh)
            except Exception:
                manifest_payload = {}
            if (
                isinstance(manifest_payload, dict)
                and str(manifest_payload.get("run_id", "") or self.context.run_id) == self.context.run_id
            ):
                imported_metadata = manifest_payload.get("metadata_json")
                if not isinstance(imported_metadata, dict):
                    imported_metadata = _parse_json_field(imported_metadata, {})
                with self._lock:
                    self._manifest.update(
                        {
                            "started_at": str(manifest_payload.get("started_at", "") or self._manifest.get("started_at", "")),
                            "completed_at": str(manifest_payload.get("completed_at", "") or self._manifest.get("completed_at", "")),
                            "status": str(manifest_payload.get("status", "") or self._manifest.get("status", "")),
                            "fatal_stage": str(manifest_payload.get("fatal_stage", "") or self._manifest.get("fatal_stage", "")),
                            "fatal_error_type": str(manifest_payload.get("fatal_error_type", "") or self._manifest.get("fatal_error_type", "")),
                            "fatal_error_message": str(manifest_payload.get("fatal_error_message", "") or self._manifest.get("fatal_error_message", "")),
                            "metadata_json": dict(imported_metadata or self._manifest.get("metadata_json", {}) or {}),
                        }
                    )
                    self._snapshot_dirty = True

    def _build_consistency_guard(self, manifest_payload: dict[str, Any] | None = None) -> dict[str, Any]:
        effective_args_run_id = ""
        effective_args_path = get_run_artifact_path(self.context, "effective_args_json")
        if effective_args_path and os.path.exists(effective_args_path):
            try:
                with open(effective_args_path, encoding="utf-8") as fh:
                    effective_args_payload = json.load(fh)
            except Exception:
                effective_args_payload = {}
            if isinstance(effective_args_payload, dict):
                effective_args_run_id = str(
                    effective_args_payload.get("run_id", "")
                    or dict(effective_args_payload.get("args") or {}).get("run_id", "")
                    or ""
                ).strip()
        manifest_payload = dict(manifest_payload or self._manifest)
        manifest_run_id = str(manifest_payload.get("run_id", "") or self.context.run_id).strip()
        summary_run_id = self.context.run_id
        non_empty_ids = [item for item in (effective_args_run_id, manifest_run_id, summary_run_id) if item]
        return {
            "effective_args_run_id": effective_args_run_id,
            "manifest_run_id": manifest_run_id,
            "summary_run_id": summary_run_id,
            "mixed_run_bundle_detected": bool(non_empty_ids and len(set(non_empty_ids)) > 1),
        }

    def _build_manifest_payload(self) -> dict[str, Any]:
        with self._lock:
            manifest_payload = dict(self._manifest)
        manifest_payload.update(
            {
                "run_id": self.context.run_id,
                "run_output_dir": self.context.run_output_dir,
                "latest_output_dir": self.context.latest_output_dir,
                "telemetry_mode": self.context.telemetry_mode,
                "monitor_csv_path": self.context.monitor_csv_path,
                "effective_args_json": self.context.effective_args_json,
                "effective_runtime_json": self.context.effective_runtime_json,
                "checkpoints_csv": self.context.checkpoints_csv,
                "pipeline_run_results_csv": self.context.run_results_csv,
                "pipeline_stage_events_csv": self.context.stage_events_csv,
                "worker_heartbeats_csv": self.context.worker_heartbeats_csv,
                "stage_metrics_csv": self.context.stage_metrics_csv,
                "stall_events_csv": self.context.stall_events_csv,
                "run_manifest_json": self.context.run_manifest_json,
                "run_manifest_csv": self.context.run_manifest_csv,
                "run_summary_json": self.context.run_summary_json,
                "submission_zip": self.context.submission_zip,
                "submission_dir": self.context.submission_dir,
            }
        )
        consistency_guard = self._build_consistency_guard(manifest_payload)
        manifest_payload["mixed_run_bundle_detected"] = bool(consistency_guard["mixed_run_bundle_detected"])
        manifest_payload["consistency_guard"] = consistency_guard
        metadata_json = manifest_payload.get("metadata_json", {})
        if not isinstance(metadata_json, dict):
            metadata_json = _parse_json_field(metadata_json, {})
        manifest_payload["metadata_json"] = dict(metadata_json)
        return manifest_payload

    def _build_summary_payload(self) -> dict[str, Any]:
        with self._lock:
            run_result_rows = [dict(row) for row in self._url_results.values()]
            stage_event_rows = [dict(row) for row in self._stage_events]
            stage_metric_rows = [dict(row) for row in self._stage_metrics]
            stall_event_rows = [dict(row) for row in self._stall_events]
            heartbeat_rows = [dict(row) for row in self._worker_heartbeats.values()]
        manifest_payload = self._build_manifest_payload()
        pipeline_status_counts: dict[str, int] = {}
        emitted_decision_counts: dict[str, int] = {}
        terminal_records = 0
        emitted_submission_records = 0
        for row in run_result_rows:
            final_status = str(row.get("final_pipeline_status", "") or "").strip()
            if final_status:
                pipeline_status_counts[final_status] = pipeline_status_counts.get(final_status, 0) + 1
                if final_status in TERMINAL_PIPELINE_STATUSES:
                    terminal_records += 1
            payload = str(row.get("submission_record_json", "") or "").strip()
            if not payload:
                continue
            try:
                parsed_payload = dict(json.loads(payload) or {})
            except Exception:
                continue
            emitted_submission_records += 1
            decision = str(
                row.get("final_decision", "")
                or parsed_payload.get("Phishing/Suspected Domains (i.e. Class Label)", "")
                or ""
            ).strip()
            if decision:
                emitted_decision_counts[decision] = emitted_decision_counts.get(decision, 0) + 1

        return {
            "run_id": self.context.run_id,
            "status": str(manifest_payload.get("status", "") or ""),
            "started_at": str(manifest_payload.get("started_at", "") or ""),
            "updated_at": str(manifest_payload.get("updated_at", "") or ""),
            "completed_at": str(manifest_payload.get("completed_at", "") or ""),
            "fatal_stage": str(manifest_payload.get("fatal_stage", "") or ""),
            "fatal_error_type": str(manifest_payload.get("fatal_error_type", "") or ""),
            "fatal_error_message": str(manifest_payload.get("fatal_error_message", "") or ""),
            "telemetry_mode": self.context.telemetry_mode,
            "totals": {
                "tracked_records": len(run_result_rows),
                "terminal_records": terminal_records,
                "submission_records_emitted": emitted_submission_records,
                "stage_events": len(stage_event_rows),
                "stage_metrics": len(stage_metric_rows),
                "stall_events": len(stall_event_rows),
                "worker_heartbeats": len(heartbeat_rows),
            },
            "pipeline_status_counts": pipeline_status_counts,
            "final_decision_counts": emitted_decision_counts,
            "artifact_paths": {
                "run_output_dir": self.context.run_output_dir,
                "latest_output_dir": self.context.latest_output_dir,
                "checkpoints_csv": self.context.checkpoints_csv,
                "pipeline_run_results_csv": self.context.run_results_csv,
                "pipeline_stage_events_csv": self.context.stage_events_csv,
                "worker_heartbeats_csv": self.context.worker_heartbeats_csv,
                "stage_metrics_csv": self.context.stage_metrics_csv,
                "stall_events_csv": self.context.stall_events_csv,
                "run_manifest_json": self.context.run_manifest_json,
                "run_summary_json": self.context.run_summary_json,
                "submission_zip": self.context.submission_zip,
                "submission_dir": self.context.submission_dir,
            },
            "mixed_run_bundle_detected": bool(manifest_payload.get("mixed_run_bundle_detected", False)),
            "consistency_guard": dict(manifest_payload.get("consistency_guard") or {}),
        }

    def flush_appends(self, *, force: bool = False, best_effort: bool = False) -> None:
        with self._lock:
            rows = list(self._monitor_rows)
            self._monitor_rows.clear()
        if not rows:
            return
        try:
            _append_csv_rows(self.context.monitor_csv_path, PIPELINE_MONITOR_COLUMNS, rows)
            sync_run_artifact(self.context, "pipeline_monitor_csv", src_path=self.context.monitor_csv_path, best_effort=best_effort)
            with self._lock:
                self._append_dirty = bool(self._monitor_rows)
        except Exception as exc:
            if best_effort and _is_retryable_filesystem_error(exc):
                with self._lock:
                    self._monitor_rows = rows + self._monitor_rows
                    self._append_dirty = True
                self._log_deferred_export_warning("append_monitor", exc)
            else:
                raise

    def maybe_export(self, *, force: bool = False) -> None:
        if force or self._append_dirty or self._snapshot_dirty:
            self.export_all(best_effort=True)

    def export_all(self, *, best_effort: bool = False) -> None:
        self.flush_appends(force=True, best_effort=best_effort)
        with self._lock:
            run_result_rows = sorted(
                (_normalize_run_result_row(row, run_id=self.context.run_id) for row in self._url_results.values()),
                key=lambda row: (str(row.get("source_workbook", "") or ""), str(row.get("normalized_url", "") or ""), str(row.get("record_key", "") or "")),
            )
            stage_event_rows = sorted(
                (dict(row) for row in self._stage_events),
                key=lambda row: (str(row.get("stage_name", "") or ""), str(row.get("started_at", "") or ""), str(row.get("record_key", "") or "")),
            )
            worker_heartbeat_rows = sorted(
                (dict(row) for row in self._worker_heartbeats.values()),
                key=lambda row: (str(row.get("stage_name", "") or ""), str(row.get("worker_id", "") or "")),
            )
            stage_metric_rows = sorted(
                (dict(row) for row in self._stage_metrics),
                key=lambda row: (str(row.get("emitted_at", "") or ""), str(row.get("stage_name", "") or ""), str(row.get("label", "") or "")),
            )
            stall_event_rows = sorted(
                (dict(row) for row in self._stall_events),
                key=lambda row: (str(row.get("emitted_at", "") or ""), str(row.get("stage_name", "") or ""), str(row.get("label", "") or "")),
            )
        manifest_payload = self._build_manifest_payload()
        summary_payload = self._build_summary_payload()
        manifest_csv_row = dict(manifest_payload)
        manifest_csv_row["metadata_json"] = _stable_json_dumps(manifest_csv_row.get("metadata_json", {}))
        manifest_csv_row["consistency_guard_json"] = _stable_json_dumps(manifest_csv_row.pop("consistency_guard", {}))

        failures: list[tuple[str, BaseException]] = []
        export_specs: list[tuple[str, Callable[[], None]]] = [
            ("checkpoints_csv", lambda: self._export_csv_artifact("checkpoints_csv", RUN_RESULT_COLUMNS, run_result_rows, best_effort=best_effort)),
            ("pipeline_run_results_csv", lambda: self._export_csv_artifact("pipeline_run_results_csv", RUN_RESULT_COLUMNS, run_result_rows, best_effort=best_effort)),
            ("pipeline_stage_events_csv", lambda: self._export_csv_artifact("pipeline_stage_events_csv", STAGE_EVENT_COLUMNS, stage_event_rows, best_effort=best_effort)),
            ("worker_heartbeats_csv", lambda: self._export_csv_artifact("worker_heartbeats_csv", WORKER_HEARTBEAT_COLUMNS, worker_heartbeat_rows, best_effort=best_effort)),
            ("stage_metrics_csv", lambda: self._export_csv_artifact("stage_metrics_csv", STAGE_METRIC_COLUMNS, stage_metric_rows, best_effort=best_effort)),
            ("stall_events_csv", lambda: self._export_csv_artifact("stall_events_csv", STALL_EVENT_COLUMNS, stall_event_rows, best_effort=best_effort)),
            ("run_manifest_csv", lambda: self._export_csv_artifact("run_manifest_csv", RUN_MANIFEST_COLUMNS, [manifest_csv_row], best_effort=best_effort)),
            ("run_manifest_json", lambda: self._export_json_artifact("run_manifest_json", manifest_payload, best_effort=best_effort)),
            ("run_summary_json", lambda: self._export_json_artifact("run_summary_json", summary_payload, best_effort=best_effort)),
        ]
        for operation, exporter in export_specs:
            try:
                exporter()
            except Exception as exc:
                if best_effort and _is_retryable_filesystem_error(exc):
                    failures.append((operation, exc))
                    self._log_deferred_export_warning(operation, exc)
                    continue
                raise
        with self._lock:
            self._snapshot_dirty = bool(failures)

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
