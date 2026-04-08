from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import logging
import os
import random
import shutil
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

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
    "last_seen_at",
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
    checkpoints_csv: str
    checkpoint_dir: str
    run_results_csv: str
    stage_events_csv: str
    run_manifest_csv: str
    checkpoint_run_manifest_csv: str
    url_result_events_csv: str
    checkpoint_stage_events_csv: str
    worker_heartbeats_csv: str
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
    checkpoints_csv = os.path.join(output_dir, "checkpoints.csv")
    return RunContext(
        run_id=resolved_run_id,
        output_dir=output_dir,
        checkpoints_csv=checkpoints_csv,
        checkpoint_dir="",
        run_results_csv=os.path.join(output_dir, "pipeline_run_results.csv"),
        stage_events_csv=os.path.join(output_dir, "pipeline_stage_events.csv"),
        run_manifest_csv=os.path.join(output_dir, "run_manifest.csv"),
        checkpoint_run_manifest_csv=os.path.join(output_dir, "run_manifest.csv"),
        url_result_events_csv=checkpoints_csv,
        checkpoint_stage_events_csv=os.path.join(output_dir, "pipeline_stage_events.csv"),
        worker_heartbeats_csv="",
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


def _write_csv_atomic(path: str, fieldnames: tuple[str, ...] | list[str], rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    os.replace(temp_path, path)


def _append_csv_rows(path: str, fieldnames: tuple[str, ...] | list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    file_exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
        fh.flush()


def _copy_csv_atomic(src_path: str, dst_path: str, fieldnames: tuple[str, ...] | list[str]) -> None:
    if not os.path.exists(src_path):
        _write_csv_atomic(dst_path, fieldnames, [])
        return
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    temp_path = f"{dst_path}.tmp"
    with open(src_path, "r", newline="", encoding="utf-8") as src, open(temp_path, "w", newline="", encoding="utf-8") as dst:
        shutil.copyfileobj(src, dst)
    os.replace(temp_path, dst_path)


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
        self._load_existing_state()
        self.start_run(status="running", metadata=self.context.metadata)

    def _load_existing_state(self) -> None:
        with self._lock:
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
                }
            )
        self._write_manifest_files()

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
        self._write_manifest_files()

    def mark_completed(self) -> None:
        self.update_manifest(status="completed", completed_at=utc_now_iso())

    def mark_failed(self, *, stage: str, exc: BaseException | None = None) -> None:
        error = normalize_exception(exc)
        self.update_manifest(
            status="failed",
            completed_at=utc_now_iso(),
            fatal_stage=stage,
            fatal_error_type=error["error_type"],
            fatal_error_message=error["error_message"],
        )

    def _write_manifest_files(self) -> None:
        manifest = self.get_manifest()
        manifest_row = {
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
        _write_csv_atomic(self.context.run_manifest_csv, RUN_MANIFEST_COLUMNS, [manifest_row])

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
        self.maybe_export()
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
        self.maybe_export()

    def update_worker_heartbeat(
        self,
        *,
        stage_name: str,
        worker_id: str,
        record_key: str,
        state: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self._worker_heartbeats[(stage_name, worker_id)] = {
                "stage_name": stage_name,
                "worker_id": worker_id,
                "record_key": record_key,
                "state": state,
                "last_seen_at": utc_now_iso(),
                "details_json": dict(details or {}),
            }

    def clear_worker_heartbeat(self, *, stage_name: str, worker_id: str) -> None:
        with self._lock:
            self._worker_heartbeats.pop((stage_name, worker_id), None)

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

    def flush_appends(self, *, force: bool = False) -> None:
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
            self._pending_result_events.clear()
            self._pending_event_count = 0
            self._append_dirty = False
            self._last_append_flush_monotonic = now

        if result_rows:
            _append_csv_rows(self.context.checkpoints_csv, RUN_RESULT_COLUMNS, result_rows)

    def maybe_export(self, *, force: bool = False) -> None:
        self.flush_appends(force=force)
        now = time.monotonic()
        if not force:
            with self._lock:
                due_by_rows = self._snapshot_dirty and self._dirty_snapshot_updates >= self.context.snapshot_flush_row_interval
                due_by_time = self._snapshot_dirty and (
                    (now - self._last_snapshot_flush_monotonic) >= self.context.snapshot_flush_interval_seconds
                )
                if not due_by_rows and not due_by_time:
                    return
        self.export_all()

    def export_all(self) -> None:
        self.flush_appends(force=True)
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
            self._snapshot_dirty = False
            self._dirty_snapshot_updates = 0
            self._last_snapshot_flush_monotonic = time.monotonic()

        _write_csv_atomic(self.context.run_results_csv, RUN_RESULT_COLUMNS, result_rows)
        _write_csv_atomic(self.context.stage_events_csv, STAGE_EVENT_COLUMNS, stage_rows)
        self._write_manifest_files()

    def close(self) -> None:
        self.export_all()


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
            if seconds_stalled >= self.warn_after_seconds:
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
            if seconds_stalled >= self.stall_after_seconds and not self._stall_triggered:
                self._stall_triggered = True
                self.logger.error(
                    "Watchdog stall detected | stage=%s | stalled_for=%.1fs | queue_depth=%s | active=%s",
                    self.stage_name,
                    seconds_stalled,
                    queue_depth,
                    active,
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
