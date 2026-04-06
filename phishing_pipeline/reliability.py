from __future__ import annotations

import asyncio
import csv
import hashlib
import json
import logging
import os
import random
import sqlite3
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

TERMINAL_PIPELINE_STATUSES = {
    "completed",
    "terminal_invalid_input",
    "classification_failed",
    "filtered_lexical_miss",
    "stage1_failed",
    "stage1_failed_fallback_dns",
    "dns_rejected",
    "hash_failed",
    "not_registered_domain",
    "parked_or_placeholder",
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
    checkpoint_db_path: str
    run_results_csv: str
    stage_events_csv: str
    run_manifest_json: str
    stall_threshold_seconds: int = 180
    watchdog_warning_seconds: int = 60
    export_flush_interval_seconds: int = 5
    export_flush_row_interval: int = 50
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
    export_flush_interval_seconds: int = 5,
    export_flush_row_interval: int = 50,
    stage1_failure_policy: str = "route_to_dns",
    max_worker_restarts: int = 2,
    metadata: dict[str, Any] | None = None,
) -> RunContext:
    resolved_run_id = str(run_id or datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ"))
    checkpoint_dir = os.path.join(output_dir, "checkpoints", resolved_run_id)
    os.makedirs(checkpoint_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    return RunContext(
        run_id=resolved_run_id,
        output_dir=output_dir,
        checkpoint_db_path=os.path.join(checkpoint_dir, "pipeline_state.sqlite3"),
        run_results_csv=os.path.join(output_dir, "pipeline_run_results.csv"),
        stage_events_csv=os.path.join(output_dir, "pipeline_stage_events.csv"),
        run_manifest_json=os.path.join(output_dir, "run_manifest.json"),
        stall_threshold_seconds=max(30, int(stall_threshold_seconds)),
        watchdog_warning_seconds=max(15, int(watchdog_warning_seconds)),
        export_flush_interval_seconds=max(1, int(export_flush_interval_seconds)),
        export_flush_row_interval=max(1, int(export_flush_row_interval)),
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


class CheckpointStore:
    def __init__(self, context: RunContext):
        self.context = context
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.context.checkpoint_db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA temp_store=MEMORY")
        self._last_export_monotonic = time.monotonic()
        self._dirty_updates = 0
        self._initialize()
        self.start_run(status="running", metadata=self.context.metadata)

    def _initialize(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS run_manifest (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    fatal_stage TEXT,
                    fatal_error_type TEXT,
                    fatal_error_message TEXT,
                    metadata_json TEXT,
                    checkpoint_db_path TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS url_results (
                    record_key TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    source_workbook TEXT,
                    raw_url TEXT,
                    normalized_url TEXT,
                    current_stage TEXT,
                    stage_status TEXT,
                    stage_error_type TEXT,
                    stage_error_message TEXT,
                    retry_count INTEGER,
                    timeout_hit INTEGER,
                    skipped_due_to_previous_failure INTEGER,
                    fallback_taken TEXT,
                    worker_id TEXT,
                    stage_started_at TEXT,
                    stage_finished_at TEXT,
                    duration_ms INTEGER,
                    stage0_status TEXT,
                    stage1_status TEXT,
                    dns_stage_status TEXT,
                    hash_stage_status TEXT,
                    classify_stage_status TEXT,
                    final_pipeline_status TEXT,
                    final_decision TEXT,
                    failure_reason TEXT,
                    processing_time_ms INTEGER,
                    submission_record_json TEXT,
                    last_updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS stage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    record_key TEXT NOT NULL,
                    source_workbook TEXT,
                    normalized_url TEXT,
                    stage_name TEXT,
                    attempt_index INTEGER,
                    worker_id TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    duration_ms INTEGER,
                    status TEXT,
                    error_type TEXT,
                    error_message TEXT,
                    retry_count INTEGER,
                    timeout_flag INTEGER,
                    fallback_taken TEXT
                );
                CREATE TABLE IF NOT EXISTS worker_heartbeat (
                    stage_name TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    record_key TEXT,
                    state TEXT,
                    last_seen_at TEXT,
                    details_json TEXT,
                    PRIMARY KEY(stage_name, worker_id)
                );
                CREATE TABLE IF NOT EXISTS run_counters (
                    run_id TEXT NOT NULL,
                    counter_name TEXT NOT NULL,
                    counter_value INTEGER NOT NULL,
                    PRIMARY KEY(run_id, counter_name)
                );
                """
            )
            self._conn.commit()

    def start_run(self, *, status: str = "running", metadata: dict[str, Any] | None = None) -> None:
        now = utc_now_iso()
        payload = json.dumps(metadata or self.context.metadata or {}, ensure_ascii=True, sort_keys=True)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO run_manifest (
                    run_id, status, started_at, updated_at, completed_at,
                    fatal_stage, fatal_error_type, fatal_error_message,
                    metadata_json, checkpoint_db_path
                ) VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    metadata_json=excluded.metadata_json,
                    checkpoint_db_path=excluded.checkpoint_db_path
                """,
                (
                    self.context.run_id,
                    status,
                    self.context.started_at,
                    now,
                    payload,
                    self.context.checkpoint_db_path,
                ),
            )
            self._conn.commit()
        self._export_manifest()

    def get_manifest(self) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM run_manifest WHERE run_id = ?",
                (self.context.run_id,),
            ).fetchone()
        if row is None:
            return {
                "run_id": self.context.run_id,
                "status": "unknown",
                "started_at": self.context.started_at,
                "updated_at": self.context.started_at,
                "completed_at": None,
                "fatal_stage": None,
                "fatal_error_type": None,
                "fatal_error_message": None,
                "metadata_json": self.context.metadata,
                "checkpoint_db_path": self.context.checkpoint_db_path,
            }
        data = dict(row)
        metadata = data.get("metadata_json")
        if isinstance(metadata, str):
            try:
                data["metadata_json"] = json.loads(metadata)
            except Exception:
                pass
        return data

    def update_manifest(self, **patch: Any) -> None:
        now = utc_now_iso()
        current = self.get_manifest()
        merged = dict(current)
        merged.update({key: value for key, value in patch.items() if value is not None})
        merged.setdefault("run_id", self.context.run_id)
        merged.setdefault("started_at", self.context.started_at)
        merged["updated_at"] = now
        metadata_json = merged.get("metadata_json", self.context.metadata)
        if not isinstance(metadata_json, str):
            metadata_json = json.dumps(metadata_json or {}, ensure_ascii=True, sort_keys=True)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO run_manifest (
                    run_id, status, started_at, updated_at, completed_at,
                    fatal_stage, fatal_error_type, fatal_error_message,
                    metadata_json, checkpoint_db_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    completed_at=excluded.completed_at,
                    fatal_stage=excluded.fatal_stage,
                    fatal_error_type=excluded.fatal_error_type,
                    fatal_error_message=excluded.fatal_error_message,
                    metadata_json=excluded.metadata_json,
                    checkpoint_db_path=excluded.checkpoint_db_path
                """,
                (
                    merged.get("run_id", self.context.run_id),
                    merged.get("status", "running"),
                    merged.get("started_at", self.context.started_at),
                    merged.get("updated_at", now),
                    merged.get("completed_at"),
                    merged.get("fatal_stage"),
                    merged.get("fatal_error_type"),
                    merged.get("fatal_error_message"),
                    metadata_json,
                    merged.get("checkpoint_db_path", self.context.checkpoint_db_path),
                ),
            )
            self._conn.commit()
        self._export_manifest()

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

    def get_url_result(self, record_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM url_results WHERE record_key = ?",
                (record_key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def upsert_url_result(self, patch: dict[str, Any]) -> dict[str, Any]:
        record_key = str(patch.get("record_key", "") or "")
        if not record_key:
            raise ValueError("record_key is required for url result upsert")
        with self._lock:
            existing = self.get_url_result(record_key) or {}
            merged = dict(existing)
            merged.update({key: value for key, value in patch.items() if value is not None})
            merged.setdefault("run_id", self.context.run_id)
            merged.setdefault("record_key", record_key)
            merged.setdefault("source_workbook", "")
            merged.setdefault("raw_url", "")
            merged.setdefault("normalized_url", "")
            merged.setdefault("current_stage", "")
            merged.setdefault("stage_status", "")
            merged.setdefault("stage_error_type", "")
            merged.setdefault("stage_error_message", "")
            merged.setdefault("retry_count", 0)
            merged.setdefault("timeout_hit", 0)
            merged.setdefault("skipped_due_to_previous_failure", 0)
            merged.setdefault("fallback_taken", "")
            merged.setdefault("worker_id", "")
            merged.setdefault("stage_started_at", "")
            merged.setdefault("stage_finished_at", "")
            merged.setdefault("duration_ms", 0)
            merged.setdefault("stage0_status", "pending")
            merged.setdefault("stage1_status", "pending")
            merged.setdefault("dns_stage_status", "pending")
            merged.setdefault("hash_stage_status", "pending")
            merged.setdefault("classify_stage_status", "pending")
            merged.setdefault("final_pipeline_status", "pending")
            merged.setdefault("final_decision", "")
            merged.setdefault("failure_reason", "")
            merged.setdefault("processing_time_ms", 0)
            merged.setdefault("submission_record_json", "")
            merged["last_updated_at"] = utc_now_iso()
            placeholders = ", ".join("?" for _ in RUN_RESULT_COLUMNS)
            self._conn.execute(
                f"INSERT OR REPLACE INTO url_results ({', '.join(RUN_RESULT_COLUMNS)}) VALUES ({placeholders})",
                [merged.get(column) for column in RUN_RESULT_COLUMNS],
            )
            self._conn.commit()
            self._dirty_updates += 1
        self.maybe_export()
        return merged

    def ensure_url_result(
        self,
        *,
        raw_url: str,
        normalized_url: str,
        source_workbook: str,
    ) -> dict[str, Any]:
        return self.upsert_url_result(
            default_run_result(
                run_id=self.context.run_id,
                raw_url=raw_url,
                normalized_url=normalized_url,
                source_workbook=source_workbook,
            )
        )

    def append_stage_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT INTO stage_events ({', '.join(STAGE_EVENT_COLUMNS)}) VALUES ({', '.join('?' for _ in STAGE_EVENT_COLUMNS)})",
                [event.get(column) for column in STAGE_EVENT_COLUMNS],
            )
            self._conn.commit()
            self._dirty_updates += 1
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
            self._conn.execute(
                """
                INSERT INTO worker_heartbeat (stage_name, worker_id, record_key, state, last_seen_at, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(stage_name, worker_id) DO UPDATE SET
                    record_key=excluded.record_key,
                    state=excluded.state,
                    last_seen_at=excluded.last_seen_at,
                    details_json=excluded.details_json
                """,
                (
                    stage_name,
                    worker_id,
                    record_key,
                    state,
                    utc_now_iso(),
                    json.dumps(details or {}, ensure_ascii=True, sort_keys=True),
                ),
            )
            self._conn.commit()

    def clear_worker_heartbeat(self, *, stage_name: str, worker_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM worker_heartbeat WHERE stage_name = ? AND worker_id = ?",
                (stage_name, worker_id),
            )
            self._conn.commit()

    def list_worker_heartbeats(self, *, stage_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if stage_name:
                rows = self._conn.execute(
                    "SELECT * FROM worker_heartbeat WHERE stage_name = ? ORDER BY worker_id",
                    (stage_name,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM worker_heartbeat ORDER BY stage_name, worker_id"
                ).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            details = item.get("details_json")
            if isinstance(details, str):
                try:
                    item["details_json"] = json.loads(details)
                except Exception:
                    pass
            output.append(item)
        return output

    def get_completed_record_keys(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT record_key
                FROM url_results
                WHERE final_pipeline_status IN ({})
                """.format(", ".join("?" for _ in TERMINAL_PIPELINE_STATUSES)),
                tuple(sorted(TERMINAL_PIPELINE_STATUSES)),
            ).fetchall()
        return {str(row[0]) for row in rows}

    def get_terminal_submission_records(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT submission_record_json
                FROM url_results
                WHERE submission_record_json IS NOT NULL
                  AND submission_record_json != ''
                ORDER BY normalized_url, source_workbook
                """
            ).fetchall()
        output = []
        for row in rows:
            try:
                output.append(json.loads(str(row[0])))
            except Exception:
                continue
        return output

    def maybe_export(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force:
            if self._dirty_updates < self.context.export_flush_row_interval and (
                now - self._last_export_monotonic
            ) < self.context.export_flush_interval_seconds:
                return
        self.export_all()

    def export_all(self) -> None:
        with self._lock:
            result_rows = self._conn.execute(
                "SELECT * FROM url_results ORDER BY normalized_url, source_workbook, record_key"
            ).fetchall()
            event_rows = self._conn.execute(
                "SELECT * FROM stage_events ORDER BY id"
            ).fetchall()
        _write_csv_atomic(
            self.context.run_results_csv,
            RUN_RESULT_COLUMNS,
            [dict(row) for row in result_rows],
        )
        _write_csv_atomic(
            self.context.stage_events_csv,
            STAGE_EVENT_COLUMNS,
            [dict(row) for row in event_rows],
        )
        self._export_manifest()
        self._last_export_monotonic = time.monotonic()
        self._dirty_updates = 0

    def _export_manifest(self) -> None:
        manifest = self.get_manifest()
        with open(self.context.run_manifest_json, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=True, sort_keys=True)

    def close(self) -> None:
        self.export_all()
        with self._lock:
            self._conn.commit()
            self._conn.close()


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
            if "skip" in str(final_status) or final_status in {"review_only", "filtered_lexical_miss", "dns_rejected"}:
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
