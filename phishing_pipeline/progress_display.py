from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator

from tqdm import tqdm

PROGRESS_MODE_AUTO = "auto"
PROGRESS_MODE_OFF = "off"
PROGRESS_MODE_COMPACT = "compact"
_PROGRESS_MODES = {PROGRESS_MODE_AUTO, PROGRESS_MODE_OFF, PROGRESS_MODE_COMPACT}
_BAR_FORMAT = "{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"


def resolve_progress_mode(
    requested_mode: str | None = None,
    *,
    execution_backend: str = "ray",
    is_tty: bool | None = None,
) -> str:
    raw_mode = str(requested_mode or os.getenv("PHISHING_PROGRESS_MODE", PROGRESS_MODE_AUTO)).strip().lower()
    mode = raw_mode if raw_mode in _PROGRESS_MODES else PROGRESS_MODE_AUTO
    if mode == PROGRESS_MODE_OFF:
        return PROGRESS_MODE_OFF
    if mode == PROGRESS_MODE_COMPACT:
        return PROGRESS_MODE_COMPACT
    interactive = sys.stderr.isatty() if is_tty is None else bool(is_tty)
    if str(execution_backend or "").strip().lower() != "ray":
        return PROGRESS_MODE_OFF
    return PROGRESS_MODE_COMPACT if interactive else PROGRESS_MODE_OFF


def progress_bars_enabled(progress_mode: str | None) -> bool:
    return str(progress_mode or "").strip().lower() == PROGRESS_MODE_COMPACT


def format_duration_compact(seconds: float) -> str:
    total_seconds = max(0, int(round(float(seconds or 0.0))))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def build_timing_postfix(
    *,
    completed: int,
    total: int,
    started_monotonic: float,
    rate_key: str,
) -> dict[str, str]:
    elapsed_s = max(0.0, time.perf_counter() - float(started_monotonic or time.perf_counter()))
    rate = float(completed) / elapsed_s if elapsed_s > 0 else 0.0
    remaining = max(0, int(total) - int(completed))
    eta_s = (remaining / rate) if rate > 0 else 0.0
    return {
        "elapsed": format_duration_compact(elapsed_s),
        "eta": format_duration_compact(eta_s),
        rate_key: f"{rate:.1f}",
        "done/total": f"{int(completed)}/{int(total)}",
    }


def build_compact_postfix(fields: dict[str, Any]) -> dict[str, str]:
    rendered: dict[str, str] = {}
    for key, value in fields.items():
        if value is None:
            continue
        rendered[str(key)] = str(value)
    return rendered


class TqdmCompatibleLoggingHandler(logging.Handler):
    def __init__(self, *, stream: Any | None = None) -> None:
        super().__init__()
        self.stream = stream if stream is not None else sys.stderr

    def emit(self, record: logging.LogRecord) -> None:
        try:
            tqdm.write(self.format(record), file=self.stream)
        except Exception:
            self.handleError(record)


@contextmanager
def tqdm_logging_redirect(enabled: bool) -> Iterator[None]:
    if not enabled:
        yield
        return
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    redirected_handlers: list[logging.Handler] = []
    for handler in original_handlers:
        if isinstance(handler, logging.StreamHandler):
            tqdm_handler = TqdmCompatibleLoggingHandler(stream=getattr(handler, "stream", sys.stderr))
            tqdm_handler.setLevel(handler.level)
            if handler.formatter is not None:
                tqdm_handler.setFormatter(handler.formatter)
            for log_filter in handler.filters:
                tqdm_handler.addFilter(log_filter)
            redirected_handlers.append(tqdm_handler)
        else:
            redirected_handlers.append(handler)
    root_logger.handlers = redirected_handlers
    try:
        yield
    finally:
        root_logger.handlers = original_handlers


@contextmanager
def managed_progress_bar(
    *,
    enabled: bool,
    desc: str,
    total: int,
    unit: str,
    position: int = 0,
) -> Iterator[Any | None]:
    if not enabled:
        yield None
        return
    progress_bar = tqdm(
        total=max(0, int(total)),
        desc=desc,
        unit=unit,
        position=position,
        leave=True,
        dynamic_ncols=True,
        mininterval=0.2,
        bar_format=_BAR_FORMAT,
    )
    try:
        yield progress_bar
    finally:
        progress_bar.close()
