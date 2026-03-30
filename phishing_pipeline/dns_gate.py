from __future__ import annotations

import asyncio
import csv
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from .config import OUTPUT_DIR

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 3.0
DEFAULT_AUDIT_PATH = os.path.join(OUTPUT_DIR, "dns_gate_audit.csv")
DEFAULT_MIN_WORKERS = 32
DEFAULT_MAX_WORKERS = 256


def normalize_url(url: str) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        return "https://" + text.lstrip("/")
    return text


def _resolve_dns_worker_count(target_count: int, max_workers: int | None = None) -> int:
    if max_workers is not None:
        return max(1, int(max_workers))

    cpu_count = os.cpu_count() or 4
    scaled = cpu_count * 8
    return max(1, min(DEFAULT_MAX_WORKERS, max(DEFAULT_MIN_WORKERS, scaled, min(target_count, DEFAULT_MAX_WORKERS))))


async def _resolve_single_url(
    target_url: str,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> dict:
    normalized_url = normalize_url(target_url)
    hostname = (urlparse(normalized_url).hostname or "").lower()

    if not normalized_url or not hostname:
        return {
            "target_url": target_url,
            "hostname": hostname,
            "resolved_ips": "",
            "dns_status": "invalid_host",
            "decision": "rejected",
        }

    try:
        async with semaphore:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(
                    hostname,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                ),
                timeout=timeout,
            )

        resolved_ips = sorted({
            info[4][0]
            for info in infos
            if len(info) >= 5 and info[4] and info[4][0]
        })

        if not resolved_ips:
            return {
                "target_url": target_url,
                "hostname": hostname,
                "resolved_ips": "",
                "dns_status": "no_records",
                "decision": "rejected",
            }

        return {
            "target_url": target_url,
            "hostname": hostname,
            "resolved_ips": ";".join(resolved_ips),
            "dns_status": "resolved",
            "decision": "accepted",
        }
    except asyncio.TimeoutError:
        dns_status = "timeout"
    except (socket.gaierror, UnicodeError, ValueError):
        dns_status = "dns_error"
    except OSError:
        dns_status = "os_error"
    except Exception:
        dns_status = "resolver_error"

    return {
        "target_url": target_url,
        "hostname": hostname,
        "resolved_ips": "",
        "dns_status": dns_status,
        "decision": "rejected",
    }


async def _gate_urls_for_hashing_async(
    target_urls: list[str],
    timeout: float,
    max_workers: int | None,
) -> tuple[list[str], list[dict]]:
    if not target_urls:
        return [], []

    worker_count = _resolve_dns_worker_count(len(target_urls), max_workers=max_workers)
    semaphore = asyncio.Semaphore(worker_count)
    loop = asyncio.get_running_loop()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        loop.set_default_executor(executor)
        audit_rows = await asyncio.gather(*[
            _resolve_single_url(target_url, semaphore, timeout)
            for target_url in target_urls
        ])

    accepted_urls = [
        row["target_url"]
        for row in audit_rows
        if row["decision"] == "accepted"
    ]
    return accepted_urls, audit_rows


def write_dns_gate_audit(
    audit_rows: list[dict],
    output_path: str = DEFAULT_AUDIT_PATH,
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "target_url",
                "hostname",
                "resolved_ips",
                "dns_status",
                "decision",
            ],
        )
        writer.writeheader()
        writer.writerows(audit_rows)


def gate_urls_for_hashing(
    target_urls: list[str],
    timeout: float = DEFAULT_DNS_TIMEOUT,
    audit_output_path: str = DEFAULT_AUDIT_PATH,
    max_workers: int | None = None,
) -> tuple[list[str], list[dict]]:
    accepted_urls, audit_rows = asyncio.run(
        _gate_urls_for_hashing_async(
            target_urls,
            timeout=timeout,
            max_workers=max_workers,
        )
    )
    write_dns_gate_audit(audit_rows, output_path=audit_output_path)
    logger.info(
        "DNS gate kept %d/%d URLs at %.1fs timeout",
        len(accepted_urls),
        len(target_urls),
        timeout,
    )
    return accepted_urls, audit_rows
