from __future__ import annotations

import asyncio
import csv
import logging
import os
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver

from .config import OUTPUT_DIR

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 1.5
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
    resolver: dns.asyncresolver.Resolver,
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
            a_task = resolver.resolve(hostname, "A", lifetime=timeout)
            aaaa_task = resolver.resolve(hostname, "AAAA", lifetime=timeout)
            answers = await asyncio.gather(
                a_task,
                aaaa_task,
                return_exceptions=True,
            )

        resolved_ips: set[str] = set()
        saw_timeout = False
        saw_resolver_error = False

        for answer in answers:
            if isinstance(answer, Exception):
                if isinstance(answer, dns.resolver.NoAnswer):
                    continue
                if isinstance(answer, dns.resolver.NXDOMAIN):
                    return {
                        "target_url": target_url,
                        "hostname": hostname,
                        "resolved_ips": "",
                        "dns_status": "dns_error",
                        "decision": "rejected",
                    }
                if isinstance(answer, dns.exception.Timeout):
                    saw_timeout = True
                    continue
                if isinstance(answer, (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout)):
                    saw_resolver_error = True
                    continue
                saw_resolver_error = True
                continue

            for item in answer:
                text = getattr(item, "address", None) or item.to_text()
                if text:
                    resolved_ips.add(text)

        if resolved_ips:
            return {
                "target_url": target_url,
                "hostname": hostname,
                "resolved_ips": ";".join(sorted(resolved_ips)),
                "dns_status": "resolved",
                "decision": "accepted",
            }

        if saw_timeout:
            return {
                "target_url": target_url,
                "hostname": hostname,
                "resolved_ips": "",
                "dns_status": "timeout",
                "decision": "rejected",
            }

        return {
            "target_url": target_url,
            "hostname": hostname,
            "resolved_ips": "",
            "dns_status": "resolver_error" if saw_resolver_error else "no_records",
            "decision": "rejected",
        }
    except (UnicodeError, ValueError):
        dns_status = "dns_error"
    except dns.exception.Timeout:
        dns_status = "timeout"
    except dns.resolver.NXDOMAIN:
        dns_status = "dns_error"
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        dns_status = "resolver_error"
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
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout

    audit_rows = await asyncio.gather(*[
        _resolve_single_url(target_url, semaphore, resolver, timeout)
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
