from __future__ import annotations

import asyncio
import csv
import logging
import os
from collections import Counter
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver

from .config import OUTPUT_DIR

logger = logging.getLogger(__name__)

DEFAULT_DNS_TIMEOUT = 5.0
DEFAULT_DNS_RETRIES = 2
DEFAULT_AUDIT_PATH = os.path.join(OUTPUT_DIR, "dns_gate_audit.csv")
DEFAULT_FALLBACK_NAMESERVERS = ("1.1.1.1", "8.8.8.8")


def _read_env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw in (None, ""):
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        logger.warning("Invalid integer override for %s=%r; using %d", name, raw, default)
        return default


DEFAULT_MIN_WORKERS = _read_env_int("PHISHING_DNS_GATE_MIN_WORKERS", 128)
DEFAULT_MAX_WORKERS = _read_env_int("PHISHING_DNS_GATE_MAX_WORKERS", 384)


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

    if target_count <= 0:
        return 1

    cpu_count = os.cpu_count() or 4
    multiplier = 12 if cpu_count >= 32 else 8
    adaptive = max(DEFAULT_MIN_WORKERS, min(DEFAULT_MAX_WORKERS, cpu_count * multiplier))
    return max(1, min(target_count, adaptive))


def _build_resolver(timeout: float, nameservers: tuple[str, ...] | list[str] | None = None) -> dns.asyncresolver.Resolver:
    use_system = not nameservers
    resolver = dns.asyncresolver.Resolver(configure=use_system)
    if nameservers:
        resolver.nameservers = list(nameservers)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


async def _resolve_single_url_once(
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


async def _resolve_single_url(
    target_url: str,
    semaphore: asyncio.Semaphore,
    primary_resolver: dns.asyncresolver.Resolver,
    timeout: float,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_resolver: dns.asyncresolver.Resolver | None = None,
) -> dict:
    retry_budget = max(0, int(retries))
    final_row = None

    for attempt in range(retry_budget + 1):
        use_fallback = attempt > 0 and fallback_resolver is not None
        resolver = fallback_resolver if use_fallback else primary_resolver
        row = await _resolve_single_url_once(
            target_url=target_url,
            semaphore=semaphore,
            resolver=resolver,
            timeout=timeout,
        )
        row["attempts"] = attempt + 1
        row["retry_count"] = attempt
        row["retry_success"] = False
        row["resolver_profile"] = "fallback" if use_fallback else "default"
        final_row = row

        if row.get("decision") == "accepted":
            row["retry_success"] = attempt > 0
            return row

        dns_status = str(row.get("dns_status", ""))
        is_retryable = dns_status in {"timeout", "resolver_error"}
        if not is_retryable:
            return row

    return final_row or {
        "target_url": target_url,
        "hostname": "",
        "resolved_ips": "",
        "dns_status": "resolver_error",
        "decision": "rejected",
        "attempts": retry_budget + 1,
        "retry_count": retry_budget,
        "retry_success": False,
        "resolver_profile": "default",
    }


async def _gate_urls_for_hashing_async(
    target_urls: list[str],
    timeout: float,
    max_workers: int | None,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_nameservers: tuple[str, ...] | list[str] | None = DEFAULT_FALLBACK_NAMESERVERS,
) -> tuple[list[str], list[dict]]:
    if not target_urls:
        return [], []

    retries = max(0, int(retries))
    worker_count = _resolve_dns_worker_count(len(target_urls), max_workers=max_workers)
    semaphore = asyncio.Semaphore(worker_count)
    resolver = _build_resolver(timeout)
    fallback_resolver = None
    if fallback_nameservers:
        try:
            fallback_resolver = _build_resolver(timeout, nameservers=fallback_nameservers)
        except Exception:
            fallback_resolver = None

    audit_rows = await asyncio.gather(*[
        _resolve_single_url(
            target_url=target_url,
            semaphore=semaphore,
            primary_resolver=resolver,
            timeout=timeout,
            retries=retries,
            fallback_resolver=fallback_resolver,
        )
        for target_url in target_urls
    ])

    accepted_urls = [
        row["target_url"]
        for row in audit_rows
        if row["decision"] == "accepted"
    ]
    status_counts = Counter(str(row.get("dns_status", "")) for row in audit_rows)
    retry_success_count = sum(1 for row in audit_rows if row.get("retry_success"))
    logger.info(
        "DNS gate details | urls=%d | kept=%d | timeout=%.1fs | retries=%d | workers=%d | "
        "resolved=%d timeout=%d resolver_error=%d no_records=%d dns_error=%d retry_success=%d",
        len(target_urls),
        len(accepted_urls),
        timeout,
        retries,
        worker_count,
        status_counts.get("resolved", 0),
        status_counts.get("timeout", 0),
        status_counts.get("resolver_error", 0),
        status_counts.get("no_records", 0),
        status_counts.get("dns_error", 0),
        retry_success_count,
    )
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
                "source_workbook",
                "hostname",
                "resolved_ips",
                "dns_status",
                "decision",
                "attempts",
                "retry_count",
                "retry_success",
                "resolver_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(audit_rows)


def gate_urls_for_hashing(
    target_urls: list[str],
    timeout: float = DEFAULT_DNS_TIMEOUT,
    audit_output_path: str = DEFAULT_AUDIT_PATH,
    max_workers: int | None = None,
    retries: int = DEFAULT_DNS_RETRIES,
    fallback_nameservers: tuple[str, ...] | list[str] | None = DEFAULT_FALLBACK_NAMESERVERS,
) -> tuple[list[str], list[dict]]:
    accepted_urls, audit_rows = asyncio.run(
        _gate_urls_for_hashing_async(
            target_urls,
            timeout=timeout,
            max_workers=max_workers,
            retries=retries,
            fallback_nameservers=fallback_nameservers,
        )
    )
    write_dns_gate_audit(audit_rows, output_path=audit_output_path)
    logger.info(
        "DNS gate kept %d/%d URLs at %.1fs timeout (retries=%d)",
        len(accepted_urls),
        len(target_urls),
        timeout,
        retries,
    )
    return accepted_urls, audit_rows
