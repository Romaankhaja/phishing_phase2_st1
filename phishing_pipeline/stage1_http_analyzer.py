from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import geoip2.database
import httpx
import tldextract
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from .config import (
    ASN_DB_PATH,
    ROOT_DIR,
    STAGE1_AUTH_TERMS,
    STAGE1_HTTP_CONFIG,
    STAGE1_SCORE_WEIGHTS,
    STAGE1_SUSPICIOUS_CERT_ISSUER_TOKENS,
    STAGE1_SUSPICIOUS_PROVIDER_TOKENS,
)
from .rdap_utils import lookup_rdap
from .utils import _get_tvc_brand_catalog, _normalize_tvc_text

logger = logging.getLogger(__name__)

_GENERIC_ALIAS_TOKENS = {
    "account",
    "accounts",
    "auth",
    "bank",
    "cloud",
    "customer",
    "customers",
    "login",
    "mail",
    "portal",
    "secure",
    "service",
    "services",
    "verify",
}
_SCRIPT_REDIRECT_PATTERNS = (
    re.compile(r"window\.location(?:\.href)?\s*=", re.I),
    re.compile(r"location\.replace\(", re.I),
    re.compile(r"location\.assign\(", re.I),
    re.compile(r"document\.location\s*=", re.I),
)


@dataclass
class Stage1ConcurrencyControls:
    url_semaphore: asyncio.Semaphore | None = None
    http_semaphore: asyncio.Semaphore | None = None
    dns_semaphore: asyncio.Semaphore | None = None
    rdap_semaphore: asyncio.Semaphore | None = None
    tls_semaphore: asyncio.Semaphore | None = None


def build_stage1_concurrency_controls(
    config: dict[str, Any] | None = None,
) -> Stage1ConcurrencyControls:
    config = config or STAGE1_HTTP_CONFIG
    url_concurrency = max(1, int(config.get("concurrency", 24)))
    http_concurrency = max(1, int(config.get("http_concurrency", url_concurrency)))
    dns_concurrency = max(1, int(config.get("dns_concurrency", http_concurrency)))
    rdap_concurrency = max(1, int(config.get("rdap_concurrency", 32)))
    tls_concurrency = max(1, int(config.get("tls_concurrency", 32)))
    return Stage1ConcurrencyControls(
        url_semaphore=asyncio.Semaphore(url_concurrency),
        http_semaphore=asyncio.Semaphore(http_concurrency),
        dns_semaphore=asyncio.Semaphore(dns_concurrency),
        rdap_semaphore=asyncio.Semaphore(rdap_concurrency),
        tls_semaphore=asyncio.Semaphore(tls_concurrency),
    )


async def _run_with_optional_semaphore(
    semaphore: asyncio.Semaphore | None,
    awaitable_factory,
):
    if semaphore is None:
        return await awaitable_factory()
    async with semaphore:
        return await awaitable_factory()


def normalize_stage1_url(url: str) -> str:
    text = str(url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        return "https://" + text.lstrip("/")
    return text


def _normalize_host(host: str) -> str:
    return str(host or "").strip().lower().split(":")[0]


def _collapse_spaces(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _compact_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _normalize_tvc_text(value))


def _unique_ordered(values: list[str]) -> list[str]:
    seen = set()
    ordered = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _same_registered_domain(host_a: str, host_b: str) -> bool:
    ext_a = tldextract.extract(_normalize_host(host_a))
    ext_b = tldextract.extract(_normalize_host(host_b))
    left = ".".join(part for part in [ext_a.domain, ext_a.suffix] if part)
    right = ".".join(part for part in [ext_b.domain, ext_b.suffix] if part)
    return bool(left and right and left == right)


def _host_similarity_key(host: str) -> str:
    ext = tldextract.extract(_normalize_host(host))
    return ".".join(part for part in [ext.domain, ext.suffix] if part)


def _extract_alias_hits(surface_norm: str, surface_compact: str, aliases: tuple[str, ...]) -> list[str]:
    hits = []
    for alias in aliases:
        alias_norm = _normalize_tvc_text(alias)
        if not alias_norm:
            continue
        alias_compact = alias_norm.replace(" ", "")
        if " " in alias_norm:
            if alias_norm in surface_norm:
                hits.append(alias_norm)
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(alias_norm)}(?![a-z0-9])", surface_norm):
            hits.append(alias_norm)
            continue
        if alias_compact and alias_compact in surface_compact:
            hits.append(alias_norm)
    return _unique_ordered(hits)


def _count_auth_term_hits(*texts: str) -> int:
    surface = " ".join(_normalize_tvc_text(text) for text in texts if text)
    if not surface:
        return 0
    hits = 0
    for term in STAGE1_AUTH_TERMS:
        term_norm = _normalize_tvc_text(term)
        if not term_norm:
            continue
        if " " in term_norm:
            hits += int(term_norm in surface)
        else:
            hits += int(bool(re.search(rf"(?<![a-z0-9]){re.escape(term_norm)}(?![a-z0-9])", surface)))
    return hits


def _parse_creation_date(raw_value: Any) -> datetime | None:
    if not raw_value:
        return None
    try:
        dt = date_parser.parse(str(raw_value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _age_days_from_creation(raw_value: Any) -> int | None:
    created_at = _parse_creation_date(raw_value)
    if created_at is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - created_at).days))


def _extract_meta_description(soup: BeautifulSoup) -> str:
    for attrs in (
        {"name": "description"},
        {"property": "og:description"},
        {"name": "twitter:description"},
    ):
        tag = soup.find("meta", attrs=attrs)
        if tag and tag.get("content"):
            return _collapse_spaces(tag.get("content"))
    return ""


def _extract_favicon_url(soup: BeautifulSoup, final_url: str) -> str:
    for tag in soup.find_all("link"):
        rel_values = " ".join(tag.get("rel", [])).lower()
        if "icon" not in rel_values:
            continue
        href = str(tag.get("href", "") or "").strip()
        if href:
            return urljoin(final_url, href)
    return ""


def _extract_form_details(soup: BeautifulSoup, final_url: str) -> dict[str, Any]:
    forms = soup.find_all("form")
    submit_texts: list[str] = []
    action_urls: list[str] = []
    action_domains: list[str] = []
    input_count = 0
    password_count = 0
    login_form = False

    for form in forms:
        action_raw = str(form.get("action", "") or "").strip()
        action_url = urljoin(final_url, action_raw) if action_raw else ""
        if action_url:
            action_urls.append(action_url)
            action_domains.append(_normalize_host(urlparse(action_url).netloc))

        form_inputs = form.find_all("input")
        input_count += len(form_inputs)
        form_password_count = 0
        form_submit_texts = []
        for input_tag in form_inputs:
            input_type = str(input_tag.get("type", "") or "").strip().lower()
            if input_type == "password":
                form_password_count += 1
            if input_type in {"submit", "button"}:
                form_submit_texts.append(
                    _collapse_spaces(
                        input_tag.get("value")
                        or input_tag.get("aria-label")
                        or input_tag.get("name")
                        or ""
                    )
                )
        password_count += form_password_count

        for button in form.find_all("button"):
            button_text = _collapse_spaces(button.get_text(" ", strip=True))
            if button_text:
                form_submit_texts.append(button_text)

        submit_texts.extend(text for text in form_submit_texts if text)
        form_text = _collapse_spaces(form.get_text(" ", strip=True))
        action_surface = " ".join(
            value for value in [action_raw, action_url, form_text, " ".join(form_submit_texts)] if value
        )
        login_form = login_form or bool(
            form_password_count > 0 or _count_auth_term_hits(action_surface) > 0
        )

    return {
        "form_count": len(forms),
        "input_count": input_count,
        "password_count": password_count,
        "submit_texts": _unique_ordered(submit_texts),
        "action_urls": _unique_ordered(action_urls),
        "action_domains": _unique_ordered(action_domains),
        "page_has_login_form": bool(login_form),
    }


def _extract_anchor_details(soup: BeautifulSoup, final_domain: str, final_url: str) -> dict[str, Any]:
    outbound_domains = []
    anchor_count = 0
    for tag in soup.find_all("a"):
        href = str(tag.get("href", "") or "").strip()
        if not href:
            continue
        anchor_count += 1
        resolved = urljoin(final_url, href)
        domain = _normalize_host(urlparse(resolved).netloc)
        if domain and final_domain and not _same_registered_domain(domain, final_domain):
            outbound_domains.append(domain)
    ordered = _unique_ordered(outbound_domains)
    return {
        "anchor_count": anchor_count,
        "top_outbound_domains": ordered[:5],
    }


def _extract_stage1_html_features(html_text: str, final_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(html_text or "", "html.parser")
    title_text = _collapse_spaces(soup.title.get_text(" ", strip=True)) if soup.title else ""
    meta_description = _extract_meta_description(soup)
    favicon_url = _extract_favicon_url(soup, final_url)
    visible_text = _collapse_spaces(soup.get_text(" ", strip=True))
    form_details = _extract_form_details(soup, final_url)
    final_domain = _normalize_host(urlparse(final_url).netloc)
    anchor_details = _extract_anchor_details(soup, final_domain, final_url)
    meta_refresh = bool(
        soup.find(
            "meta",
            attrs={
                "http-equiv": lambda value: bool(value and str(value).strip().lower() == "refresh")
            },
        )
    )
    iframe_count = len(soup.find_all("iframe"))
    img_count = len(soup.find_all("img"))
    js_redirect = any(pattern.search(html_text or "") for pattern in _SCRIPT_REDIRECT_PATTERNS)

    return {
        "title_text": title_text,
        "meta_description": meta_description,
        "visible_text": visible_text,
        "favicon_url": favicon_url,
        "favicon_domain": _normalize_host(urlparse(favicon_url).netloc),
        "favicon_path": urlparse(favicon_url).path if favicon_url else "",
        "iframe_count": iframe_count,
        "img_count": img_count,
        "meta_refresh": meta_refresh,
        "js_redirect": js_redirect,
        "text_word_count": len(re.findall(r"[a-z0-9]+", visible_text.lower())),
        **form_details,
        **anchor_details,
    }


def _build_entity_context() -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    entity_db_path = os.path.join(ROOT_DIR, "data", "entity_hash_db.json")
    try:
        with open(entity_db_path, "r", encoding="utf-8") as fh:
            entity_db = json.load(fh)
    except Exception:
        entity_db = {}

    catalog = _get_tvc_brand_catalog()
    entity_context: dict[str, dict[str, Any]] = {}
    ordered_names = []
    for entity_name, payload in entity_db.items():
        domains = tuple(
            sorted(
                {
                    _normalize_host(str(domain or ""))
                    for domain in (payload or {}).get("domains", [])
                    if str(domain or "").strip()
                }
            )
        )
        entity_name_norm = _normalize_tvc_text(entity_name)
        entity_name_compact = entity_name_norm.replace(" ", "")
        aliases = {entity_name_norm, entity_name_compact}
        for domain in domains:
            ext = tldextract.extract(domain)
            primary = str(ext.domain or "").strip().lower()
            if primary:
                aliases.add(primary)

        for canonical, brand_payload in catalog.items():
            detection_aliases = set(brand_payload.get("detection_aliases", brand_payload.get("aliases", set())))
            brand_domains = {
                _normalize_host(domain)
                for domain in brand_payload.get("domains", set())
                if str(domain or "").strip()
            }
            if (
                (set(domains) & brand_domains)
                or entity_name_norm in detection_aliases
                or entity_name_compact in detection_aliases
                or canonical == entity_name_compact
            ):
                aliases.update(detection_aliases)

        cleaned_aliases = []
        for alias in aliases:
            alias_norm = _normalize_tvc_text(alias)
            if not alias_norm or len(alias_norm.replace(" ", "")) < 3:
                continue
            if alias_norm in _GENERIC_ALIAS_TOKENS:
                continue
            cleaned_aliases.append(alias_norm)

        alias_tuple = tuple(sorted(set(cleaned_aliases), key=lambda item: (-len(item), item)))
        entity_context[entity_name] = {
            "name": entity_name,
            "domains": domains,
            "aliases": alias_tuple,
        }
        ordered_names.append(entity_name)

    return entity_context, tuple(ordered_names)


@lru_cache(maxsize=1)
def get_stage1_entity_context() -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    return _build_entity_context()


@lru_cache(maxsize=1)
def _geoip_readers() -> tuple[Any, Any]:
    city_db_path = ASN_DB_PATH.replace("ASN", "City")
    try:
        return geoip2.database.Reader(ASN_DB_PATH), geoip2.database.Reader(city_db_path)
    except Exception:
        try:
            return geoip2.database.Reader(ASN_DB_PATH), None
        except Exception:
            return None, None


def _lookup_geoip(ip_address: str) -> dict[str, Any]:
    asn_reader, city_reader = _geoip_readers()
    result = {
        "asn": None,
        "asn_org": "",
        "country": "",
    }
    if not ip_address or asn_reader is None:
        return result
    try:
        asn_record = asn_reader.asn(ip_address)
        result["asn"] = asn_record.autonomous_system_number
        result["asn_org"] = str(asn_record.autonomous_system_organization or "")
    except Exception:
        pass
    if city_reader is None:
        return result
    try:
        city_record = city_reader.city(ip_address)
        result["country"] = str(city_record.country.iso_code or "")
    except Exception:
        pass
    return result


def _fetch_tls_summary_sync(host: str, timeout: float) -> dict[str, Any]:
    summary = {
        "cert_cn": "",
        "cert_san": [],
        "cert_issuer": "",
    }
    if not host:
        return summary
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    return summary
                subject = dict(item[0] for item in cert.get("subject", []))
                issuer = dict(item[0] for item in cert.get("issuer", []))
                san_hosts = [entry[1] for entry in cert.get("subjectAltName", []) if entry and entry[0] == "DNS"]
                summary["cert_cn"] = str(subject.get("commonName", "") or "")
                summary["cert_san"] = _unique_ordered(san_hosts)
                summary["cert_issuer"] = str(
                    issuer.get("organizationName")
                    or issuer.get("O")
                    or ""
                )
    except Exception:
        return summary
    return summary


async def _fetch_tls_summary(host: str, timeout: float) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _fetch_tls_summary_sync, host, timeout)


async def _resolve_dns_answers(host: str, timeout: float) -> dict[str, Any]:
    if not host:
        return {"resolved_ips": [], "dns_answer_count": 0}

    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    answers = await asyncio.gather(
        resolver.resolve(host, "A", lifetime=timeout),
        resolver.resolve(host, "AAAA", lifetime=timeout),
        return_exceptions=True,
    )
    ips = []
    for answer in answers:
        if isinstance(answer, Exception):
            continue
        for item in answer:
            value = getattr(item, "address", None) or item.to_text()
            if value:
                ips.append(value)
    ordered_ips = _unique_ordered(ips)
    return {
        "resolved_ips": ordered_ips,
        "dns_answer_count": len(ordered_ips),
    }


def _best_matching_domain(final_domain: str, domains: tuple[str, ...]) -> str:
    if not final_domain:
        return domains[0] if domains else ""
    final_key = _host_similarity_key(final_domain)
    best_domain = ""
    best_score = -1
    for domain in domains:
        domain_key = _host_similarity_key(domain)
        score = 0
        if final_key and domain_key and final_key == domain_key:
            score = 3
        elif domain_key and domain_key in final_key:
            score = 2
        elif final_key and domain_key and final_key.startswith(domain_key):
            score = 1
        if score > best_score:
            best_score = score
            best_domain = domain
    return best_domain or (domains[0] if domains else "")


def score_stage1_http_signals(
    extracted: dict[str, Any],
    entity_context: dict[str, dict[str, Any]] | None = None,
    ordered_entities: tuple[str, ...] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config or STAGE1_HTTP_CONFIG
    weights = STAGE1_SCORE_WEIGHTS
    if entity_context is None or ordered_entities is None:
        entity_context, ordered_entities = get_stage1_entity_context()

    final_url = str(extracted.get("final_landing_url") or extracted.get("final_url") or "")
    final_domain = _normalize_host(extracted.get("final_domain") or urlparse(final_url).netloc)
    original_domain = _normalize_host(extracted.get("original_domain") or urlparse(extracted.get("normalized_url", "")).netloc)
    title_text = str(extracted.get("title_text") or "")
    meta_description = str(extracted.get("meta_description") or "")
    visible_text = str(extracted.get("visible_text") or extracted.get("html_excerpt") or "")
    submit_text = " ".join(extracted.get("submit_texts", []) or [])
    redirect_surface = " ".join(extracted.get("redirect_chain", []) or []) + " " + final_url
    favicon_url = str(extracted.get("favicon_url") or "")

    title_norm = _normalize_tvc_text(title_text)
    title_compact = _compact_text(title_text)
    meta_norm = _normalize_tvc_text(meta_description)
    meta_compact = _compact_text(meta_description)
    body_norm = _normalize_tvc_text(visible_text)
    body_compact = _compact_text(visible_text)
    submit_norm = _normalize_tvc_text(submit_text)
    submit_compact = _compact_text(submit_text)
    final_domain_norm = _normalize_tvc_text(final_domain)
    final_domain_compact = _compact_text(final_domain)
    redirect_norm = _normalize_tvc_text(redirect_surface)
    redirect_compact = _compact_text(redirect_surface)
    favicon_norm = _normalize_tvc_text(favicon_url)
    favicon_compact = _compact_text(favicon_url)

    ranked_entities = []
    for entity_name in ordered_entities:
        entity_payload = entity_context.get(entity_name) or {}
        aliases = entity_payload.get("aliases", ())
        if not aliases:
            continue

        title_hits = _extract_alias_hits(title_norm, title_compact, aliases)
        meta_hits = _extract_alias_hits(meta_norm, meta_compact, aliases)
        body_hits = _extract_alias_hits(body_norm, body_compact, aliases)
        submit_hits = _extract_alias_hits(submit_norm, submit_compact, aliases)
        final_domain_hits = _extract_alias_hits(final_domain_norm, final_domain_compact, aliases)
        redirect_hits = _extract_alias_hits(redirect_norm, redirect_compact, aliases)
        favicon_hits = _extract_alias_hits(favicon_norm, favicon_compact, aliases)

        brand_score = 0
        if title_hits:
            brand_score += weights["brand"]["title"]
        if meta_hits:
            brand_score += weights["brand"]["meta"]
        if body_hits:
            brand_score += weights["brand"]["body"]
        if submit_hits:
            brand_score += weights["brand"]["submit"]
        if favicon_hits:
            brand_score += weights["brand"]["favicon"]
        if final_domain_hits:
            brand_score += weights["brand"]["final_domain"]
        if redirect_hits:
            brand_score += weights["brand"]["redirect_alias"]

        mention_hits = _unique_ordered(
            title_hits + meta_hits + body_hits + submit_hits + final_domain_hits + redirect_hits + favicon_hits
        )
        if brand_score <= 0 and not mention_hits:
            continue

        ranked_entities.append(
            {
                "entity_name": entity_name,
                "brand_score": brand_score,
                "mention_count": len(mention_hits),
                "matched_aliases": mention_hits,
                "surface_hits": {
                    "title": bool(title_hits),
                    "meta": bool(meta_hits),
                    "body": bool(body_hits),
                    "submit": bool(submit_hits),
                    "final_domain": bool(final_domain_hits),
                    "redirect": bool(redirect_hits),
                    "favicon": bool(favicon_hits),
                },
                "best_matching_domain": _best_matching_domain(final_domain, entity_payload.get("domains", ())),
            }
        )

    ranked_entities.sort(
        key=lambda item: (
            -int(item["brand_score"]),
            -int(item["mention_count"]),
            item["entity_name"],
        )
    )

    best_brand_match = ranked_entities[0] if ranked_entities else None
    brand_score = int(best_brand_match["brand_score"]) if best_brand_match else 0
    csc_mention_count = int(best_brand_match["mention_count"]) if best_brand_match else 0
    best_entity = str(best_brand_match["entity_name"]) if best_brand_match else ""
    best_matching_domain = str(best_brand_match["best_matching_domain"]) if best_brand_match else ""
    surface_hits = dict(best_brand_match["surface_hits"]) if best_brand_match else {}

    password_count = int(extracted.get("password_count", 0) or 0)
    page_has_password_field = bool(password_count > 0 or extracted.get("page_has_password_field"))
    input_count = int(extracted.get("input_count", 0) or 0)
    form_count = int(extracted.get("form_count", 0) or 0)
    auth_term_hits = _count_auth_term_hits(
        title_text,
        meta_description,
        visible_text,
        submit_text,
        " ".join(extracted.get("action_urls", []) or []),
    )
    page_has_login_form = bool(extracted.get("page_has_login_form")) or bool(
        form_count > 0 and (page_has_password_field or auth_term_hits > 0)
    )
    form_action_domains = [
        _normalize_host(domain)
        for domain in (extracted.get("action_domains", []) or [])
        if str(domain or "").strip()
    ]
    form_action_mismatch = bool(
        final_domain
        and any(
            action_domain and not _same_registered_domain(action_domain, final_domain)
            for action_domain in form_action_domains
        )
    )
    submit_auth = _count_auth_term_hits(submit_text) > 0

    credential_score = 0
    if page_has_password_field:
        credential_score += weights["credential"]["password"]
    if page_has_login_form:
        credential_score += weights["credential"]["login_form"]
    if auth_term_hits > 0:
        credential_score += weights["credential"]["auth_terms"]
    if submit_auth:
        credential_score += weights["credential"]["submit_auth"]
    if form_action_mismatch:
        credential_score += weights["credential"]["action_mismatch"]
    if input_count >= 3:
        credential_score += weights["credential"]["multi_input"]

    rdap_age_days = extracted.get("rdap_age_days")
    asn_org = str(extracted.get("asn_org") or "")
    cert_issuer = str(extracted.get("cert_issuer") or "")
    cert_cn = str(extracted.get("cert_cn") or "")
    redirect_count = int(extracted.get("redirect_count", 0) or 0)
    suspicious_provider = any(token in asn_org.lower() for token in STAGE1_SUSPICIOUS_PROVIDER_TOKENS)
    cert_suspect = any(token in cert_issuer.lower() for token in STAGE1_SUSPICIOUS_CERT_ISSUER_TOKENS)
    if cert_cn and final_domain and not _same_registered_domain(cert_cn, final_domain):
        cert_suspect = True

    infra_score = 0
    if isinstance(rdap_age_days, int) and rdap_age_days <= 30:
        infra_score += weights["infra"]["age_le_30d"]
    elif isinstance(rdap_age_days, int) and rdap_age_days <= 90:
        infra_score += weights["infra"]["age_le_90d"]
    if suspicious_provider:
        infra_score += weights["infra"]["suspicious_provider"]
    if cert_suspect:
        infra_score += weights["infra"]["cert_suspect"]
    if redirect_count >= 2:
        infra_score += weights["infra"]["redirect_count_ge_2"]

    text_word_count = int(extracted.get("text_word_count", 0) or 0)
    img_count = int(extracted.get("img_count", 0) or 0)
    iframe_count = int(extracted.get("iframe_count", 0) or 0)
    meta_refresh = bool(extracted.get("meta_refresh"))
    js_redirect = bool(extracted.get("js_redirect"))
    image_heavy_low_text = bool((img_count >= 5 or iframe_count >= 3) and text_word_count < 25)
    final_domain_changed = bool(
        final_domain and original_domain and not _same_registered_domain(final_domain, original_domain)
    )

    evasion_score = 0
    if meta_refresh:
        evasion_score += weights["evasion"]["meta_refresh"]
    if js_redirect:
        evasion_score += weights["evasion"]["js_redirect"]
    if iframe_count > 0:
        evasion_score += weights["evasion"]["iframe"]
    if image_heavy_low_text:
        evasion_score += weights["evasion"]["image_heavy_low_text"]
    if final_domain_changed:
        evasion_score += weights["evasion"]["final_domain_changed"]

    title_brand_hit = bool(surface_hits.get("title"))
    hard_trigger_brand_min = int(config.get("hard_trigger_brand_min", 1) or 1)
    hard_trigger_hit = bool(
        (brand_score >= hard_trigger_brand_min and page_has_password_field)
        or (brand_score >= hard_trigger_brand_min and page_has_login_form)
        or (title_brand_hit and form_action_mismatch)
        or (
            brand_score >= hard_trigger_brand_min
            and auth_term_hits > 0
            and isinstance(rdap_age_days, int)
            and rdap_age_days <= 30
        )
    )

    reason_list = []
    if title_brand_hit:
        reason_list.append("title_brand_match")
    if surface_hits.get("meta"):
        reason_list.append("meta_brand_match")
    if surface_hits.get("body"):
        reason_list.append("body_brand_match")
    if surface_hits.get("submit"):
        reason_list.append("submit_brand_match")
    if surface_hits.get("favicon"):
        reason_list.append("favicon_brand_match")
    if surface_hits.get("redirect"):
        reason_list.append("redirect_brand_match")
    if surface_hits.get("final_domain"):
        reason_list.append("final_domain_brand_match")
    if page_has_password_field:
        reason_list.append("password_field")
    if page_has_login_form:
        reason_list.append("login_form")
    if auth_term_hits > 0:
        reason_list.append("auth_wording")
    if submit_auth:
        reason_list.append("submit_auth_wording")
    if form_action_mismatch:
        reason_list.append("form_action_mismatch")
    if input_count >= 3:
        reason_list.append("multi_input_form")
    if isinstance(rdap_age_days, int) and rdap_age_days <= 30:
        reason_list.append("very_new_domain")
    elif isinstance(rdap_age_days, int) and rdap_age_days <= 90:
        reason_list.append("new_domain")
    if suspicious_provider:
        reason_list.append("suspicious_hosting_provider")
    if cert_suspect:
        reason_list.append("suspicious_certificate")
    if redirect_count >= 2:
        reason_list.append("multi_redirect_chain")
    if meta_refresh:
        reason_list.append("meta_refresh")
    if js_redirect:
        reason_list.append("js_redirect")
    if iframe_count > 0:
        reason_list.append("iframe_present")
    if image_heavy_low_text:
        reason_list.append("image_heavy_low_text")
    if final_domain_changed:
        reason_list.append("final_domain_changed")
    if hard_trigger_hit:
        reason_list.append("hard_trigger")

    total_stage1_score = int(brand_score + credential_score + infra_score + evasion_score)
    escalate_reasons = []
    if hard_trigger_hit:
        escalate_reasons.append("hard_trigger_hit")
    if total_stage1_score >= int(config["escalate_total_threshold"]):
        escalate_reasons.append("stage1_score_threshold")
    if brand_score >= int(config["brand_min"]) and credential_score >= int(config["credential_min"]):
        escalate_reasons.append("brand_credential_combo")
    escalate_to_hashing = bool(escalate_reasons)
    if not escalate_to_hashing:
        if total_stage1_score >= int(config["low_band_min"]):
            escalate_reason = "stage1_suspected_non_escalated"
        elif str(extracted.get("fetch_status", "")).strip().lower() == "failed":
            escalate_reason = "stage1_fetch_failed"
        else:
            escalate_reason = "stage1_low_suspicion"
    else:
        escalate_reason = "|".join(_unique_ordered(escalate_reasons))

    return {
        "best_entity": best_entity,
        "best_matching_domain": best_matching_domain,
        "candidate_entities": [item["entity_name"] for item in ranked_entities[:5]],
        "candidate_best_matching_domains": {
            item["entity_name"]: item["best_matching_domain"] for item in ranked_entities[:5]
        },
        "brand_score": brand_score,
        "credential_score": credential_score,
        "infra_score": infra_score,
        "evasion_score": evasion_score,
        "total_stage1_score": total_stage1_score,
        "hard_trigger_hit": hard_trigger_hit,
        "stage1_reasons": "|".join(_unique_ordered(reason_list)),
        "page_has_password_field": page_has_password_field,
        "page_has_login_form": page_has_login_form,
        "form_action_mismatch": form_action_mismatch,
        "csc_mention_count": csc_mention_count,
        "redirect_count": redirect_count,
        "final_domain": final_domain,
        "favicon_domain": _normalize_host(extracted.get("favicon_domain") or urlparse(favicon_url).netloc),
        "html_bytes_read": int(extracted.get("html_bytes_read", 0) or 0),
        "escalate_to_hashing": escalate_to_hashing,
        "escalate_reason": escalate_reason,
        "rdap_age_days": rdap_age_days,
        "matched_aliases": list(best_brand_match["matched_aliases"]) if best_brand_match else [],
        "surface_hits": surface_hits,
    }


def _default_stage1_result(url: str) -> dict[str, Any]:
    normalized_url = normalize_stage1_url(url)
    return {
        "url": normalized_url,
        "normalized_url": normalized_url,
        "original_domain": _normalize_host(urlparse(normalized_url).netloc),
        "fetch_status": "failed",
        "visual_status": "not_attempted",
        "fetch_error_type": "",
        "fetch_error_detail": "",
        "status_code": 0,
        "redirect_chain": [],
        "redirect_count": 0,
        "final_landing_url": "",
        "final_domain": "",
        "response_headers": {},
        "content_type": "",
        "content_length": 0,
        "html_excerpt": "",
        "html_bytes_read": 0,
        "title_text": "",
        "meta_description": "",
        "visible_text": "",
        "favicon_url": "",
        "favicon_domain": "",
        "favicon_path": "",
        "form_count": 0,
        "input_count": 0,
        "password_count": 0,
        "submit_texts": [],
        "action_urls": [],
        "action_domains": [],
        "page_has_login_form": False,
        "anchor_count": 0,
        "top_outbound_domains": [],
        "iframe_count": 0,
        "img_count": 0,
        "meta_refresh": False,
        "js_redirect": False,
        "text_word_count": 0,
        "resolved_ips": [],
        "dns_answer_count": 0,
        "asn": None,
        "asn_org": "",
        "country": "",
        "cert_cn": "",
        "cert_san": [],
        "cert_issuer": "",
        "rdap_creation_date": None,
        "rdap_age_days": None,
        "best_entity": "",
        "best_matching_domain": "",
        "candidate_entities": [],
        "candidate_best_matching_domains": {},
        "brand_score": 0,
        "credential_score": 0,
        "infra_score": 0,
        "evasion_score": 0,
        "total_stage1_score": 0,
        "hard_trigger_hit": False,
        "stage1_reasons": "",
        "page_has_password_field": False,
        "form_action_mismatch": False,
        "csc_mention_count": 0,
        "escalate_to_hashing": False,
        "escalate_reason": "stage1_fetch_failed",
    }


async def analyze_stage1_url(
    url: str,
    client: httpx.AsyncClient,
    entity_context: dict[str, dict[str, Any]] | None = None,
    ordered_entities: tuple[str, ...] | None = None,
    config: dict[str, Any] | None = None,
    concurrency_controls: Stage1ConcurrencyControls | None = None,
) -> dict[str, Any]:
    config = config or STAGE1_HTTP_CONFIG
    concurrency_controls = concurrency_controls or Stage1ConcurrencyControls()
    result = _default_stage1_result(url)
    if entity_context is None or ordered_entities is None:
        entity_context, ordered_entities = get_stage1_entity_context()

    normalized_url = result["normalized_url"]
    if not normalized_url:
        result["fetch_error_type"] = "invalid_url"
        result["fetch_error_detail"] = "empty url"
        return result

    redirect_chain: list[str] = []
    head_response = None
    response_headers = {}
    html_bytes = b""
    response = None

    async def _fetch_http_artifacts():
        nonlocal head_response, redirect_chain, response_headers, html_bytes, response
        try:
            head_response = await client.head(
                normalized_url,
                follow_redirects=True,
                timeout=httpx.Timeout(config["head_timeout"], connect=config["connect_timeout"]),
            )
            redirect_chain = [str(item.url) for item in head_response.history[: config["max_redirects"]]]
        except Exception as exc:
            result["fetch_error_type"] = "head_error"
            result["fetch_error_detail"] = str(exc)

        try:
            async with client.stream(
                "GET",
                normalized_url,
                follow_redirects=True,
                timeout=httpx.Timeout(config["get_timeout"], connect=config["connect_timeout"]),
            ) as streamed_response:
                response = streamed_response
                redirect_chain = [str(item.url) for item in response.history[: config["max_redirects"]]]
                response_headers = dict(response.headers)
                content_type = str(response.headers.get("content-type", "") or "")
                content_length_raw = response.headers.get("content-length")
                try:
                    content_length = int(content_length_raw) if content_length_raw is not None else 0
                except Exception:
                    content_length = 0

                result["status_code"] = int(response.status_code or 0)
                result["redirect_chain"] = redirect_chain
                result["redirect_count"] = len(redirect_chain)
                result["final_landing_url"] = str(response.url)
                result["final_domain"] = _normalize_host(urlparse(str(response.url)).netloc)
                result["response_headers"] = response_headers
                result["content_type"] = content_type
                result["content_length"] = content_length
                result["fetch_status"] = "fetched"

                should_read_body = ("html" in content_type.lower()) or (not content_type)
                if should_read_body:
                    total = 0
                    chunks = []
                    async for chunk in response.aiter_bytes():
                        if not chunk:
                            continue
                        remaining = int(config["max_html_bytes"]) - total
                        if remaining <= 0:
                            break
                        piece = chunk[:remaining]
                        chunks.append(piece)
                        total += len(piece)
                        if total >= int(config["max_html_bytes"]):
                            break
                    html_bytes = b"".join(chunks)
        except Exception as exc:
            if head_response is None:
                result["fetch_status"] = "failed"
            else:
                result["fetch_status"] = "head_only"
            result["fetch_error_type"] = "get_error"
            result["fetch_error_detail"] = str(exc)

    await _run_with_optional_semaphore(
        concurrency_controls.http_semaphore,
        _fetch_http_artifacts,
    )

    if not result["final_landing_url"] and head_response is not None:
        result["status_code"] = int(head_response.status_code or 0)
        result["redirect_chain"] = redirect_chain
        result["redirect_count"] = len(redirect_chain)
        result["final_landing_url"] = str(head_response.url)
        result["final_domain"] = _normalize_host(urlparse(str(head_response.url)).netloc)
        result["response_headers"] = dict(head_response.headers)
        result["content_type"] = str(head_response.headers.get("content-type", "") or "")
        content_length_raw = head_response.headers.get("content-length")
        try:
            result["content_length"] = int(content_length_raw) if content_length_raw is not None else 0
        except Exception:
            result["content_length"] = 0
        if result["fetch_status"] == "failed":
            result["fetch_status"] = "fetched"

    if html_bytes:
        charset = None
        if response is not None:
            charset = getattr(response, "charset_encoding", None) or response.encoding
        try:
            html_text = html_bytes.decode(charset or "utf-8", errors="ignore")
        except Exception:
            html_text = html_bytes.decode("utf-8", errors="ignore")
        html_features = _extract_stage1_html_features(html_text, result["final_landing_url"] or normalized_url)
        result.update(html_features)
        result["html_excerpt"] = html_text[: int(config["max_html_bytes"])]
        result["html_bytes_read"] = len(html_bytes)
    else:
        result["html_excerpt"] = ""
        result["html_bytes_read"] = 0

    final_domain = result["final_domain"]
    if final_domain:
        dns_task = asyncio.create_task(
            _run_with_optional_semaphore(
                concurrency_controls.dns_semaphore,
                lambda: _resolve_dns_answers(final_domain, float(config["dns_timeout"])),
            )
        )
        rdap_task = asyncio.create_task(
            _run_with_optional_semaphore(
                concurrency_controls.rdap_semaphore,
                lambda: lookup_rdap(
                    final_domain,
                    client=client,
                    timeout=float(config["rdap_timeout"]),
                ),
            )
        )
        tls_task = asyncio.create_task(
            _run_with_optional_semaphore(
                concurrency_controls.tls_semaphore,
                lambda: _fetch_tls_summary(final_domain, float(config["tls_timeout"])),
            )
        )
        dns_info, rdap_info, tls_info = await asyncio.gather(dns_task, rdap_task, tls_task, return_exceptions=True)

        if isinstance(dns_info, dict):
            result["resolved_ips"] = dns_info.get("resolved_ips", [])
            result["dns_answer_count"] = int(dns_info.get("dns_answer_count", 0) or 0)
            if result["resolved_ips"]:
                geoip = _lookup_geoip(result["resolved_ips"][0])
                result["asn"] = geoip.get("asn")
                result["asn_org"] = str(geoip.get("asn_org") or "")
                result["country"] = str(geoip.get("country") or "")
        if isinstance(rdap_info, dict):
            creation_date = rdap_info.get("creation_date")
            result["rdap_creation_date"] = creation_date
            result["rdap_age_days"] = _age_days_from_creation(creation_date)
        if isinstance(tls_info, dict):
            result["cert_cn"] = str(tls_info.get("cert_cn") or "")
            result["cert_san"] = list(tls_info.get("cert_san") or [])
            result["cert_issuer"] = str(tls_info.get("cert_issuer") or "")

    scored = score_stage1_http_signals(
        result,
        entity_context=entity_context,
        ordered_entities=ordered_entities,
        config=config,
    )
    result.update(scored)
    if not result["stage1_reasons"] and result["fetch_status"] == "failed":
        result["stage1_reasons"] = "stage1_fetch_failed"
        result["escalate_reason"] = "stage1_fetch_failed"
    return result
