import asyncio
import copy
import logging
import random
from typing import Dict, Any, Optional

import httpx

logger = logging.getLogger(__name__)

# RDAP Bootstrap URL (redirects to the correct authoritative server)
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"
RDAP_RETRY_ATTEMPTS = 3
RDAP_RETRY_BASE_DELAY_S = 0.25
RDAP_RETRY_MAX_DELAY_S = 1.5

_RDAP_CACHE: dict[str, Dict[str, Any]] = {}
_RDAP_IN_FLIGHT: dict[str, asyncio.Task] = {}
_RDAP_METRICS = {
    "success": 0,
    "429": 0,
    "retry_success": 0,
    "retry_exhausted": 0,
    "exception": 0,
    "cache_hit": 0,
}
_rdap_lock: asyncio.Lock | None = None


def _empty_rdap_result() -> Dict[str, Any]:
    return {
        "creation_date": None,
        "registrar": None,
        "registrant_name": None,
        "registrant_country": None,
        "name_servers": None,
        "status": None,
        "raw_rdap": {},
    }


def _get_rdap_lock() -> asyncio.Lock:
    global _rdap_lock
    if _rdap_lock is None:
        _rdap_lock = asyncio.Lock()
    return _rdap_lock


def _record_metric(name: str, increment: int = 1) -> None:
    _RDAP_METRICS[name] = int(_RDAP_METRICS.get(name, 0) or 0) + int(increment)


def reset_rdap_state() -> None:
    _RDAP_CACHE.clear()
    _RDAP_IN_FLIGHT.clear()
    for key in list(_RDAP_METRICS.keys()):
        _RDAP_METRICS[key] = 0


def get_rdap_metrics_snapshot() -> Dict[str, int]:
    return {key: int(value or 0) for key, value in _RDAP_METRICS.items()}


def _format_exception_message(exc: Exception) -> str:
    text = str(exc).strip()
    if text:
        return text
    return exc.__class__.__name__


def _retry_delay_seconds(attempt_index: int) -> float:
    base_delay = min(RDAP_RETRY_MAX_DELAY_S, RDAP_RETRY_BASE_DELAY_S * (2 ** max(0, attempt_index - 1)))
    return float(base_delay + random.uniform(0.0, 0.1))


async def _lookup_rdap_uncached(
    domain: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    local_client = False
    effective_timeout = float(timeout) if timeout is not None else 10.0
    if client is None:
        client = httpx.AsyncClient(timeout=effective_timeout, follow_redirects=True)
        local_client = True

    result = _empty_rdap_result()
    try:
        url = f"{RDAP_BOOTSTRAP_URL}{domain}"
        for attempt in range(1, RDAP_RETRY_ATTEMPTS + 1):
            try:
                response = await client.get(url, timeout=effective_timeout)
            except httpx.RequestError as exc:
                _record_metric("exception")
                message = _format_exception_message(exc)
                if attempt < RDAP_RETRY_ATTEMPTS:
                    delay_s = _retry_delay_seconds(attempt)
                    logger.debug(
                        "RDAP transient exception for %s on attempt %d/%d: %s | retrying in %.2fs",
                        domain,
                        attempt,
                        RDAP_RETRY_ATTEMPTS,
                        message,
                        delay_s,
                    )
                    await asyncio.sleep(delay_s)
                    continue
                _record_metric("retry_exhausted")
                logger.error("RDAP lookup exception for %s: %s", domain, message)
                return result
            except Exception as exc:
                _record_metric("exception")
                logger.error("RDAP lookup exception for %s: %s", domain, _format_exception_message(exc))
                return result

            if response.status_code == 200:
                try:
                    data = response.json()
                except Exception as exc:
                    _record_metric("exception")
                    logger.error("RDAP lookup exception for %s: %s", domain, _format_exception_message(exc))
                    return result
                result["raw_rdap"] = data
                result.update(_parse_rdap_response(data))
                _record_metric("success")
                if attempt > 1:
                    _record_metric("retry_success")
                return result

            if response.status_code == 404:
                logger.debug("RDAP 404 for %s: Domain not found or no RDAP entry.", domain)
                return result

            if response.status_code == 429:
                _record_metric("429")
                logger.warning("RDAP 429 Rate Limit for %s.", domain)
                if attempt < RDAP_RETRY_ATTEMPTS:
                    delay_s = _retry_delay_seconds(attempt)
                    logger.debug(
                        "RDAP 429 backoff for %s on attempt %d/%d: retrying in %.2fs",
                        domain,
                        attempt,
                        RDAP_RETRY_ATTEMPTS,
                        delay_s,
                    )
                    await asyncio.sleep(delay_s)
                    continue
                _record_metric("retry_exhausted")
                return result

            logger.debug("RDAP lookup failed for %s with status %s", domain, response.status_code)
            return result
    finally:
        if local_client:
            await client.aclose()

    return result

async def lookup_rdap(
    domain: str,
    client: Optional[httpx.AsyncClient] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Perform an RDAP lookup for a domain using httpx.
    
    Args:
        domain: The domain name to lookup.
        client: Optional existing httpx.AsyncClient to reuse.
        
    Returns:
        Dictionary containing standardized WHOIS-like data:
        {
            "creation_date": str or None,
            "registrar": str or None,
            "registrant_name": str or None,
            "registrant_country": str or None,
            "name_servers": str or None, # semicolon separated
            "status": str or None,
            "raw_rdap": dict # full JSON response
        }
    """
    normalized_domain = str(domain or "").strip().lower()
    if not normalized_domain:
        return _empty_rdap_result()

    lock = _get_rdap_lock()
    creator = False
    async with lock:
        cached = _RDAP_CACHE.get(normalized_domain)
        if cached is not None:
            _record_metric("cache_hit")
            return copy.deepcopy(cached)
        task = _RDAP_IN_FLIGHT.get(normalized_domain)
        if task is None:
            creator = True
            task = asyncio.create_task(
                _lookup_rdap_uncached(
                    normalized_domain,
                    client=client,
                    timeout=timeout,
                )
            )
            _RDAP_IN_FLIGHT[normalized_domain] = task
        else:
            _record_metric("cache_hit")

    result = await task

    async with lock:
        existing_task = _RDAP_IN_FLIGHT.get(normalized_domain)
        if existing_task is task:
            _RDAP_IN_FLIGHT.pop(normalized_domain, None)
            _RDAP_CACHE[normalized_domain] = copy.deepcopy(result)
        elif creator and normalized_domain not in _RDAP_CACHE:
            _RDAP_CACHE[normalized_domain] = copy.deepcopy(result)

    return copy.deepcopy(result)

def _parse_rdap_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses standard RDAP JSON to extract key fields."""
    parsed = {}
    
    # 1. Creation Date
    # "events": [ { "eventAction": "registration", "eventDate": "..." }, ... ]
    events = data.get("events", [])
    for event in events:
        if event.get("eventAction") == "registration":
            parsed["creation_date"] = event.get("eventDate")
            break
            
    # 2. Registrar & Registrant
    # "entities": [ { "roles": ["registrar"], "vcardArray": [...] }, ... ]
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        
        # Registrar
        if "registrar" in roles:
            # vcardArray is [ "vcard", [ ["version", {}, "text", "4.0"], ["fn", {}, "text", "Name"] ] ]
            parsed["registrar"] = _extract_vcard_fn(entity.get("vcardArray"))
            
        # Registrant
        if "registrant" in roles:
            parsed["registrant_name"] = _extract_vcard_fn(entity.get("vcardArray"))
            parsed["registrant_country"] = _extract_vcard_adr_country(entity.get("vcardArray"))

    # 3. Name Servers
    # "nameservers": [ { "ldhName": "ns1.example.com" }, ... ]
    ns_list = []
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            ns_list.append(name)
    if ns_list:
        parsed["name_servers"] = ";".join(ns_list)

    # 4. Status
    parsed["status"] = ";".join(data.get("status", []))
    
    return parsed

def _extract_vcard_fn(vcard: list) -> Optional[str]:
    """Helper to extract 'fn' (Full Name) from jCard/vCard format."""
    if not vcard or len(vcard) < 2:
        return None
    
    # vcard[1] is the list of properties
    properties = vcard[1]
    for prop in properties:
        # prop is ["name", {params}, type, "value"]
        if prop[0] == "fn":
            return prop[3]
            
    return None

def _extract_vcard_adr_country(vcard: list) -> Optional[str]:
    """Helper to extract country from 'adr' (Address) in jCard/vCard format."""
    if not vcard or len(vcard) < 2:
        return None
        
    properties = vcard[1]
    for prop in properties:
        if prop[0] == "adr":
            # adr value is a list: [pobox, ext, street, locality, region, code, country]
            # We want the last element (country)
            val = prop[3]
            if isinstance(val, list) and len(val) >= 7:
                return val[6]
    return None
