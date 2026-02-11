import httpx
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# RDAP Bootstrap URL (redirects to the correct authoritative server)
RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/"

async def lookup_rdap(domain: str, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
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
    local_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        local_client = True
        
    result = {
        "creation_date": None,
        "registrar": None,
        "registrant_name": None,
        "registrant_country": None,
        "name_servers": None,
        "status": None,
        "raw_rdap": {}
    }
    
    try:
        url = f"{RDAP_BOOTSTRAP_URL}{domain}"
        response = await client.get(url)
        
        if response.status_code == 200:
            data = response.json()
            result["raw_rdap"] = data
            result.update(_parse_rdap_response(data))
        elif response.status_code == 404:
            logger.debug(f"RDAP 404 for {domain}: Domain not found or no RDAP entry.")
        elif response.status_code == 429:
             logger.warning(f"RDAP 429 Rate Limit for {domain}.")
        else:
            logger.debug(f"RDAP lookup failed for {domain} with status {response.status_code}")
            
    except Exception as e:
        logger.error(f"RDAP lookup exception for {domain}: {e}")
    finally:
        if local_client:
            await client.aclose()
            
    return result

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
