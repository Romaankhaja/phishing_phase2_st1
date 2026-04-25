"""Whitelist-aware Stage 0 lexical scoring.

This module is adapted from the attached Stage-0 implementation and is kept
independent from the hash/scoring pipeline so Stage 0 lexical decisions can be
swapped without changing downstream scoring or classification code.
"""

from __future__ import annotations

import math
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import tldextract
from rapidfuzz import distance, process as rapidfuzz_process


PHISHING_KEYWORDS = (
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "wallet",
    "signin",
)
CUSTOM_PUBLIC_SUFFIXES = ("bank.in",)
WHITELIST_SIMILARITY_THRESHOLD = 0.93
FUZZY_BRAND_EVIDENCE_THRESHOLD = 0.93
SCORE_THRESHOLD = 40

SHORT_BRAND_SUFFIX_HINTS = frozenset(
    {
        "account",
        "bank",
        "card",
        "cards",
        "gov",
        "kyc",
        "login",
        "netbanking",
        "online",
        "pay",
        "payment",
        "payments",
        "portal",
        "reward",
        "rewards",
        "secure",
        "service",
        "sewa",
        "upi",
        "verification",
        "verify",
        "wallet",
    }
)

GENERIC_TOKENS = frozenset(
    {
        "account",
        "accounts",
        "api",
        "auth",
        "authority",
        "bank",
        "books",
        "branch",
        "care",
        "card",
        "cards",
        "centre",
        "center",
        "census",
        "co",
        "cloud",
        "com",
        "computer",
        "contents",
        "content",
        "corp",
        "corporate",
        "corporation",
        "dev",
        "department",
        "digital",
        "direct",
        "education",
        "election",
        "exam",
        "exams",
        "express",
        "finance",
        "financial",
        "foundation",
        "fund",
        "funds",
        "gov",
        "group",
        "help",
        "home",
        "health",
        "homeloans",
        "in",
        "identification",
        "india",
        "indian",
        "insurance",
        "institute",
        "informatics",
        "intranet",
        "invest",
        "investment",
        "kerala",
        "language",
        "life",
        "library",
        "limited",
        "load",
        "login",
        "mail",
        "management",
        "market",
        "medical",
        "mf",
        "mutual",
        "national",
        "net",
        "nic",
        "official",
        "online",
        "org",
        "payments",
        "portal",
        "prod",
        "research",
        "reserve",
        "registration",
        "retail",
        "sciences",
        "securelogin",
        "service",
        "services",
        "shop",
        "space",
        "state",
        "support",
        "secure",
        "signin",
        "store",
        "system",
        "systems",
        "test",
        "tourism",
        "tracker",
        "uat",
        "unique",
        "update",
        "verify",
        "wallet",
        "web",
        "bharat",
        "coal",
        "catering",
        "civil",
        "first",
        "income",
        "punjab",
        "rajasthan",
        "railway",
        "chandigarh",
        "odisha",
        "assam",
        "gujarat",
        "maharashtra",
        "tamilnadu",
        "karnataka",
        "telangana",
        "andhra",
        "bihar",
        "delhi",
        "haryana",
        "westbengal",
        "bengal",
        "organisation",
        "organization",
        "board",
        "commission",
        "agency",
        "committee",
        "council",
        "ministry",
        "bhavan",
        "cats",
        "sac",
        "sedal",
        "pord",
        "sparrow",
    }
)

_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=os.path.join(tempfile.gettempdir(), "phishing-ml-stage0-tldextract"),
    suffix_list_urls=None,
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


@dataclass(frozen=True)
class BrandIndex:
    """Prepared Stage-0 keyword inventory."""

    brand_tokens: tuple[str, ...]
    keyword_universe: tuple[str, ...]
    phishing_keywords: tuple[str, ...] = PHISHING_KEYWORDS


@dataclass(frozen=True)
class Stage0LexicalEntity:
    """Per-entity lexical inventory aligned with entity_hash_db indexes."""

    name: str
    domains: tuple[str, ...]
    whitelist_domains: tuple[str, ...]
    brand_index: BrandIndex

    @property
    def brand_tokens(self) -> frozenset[str]:
        return frozenset(self.brand_index.brand_tokens)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value)


def _ensure_url(value: Any) -> str:
    text = _stringify(value).strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return text
    return f"https://{text}"


def extract_hostname(value: Any) -> str:
    split = urlsplit(_ensure_url(value))
    return (split.hostname or "").strip(".").lower()


def registrable_domain(value: Any) -> str:
    hostname = extract_hostname(value)
    if not hostname:
        return ""

    labels = [label for label in hostname.split(".") if label]
    for suffix in CUSTOM_PUBLIC_SUFFIXES:
        suffix_labels = suffix.split(".")
        if labels[-len(suffix_labels) :] == suffix_labels and len(labels) > len(suffix_labels):
            return ".".join(labels[-(len(suffix_labels) + 1) :])

    extracted = _EXTRACTOR(hostname)
    if extracted.top_domain_under_public_suffix:
        return extracted.top_domain_under_public_suffix
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname


def split_registrable_domain(value: Any) -> tuple[str, str]:
    domain = registrable_domain(value)
    if not domain:
        return "", ""

    labels = domain.split(".")
    if len(labels) <= 1:
        return domain, ""

    label = labels[0]
    suffix = ".".join(labels[1:])
    if domain.endswith(".bank.in"):
        suffix = "bank.in"
    return label, suffix


def flatten_text(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", _stringify(value).lower())


def extract_abbreviations(text: Any) -> set[str]:
    tokens: set[str] = set()
    for match in re.findall(r"\(([A-Za-z0-9]{2,})\)", _stringify(text)):
        tokens.add(match.lower())
    return tokens


def _add_token(bucket: set[str], value: Any, *, min_length: int) -> None:
    token = flatten_text(value)
    if len(token) < min_length or token in GENERIC_TOKENS:
        return
    bucket.add(token)


def build_brand_index(records: Iterable[Mapping[str, Any]]) -> BrandIndex:
    """Derive brand tokens from whitelist domains and CSE names."""

    brand_tokens: set[str] = set()

    for record in records:
        domain_value = (
            _stringify(record.get("domains"))
            or _stringify(record.get("domain"))
            or _stringify(record.get("domain_name"))
        )
        cse_name = (
            _stringify(record.get("cse"))
            or _stringify(record.get("cse_name"))
            or _stringify(record.get("brand"))
            or _stringify(record.get("name"))
        )

        reg_label, _ = split_registrable_domain(domain_value)
        _add_token(brand_tokens, reg_label, min_length=3)

        for abbreviation in extract_abbreviations(cse_name):
            _add_token(brand_tokens, abbreviation, min_length=3)

        for word in re.findall(r"[A-Za-z0-9]{3,}", cse_name.lower()):
            _add_token(brand_tokens, word, min_length=4)

    keyword_universe = tuple(sorted(set(PHISHING_KEYWORDS) | brand_tokens))
    return BrandIndex(
        brand_tokens=tuple(sorted(brand_tokens)),
        keyword_universe=keyword_universe,
    )


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    text_length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / text_length
        entropy -= probability * math.log2(probability)
    return entropy


def _length_component(domain_label: str) -> float:
    if len(domain_label) <= 8:
        return 4.0
    if len(domain_label) <= 14:
        return 10.0
    if len(domain_label) <= 20:
        return 18.0
    return 25.0


def _entropy_component(domain_label: str) -> float:
    entropy = _shannon_entropy(domain_label)
    return min(25.0, max(0.0, (entropy / 4.5) * 25.0))


def _keyword_component(phishing_hits: list[str], brand_hits: list[str]) -> float:
    total_hits = len(phishing_hits) + len(brand_hits)
    if total_hits == 0:
        return 0.0
    return min(25.0, 8.0 + (total_hits - 1) * 6.0)


def _similarity_component(domain_label: str, keyword_universe: Iterable[str]) -> tuple[float, float]:
    label_length = len(domain_label)
    candidates = [
        keyword
        for keyword in keyword_universe
        if abs(len(keyword) - label_length) <= 6
    ]
    if not candidates:
        return 0.0, 0.0

    best_match = rapidfuzz_process.extractOne(
        domain_label,
        candidates,
        scorer=distance.JaroWinkler.normalized_similarity,
    )
    best_ratio = float(best_match[1]) if best_match is not None else 0.0
    return min(25.0, best_ratio * 25.0), best_ratio


def _domain_parts(domain_label: str) -> list[str]:
    return [
        flatten_text(part)
        for part in re.split(r"[^a-z0-9]+", domain_label.lower())
        if flatten_text(part)
    ]


def _token_matches_domain(token: str, domain_parts: Iterable[str]) -> bool:
    parts = list(domain_parts)
    for index, part in enumerate(parts):
        if part == token:
            if len(token) > 4:
                return True
            other_parts = parts[:index] + parts[index + 1 :]
            if any(
                other.startswith(keyword) or other.startswith(hint)
                for other in other_parts
                for keyword in PHISHING_KEYWORDS
                for hint in SHORT_BRAND_SUFFIX_HINTS
            ):
                return True
            continue

        if len(token) <= 4 and part.startswith(token):
            remainder = part[len(token) :]
            if any(remainder.startswith(keyword) for keyword in PHISHING_KEYWORDS):
                return True
            if any(remainder.startswith(hint) for hint in SHORT_BRAND_SUFFIX_HINTS):
                return True

        if len(token) > 4 and (part.startswith(token) or part.endswith(token)):
            return True

    return False


def _brand_hits(domain_label: str, brand_tokens: Iterable[str]) -> list[str]:
    domain_parts = _domain_parts(domain_label)
    return [
        token
        for token in brand_tokens
        if _token_matches_domain(token, domain_parts)
    ]


def score_domain(domain: str, brand_index: BrandIndex) -> dict[str, Any]:
    """Score a normalized domain for Stage-0 lexical shortlisting."""

    domain = _stringify(domain).strip().lower()
    domain_label, _ = split_registrable_domain(domain)
    if not domain_label:
        domain_label = extract_hostname(domain).split(".", 1)[0]

    flat_label = flatten_text(domain_label)
    if not flat_label:
        return {
            "final_score": 0,
            "risk": "low",
            "features": {
                "label_length": 0,
                "entropy": 0.0,
                "keyword_presence": False,
                "phishing_keyword_hits": [],
                "brand_hits": [],
                "keyword_similarity_score": 0.0,
            },
        }

    phishing_hits = [keyword for keyword in PHISHING_KEYWORDS if keyword in flat_label]
    suffix_hint_hits = [hint for hint in SHORT_BRAND_SUFFIX_HINTS if hint in flat_label]
    risk_keyword_hits = sorted(set(phishing_hits) | set(suffix_hint_hits))
    brand_hits = _brand_hits(domain_label, brand_index.brand_tokens)

    length_component = _length_component(domain_label)
    entropy_component = _entropy_component(domain_label)
    keyword_component = _keyword_component(risk_keyword_hits, brand_hits)
    similarity_component, keyword_similarity_score = _similarity_component(
        flat_label,
        brand_index.brand_tokens,
    )
    has_fuzzy_brand_evidence = bool(risk_keyword_hits) and (
        keyword_similarity_score >= FUZZY_BRAND_EVIDENCE_THRESHOLD
    )
    has_brand_evidence = bool(brand_hits) or has_fuzzy_brand_evidence
    structural_component = 0.0
    if has_brand_evidence:
        structural_component = (length_component * 0.35) + (entropy_component * 0.35)
    phishing_component = 0.0
    if has_brand_evidence and risk_keyword_hits:
        phishing_component = min(12.0, 6.0 + (len(risk_keyword_hits) - 1) * 3.0)
    brand_component = 0.0
    if brand_hits:
        brand_component = min(32.0, 18.0 + (len(brand_hits) - 1) * 6.0)
    elif has_fuzzy_brand_evidence:
        brand_component = 12.0

    final_score = int(
        round(
            structural_component
            + phishing_component
            + brand_component
            + similarity_component
        )
    )
    final_score = max(0, min(100, final_score))

    if final_score >= 70:
        risk = "high"
    elif final_score >= 40:
        risk = "medium"
    else:
        risk = "low"

    return {
        "final_score": final_score,
        "risk": risk,
        "features": {
            "label_length": len(domain_label),
            "entropy": round(_shannon_entropy(domain_label), 4),
                "keyword_presence": bool(risk_keyword_hits or brand_hits),
                "phishing_keyword_hits": risk_keyword_hits,
            "brand_hits": sorted(set(brand_hits)),
            "keyword_similarity_score": round(keyword_similarity_score, 4),
        },
    }


def normalize_domain(domain: Any) -> str:
    """Lowercase, remove http/https, remove paths, return clean domain."""
    if pd.isna(domain):
        return ""

    normalized = str(domain).lower().strip()
    normalized = re.sub(r"^https?://", "", normalized)
    return normalized.split("/")[0]


def similarity_score(domain: str, whitelist_domains: Sequence[str]) -> float:
    """Jaro-Winkler similarity against whitelist domains."""
    if not whitelist_domains:
        return 0.0

    best_match = rapidfuzz_process.extractOne(
        domain,
        whitelist_domains,
        scorer=distance.JaroWinkler.normalized_similarity,
    )
    if best_match is None:
        return 0.0
    return float(best_match[1])


def _similarity_score_with_match(domain: str, whitelist_domains: Sequence[str]) -> tuple[float, str]:
    if not whitelist_domains:
        return 0.0, ""

    best_match = rapidfuzz_process.extractOne(
        domain,
        whitelist_domains,
        scorer=distance.JaroWinkler.normalized_similarity,
    )
    if best_match is None:
        return 0.0, ""
    return float(best_match[1]), str(best_match[0] or "")


def classify_domain(domain: Any, entity: Stage0LexicalEntity) -> dict[str, Any]:
    """Classify one domain against one aligned entity using the new Stage-0 rules."""

    normalized_domain = normalize_domain(domain)
    if not normalized_domain:
        return _build_non_lexical_result(match_reason="empty_or_invalid_domain")

    try:
        max_similarity, best_matching_domain = _similarity_score_with_match(
            normalized_domain,
            entity.whitelist_domains,
        )
        score_result = score_domain(normalized_domain, entity.brand_index)
        features = score_result["features"]
        final_score = int(score_result["final_score"])
    except Exception:
        return _build_non_lexical_result(
            normalized_domain=normalized_domain,
            match_reason="classification_error",
        )

    has_fuzzy_brand_evidence = bool(features["phishing_keyword_hits"]) and (
        float(features["keyword_similarity_score"]) >= WHITELIST_SIMILARITY_THRESHOLD
    )
    has_brand_evidence = bool(features["brand_hits"]) or has_fuzzy_brand_evidence

    if max_similarity >= WHITELIST_SIMILARITY_THRESHOLD:
        label = "lexical"
        match_reason = "whitelist_similarity_match"
    elif final_score >= SCORE_THRESHOLD and has_brand_evidence:
        label = "lexical"
        match_reason = "score_threshold_match"
    else:
        label = "non_lexical"
        match_reason = "no_match"

    return {
        "normalized_domain": normalized_domain,
        "similarity_score": max_similarity,
        "best_matching_domain": best_matching_domain,
        "match_reason": match_reason,
        "label": label,
        "final_score": final_score,
        "risk": score_result["risk"],
        "label_length": features["label_length"],
        "entropy": features["entropy"],
        "keyword_presence": features["keyword_presence"],
        "phishing_keyword_hits": list(features["phishing_keyword_hits"]),
        "brand_hits": list(features["brand_hits"]),
        "keyword_similarity_score": float(features["keyword_similarity_score"]),
        "has_brand_evidence": has_brand_evidence,
        "has_fuzzy_brand_evidence": has_fuzzy_brand_evidence,
    }


def _build_non_lexical_result(normalized_domain: str = "", match_reason: str = "no_match") -> dict[str, Any]:
    return {
        "normalized_domain": normalized_domain,
        "similarity_score": 0.0,
        "best_matching_domain": "",
        "match_reason": match_reason,
        "label": "non_lexical",
        "final_score": 0,
        "risk": "low",
        "label_length": 0,
        "entropy": 0.0,
        "keyword_presence": False,
        "phishing_keyword_hits": [],
        "brand_hits": [],
        "keyword_similarity_score": 0.0,
        "has_brand_evidence": False,
        "has_fuzzy_brand_evidence": False,
    }


def build_entity_cache(entity_index: Mapping[str, Any]) -> tuple[Stage0LexicalEntity, ...]:
    """Build per-entity lexical cache from the current entity_hash_db index."""

    names = list(entity_index.get("names", []))
    domains_by_entity = list(entity_index.get("domains", []))
    keyword_sets = list(entity_index.get("kw_sets", []))
    entities: list[Stage0LexicalEntity] = []

    for idx, name in enumerate(names):
        domains = tuple(str(domain or "").strip().lower() for domain in domains_by_entity[idx])
        whitelist_domains = tuple(
            sorted(
                {
                    normalize_domain(domain)
                    for domain in domains
                    if normalize_domain(domain)
                }
            )
        )
        records: list[dict[str, Any]] = [
            {"domain": domain, "cse": name}
            for domain in domains
            if domain
        ]
        for keyword in (keyword_sets[idx] if idx < len(keyword_sets) else ()):
            records.append({"domain": "", "cse": keyword})

        entities.append(
            Stage0LexicalEntity(
                name=str(name or ""),
                domains=domains,
                whitelist_domains=whitelist_domains,
                brand_index=build_brand_index(records),
            )
        )

    return tuple(entities)


def label_similarity_score(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    try:
        return float(distance.JaroWinkler.normalized_similarity(str(text_a), str(text_b)))
    except Exception:
        return 0.0


def evaluate_prefetch_lexical_bundle(
    *,
    normalized_url: str,
    target_domain: str,
    lexical_cache: Sequence[Stage0LexicalEntity],
    top_k: int | None = None,
) -> dict[str, Any]:
    """Return the current pipeline's expected lexical metric bundle."""

    cache = tuple(lexical_cache or ())
    n_entities = len(cache)
    if n_entities == 0:
        empty_scores = np.zeros(0, dtype="float64")
        empty_mask = np.zeros(0, dtype=bool)
        return {
            "hybrid_metrics": {
                "lexical_scores": empty_scores,
                "jw_scores": empty_scores,
                "token_scores": empty_scores,
                "skeleton_scores": empty_scores,
                "host_scores": empty_scores,
                "lexical_rule_hit": empty_mask,
                "brand_token_hit": empty_mask,
                "generic_token_only_match": empty_mask,
                "candidate_mask": empty_mask,
                "candidate_reasons": [],
                "best_matching_domains": [],
                "stage0_metadata": [],
            },
        }

    lexical_scores = np.zeros(n_entities, dtype="float64")
    jw_scores = np.zeros(n_entities, dtype="float64")
    token_scores = np.zeros(n_entities, dtype="float64")
    skeleton_scores = np.zeros(n_entities, dtype="float64")
    host_scores = np.zeros(n_entities, dtype="float64")
    lexical_rule_hit = np.zeros(n_entities, dtype=bool)
    brand_token_hit = np.zeros(n_entities, dtype=bool)
    generic_token_only_match = np.zeros(n_entities, dtype=bool)
    candidate_mask = np.zeros(n_entities, dtype=bool)
    candidate_reasons = [""] * n_entities
    best_matching_domains = [""] * n_entities
    stage0_metadata: list[dict[str, Any]] = []

    normalized_domain = normalize_domain(target_domain or normalized_url)

    for idx, entity in enumerate(cache):
        result = classify_domain(normalized_domain, entity)
        similarity = float(result.get("similarity_score", 0.0) or 0.0)
        final_score = int(result.get("final_score", 0) or 0)
        keyword_similarity = float(result.get("keyword_similarity_score", 0.0) or 0.0)
        is_lexical = str(result.get("label", "")).strip().lower() == "lexical"
        has_brand_evidence = bool(result.get("has_brand_evidence", False))

        lexical_scores[idx] = max(similarity, final_score / 100.0)
        jw_scores[idx] = similarity
        token_scores[idx] = keyword_similarity
        skeleton_scores[idx] = similarity
        host_scores[idx] = similarity
        lexical_rule_hit[idx] = is_lexical
        brand_token_hit[idx] = bool(is_lexical and has_brand_evidence)
        best_matching_domains[idx] = str(result.get("best_matching_domain", "") or "")

        if is_lexical:
            candidate_mask[idx] = True
            candidate_reasons[idx] = str(result.get("match_reason", "") or "stage0_lexical_match")

        stage0_metadata.append(result)

    if not candidate_mask.any():
        fallback_count = 10 if top_k is None else max(1, int(top_k))
        fallback_count = min(fallback_count, n_entities)
        if fallback_count > 0:
            fallback_indices = np.argsort(lexical_scores)[-fallback_count:]
            candidate_mask[fallback_indices] = True
            for idx in fallback_indices:
                reason = candidate_reasons[idx]
                candidate_reasons[idx] = f"{reason}|fallback_top_k".strip("|")

    return {
        "hybrid_metrics": {
            "lexical_scores": lexical_scores,
            "jw_scores": jw_scores,
            "token_scores": token_scores,
            "skeleton_scores": skeleton_scores,
            "host_scores": host_scores,
            "lexical_rule_hit": lexical_rule_hit,
            "brand_token_hit": brand_token_hit,
            "generic_token_only_match": generic_token_only_match,
            "candidate_mask": candidate_mask,
            "candidate_reasons": candidate_reasons,
            "best_matching_domains": best_matching_domains,
            "stage0_metadata": stage0_metadata,
        },
    }
