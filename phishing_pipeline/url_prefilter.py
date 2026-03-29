from __future__ import annotations

import csv
import json
import logging
import math
import os
import re
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from multiprocessing import get_context
from urllib.parse import urlparse

import numpy as np
import tldextract
from rapidfuzz.fuzz import ratio
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

from .config import OUTPUT_DIR, ROOT_DIR

logger = logging.getLogger(__name__)
logger.propagate = False
logger.addHandler(logging.NullHandler())

ENTITY_DB_PATH = os.path.join(ROOT_DIR, "data", "entity_hash_db.json")
DEFAULT_AUDIT_PATH = os.path.join(OUTPUT_DIR, "prefilter_audit.csv")

GENERIC_HOST_TOKENS = {"com", "co", "in", "org", "net", "gov", "www"}
COMMON_PHISHING_AFFIXES = (
    "secure",
    "portal",
    "online",
    "login",
    "auth",
    "corp",
    "mail",
    "web",
    "app",
    "pay",
    "my",
)
SHORT_BRAND_AFFIXES = tuple(
    affix for affix in COMMON_PHISHING_AFFIXES
    if affix != "pay"
)

PREFILTER_CPU_CAP = max(1, min(48, os.cpu_count() or 1))
PREFILTER_DEFAULT_BATCH_SIZE = 1024
PREFILTER_MIN_PARALLEL_URLS = 2048

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
_WORKER_PREFILTER_INDEX: PrefilterIndex | None = None


@dataclass(frozen=True)
class CanonicalUrl:
    normalized_url: str
    brand_core: str
    host_tokens: tuple[str, ...]
    path_tokens: tuple[str, ...]
    canonical_text: str
    informative: bool


@dataclass(frozen=True)
class PrefilterEntry:
    entity: str
    legit_domain: str
    canonical: CanonicalUrl


@dataclass(frozen=True)
class PrefilterIndex:
    entries: tuple[PrefilterEntry, ...]
    vectorizer: TfidfVectorizer
    legit_matrix: object
    brand_cores: tuple[str, ...]
    entities: tuple[str, ...]
    legit_domains: tuple[str, ...]


def normalize_url(url: str) -> str:
    text = str(url or "").strip().lower()
    if not text:
        return ""
    if not _SCHEME_RE.match(text):
        text = "https://" + text.lstrip("/")
    return text


def _dedupe_preserve(items: list[str]) -> tuple[str, ...]:
    seen = set()
    ordered = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return tuple(ordered)


def _strip_affixes(label: str) -> str:
    cleaned = str(label or "").strip().lower().strip("-_")
    if not cleaned:
        return ""

    changed = True
    while cleaned and changed:
        changed = False
        for affix in COMMON_PHISHING_AFFIXES:
            if len(cleaned) <= len(affix):
                continue
            if cleaned.startswith(affix):
                cleaned = cleaned[len(affix):].strip("-_")
                changed = True
            if len(cleaned) <= len(affix):
                continue
            if cleaned.endswith(affix):
                cleaned = cleaned[:-len(affix)].strip("-_")
                changed = True
    return cleaned


def _tokenize_label(label: str, keep_len2: bool = False) -> list[str]:
    tokens = []
    for token in _TOKEN_SPLIT_RE.split(label):
        if not token or token in GENERIC_HOST_TOKENS:
            continue
        if len(token) >= 3 or (len(token) == 2 and keep_len2):
            tokens.append(token)
    return tokens


def _allow_len2_token(label: str, stripped: str, registered_label: str) -> bool:
    if len(stripped) != 2:
        return False

    compact_label = "".join(_TOKEN_SPLIT_RE.split(label.lower()))
    if compact_label == stripped:
        return compact_label == registered_label

    return any(
        compact_label == f"{affix}{stripped}" or compact_label == f"{stripped}{affix}"
        for affix in SHORT_BRAND_AFFIXES
    )


def _is_informative_token(token: str, keep_len2: bool = False) -> bool:
    if not token or token in GENERIC_HOST_TOKENS:
        return False
    if token in COMMON_PHISHING_AFFIXES:
        return False
    return len(token) >= 3 or (len(token) == 2 and keep_len2)


def _fallback_host_token(host_labels: list[str], registered_label: str) -> str:
    if not host_labels:
        return ""

    best_token = ""
    best_len = -1
    for label in host_labels:
        compact = "".join(_TOKEN_SPLIT_RE.split(label.lower()))
        if not compact:
            continue
        keep_len2 = label == registered_label
        if not _is_informative_token(compact, keep_len2=keep_len2):
            continue
        if len(compact) > best_len:
            best_token = compact
            best_len = len(compact)
    return best_token


def canonicalize_url(url: str) -> CanonicalUrl:
    normalized_url = normalize_url(url)
    if not normalized_url:
        return CanonicalUrl("", "", tuple(), tuple(), "", False)

    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return CanonicalUrl(normalized_url, "", tuple(), tuple(), "", False)

    extracted = _TLD_EXTRACTOR(hostname)
    registered_label = extracted.domain.lower()
    host_labels = []
    if extracted.subdomain:
        host_labels.extend(
            label for label in extracted.subdomain.split(".")
            if label and label not in GENERIC_HOST_TOKENS
        )
    if registered_label and registered_label not in GENERIC_HOST_TOKENS:
        host_labels.append(registered_label)

    host_tokens: list[str] = []
    registered_tokens: list[str] = []
    for label in host_labels:
        stripped = _strip_affixes(label)
        keep_len2 = _allow_len2_token(label, stripped, registered_label)
        tokens = _tokenize_label(stripped, keep_len2=keep_len2)
        if tokens:
            host_tokens.extend(tokens)
            if label == registered_label:
                registered_tokens.extend(tokens)

    if not host_tokens:
        fallback_token = _fallback_host_token(host_labels, registered_label)
        if fallback_token:
            host_tokens = [fallback_token]
            if registered_label and fallback_token.endswith(registered_label):
                registered_tokens = [fallback_token]

    path_tokens = [
        token for token in _TOKEN_SPLIT_RE.split(parsed.path.lower())
        if token and token not in GENERIC_HOST_TOKENS and len(token) >= 2
    ]

    host_tokens = list(_dedupe_preserve(host_tokens))
    registered_tokens = list(_dedupe_preserve(registered_tokens))
    path_tokens = list(_dedupe_preserve(path_tokens))

    brand_core = ""
    if registered_tokens:
        brand_core = registered_tokens[0]
    elif host_tokens:
        brand_core = host_tokens[0]

    parts = []
    if brand_core:
        parts.extend([brand_core, brand_core])
    if host_tokens:
        host_blob = " ".join(host_tokens)
        parts.extend([host_blob, host_blob])
    if path_tokens:
        parts.append(" ".join(path_tokens))

    canonical_text = " ".join(parts).strip()
    informative = bool(host_tokens and canonical_text)
    return CanonicalUrl(
        normalized_url=normalized_url,
        brand_core=brand_core,
        host_tokens=tuple(host_tokens),
        path_tokens=tuple(path_tokens),
        canonical_text=canonical_text,
        informative=informative,
    )


def _load_entity_db(entity_db_path: str) -> dict:
    with open(entity_db_path, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def get_prefilter_index(entity_db_path: str = ENTITY_DB_PATH) -> PrefilterIndex:
    entity_db = _load_entity_db(entity_db_path)
    entries = []
    texts = []

    for entity, entity_data in entity_db.items():
        for legit_domain in entity_data.get("domains", []):
            canonical = canonicalize_url(legit_domain)
            if not canonical.informative:
                continue
            entries.append(
                PrefilterEntry(
                    entity=entity,
                    legit_domain=legit_domain,
                    canonical=canonical,
                )
            )
            texts.append(canonical.canonical_text)

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5))
    legit_matrix = vectorizer.fit_transform(texts) if texts else None

    return PrefilterIndex(
        entries=tuple(entries),
        vectorizer=vectorizer,
        legit_matrix=legit_matrix,
        brand_cores=tuple(entry.canonical.brand_core for entry in entries),
        entities=tuple(entry.entity for entry in entries),
        legit_domains=tuple(entry.legit_domain for entry in entries),
    )


def _resolve_prefilter_workers(target_count: int, max_workers: int | None = None) -> int:
    if target_count <= 0:
        return 1

    worker_cap = max_workers if max_workers is not None else PREFILTER_CPU_CAP
    worker_cap = max(1, min(worker_cap, PREFILTER_CPU_CAP))
    if target_count < PREFILTER_MIN_PARALLEL_URLS:
        return 1

    suggested_workers = math.ceil(target_count / PREFILTER_DEFAULT_BATCH_SIZE)
    return max(1, min(worker_cap, suggested_workers))


def _resolve_batch_size(target_count: int, worker_count: int, batch_size: int | None = None) -> int:
    if batch_size is not None:
        return max(64, int(batch_size))
    if target_count <= 0:
        return PREFILTER_DEFAULT_BATCH_SIZE

    dynamic_batch = math.ceil(target_count / max(worker_count * 4, 1))
    return max(256, min(4096, dynamic_batch, PREFILTER_DEFAULT_BATCH_SIZE))


def _chunk_targets(target_urls: list[str], batch_size: int) -> list[list[tuple[int, str]]]:
    return [
        list(enumerate(target_urls[start:start + batch_size], start=start))
        for start in range(0, len(target_urls), batch_size)
    ]


def _build_prefilter_result(target_url: str, canonical: CanonicalUrl) -> dict:
    return {
        "target_url": target_url,
        "best_entity": "",
        "best_legit_domain": "",
        "prefilter_score": 0.0,
        "informative": canonical.informative,
    }


def _select_best_match(
    canonical: CanonicalUrl,
    similarities,
    prefilter_index: PrefilterIndex,
) -> tuple[str, str, float]:
    best_score = 0.0
    best_match_index = -1

    for idx, similarity in enumerate(similarities):
        brand_core = prefilter_index.brand_cores[idx]
        if not brand_core:
            continue

        brand_similarity = max(
            ratio(target_token, brand_core) / 100.0
            for target_token in canonical.host_tokens
        )
        adjusted_score = max(float(similarity), 0.0) * (brand_similarity ** 2) * 100.0
        if adjusted_score > best_score:
            best_score = adjusted_score
            best_match_index = idx

    if best_match_index < 0:
        return "", "", 0.0

    return (
        prefilter_index.entities[best_match_index],
        prefilter_index.legit_domains[best_match_index],
        round(best_score, 4),
    )


def _score_prefilter_batch(
    indexed_urls: list[tuple[int, str]],
    prefilter_index: PrefilterIndex | None = None,
) -> list[tuple[int, dict]]:
    index = prefilter_index or _WORKER_PREFILTER_INDEX or get_prefilter_index()
    batch_results = []
    informative_rows = []

    for absolute_index, target_url in indexed_urls:
        canonical = canonicalize_url(target_url)
        result = _build_prefilter_result(target_url, canonical)
        batch_results.append([absolute_index, result, canonical])
        if canonical.informative and index.entries and index.legit_matrix is not None:
            informative_rows.append((len(batch_results) - 1, canonical))

    if informative_rows:
        texts = [canonical.canonical_text for _, canonical in informative_rows]
        target_matrix = index.vectorizer.transform(texts)
        similarity_matrix = np.asarray(linear_kernel(target_matrix, index.legit_matrix))

        for matrix_row_index, (result_index, canonical) in enumerate(informative_rows):
            best_entity, best_legit_domain, best_score = _select_best_match(
                canonical,
                similarity_matrix[matrix_row_index],
                index,
            )
            batch_results[result_index][1].update(
                {
                    "best_entity": best_entity,
                    "best_legit_domain": best_legit_domain,
                    "prefilter_score": best_score,
                }
            )

    return [(absolute_index, result) for absolute_index, result, _ in batch_results]


def _init_prefilter_worker(prefilter_index: PrefilterIndex) -> None:
    global _WORKER_PREFILTER_INDEX
    _WORKER_PREFILTER_INDEX = prefilter_index


def _score_target_urls_parallel(
    target_urls: list[str],
    prefilter_index: PrefilterIndex,
    max_workers: int | None = None,
    batch_size: int | None = None,
) -> list[dict]:
    if not target_urls:
        return []

    worker_count = _resolve_prefilter_workers(len(target_urls), max_workers=max_workers)
    resolved_batch_size = _resolve_batch_size(
        len(target_urls),
        worker_count=worker_count,
        batch_size=batch_size,
    )
    batches = _chunk_targets(target_urls, resolved_batch_size)

    if worker_count == 1 or len(batches) == 1:
        ordered_results = [None] * len(target_urls)
        for batch in batches:
            for absolute_index, row in _score_prefilter_batch(batch, prefilter_index=prefilter_index):
                ordered_results[absolute_index] = row
        return ordered_results

    logger.info(
        "Running parallel prefilter scoring with %d workers and batch size %d for %d URLs",
        worker_count,
        resolved_batch_size,
        len(target_urls),
    )

    ordered_results = [None] * len(target_urls)
    try:
        with ProcessPoolExecutor(
            max_workers=worker_count,
            mp_context=get_context("spawn"),
            initializer=_init_prefilter_worker,
            initargs=(prefilter_index,),
        ) as executor:
            future_to_batch = {
                executor.submit(_score_prefilter_batch, batch): batch
                for batch in batches
            }

            for future in as_completed(future_to_batch):
                batch = future_to_batch[future]
                try:
                    scored_rows = future.result()
                except Exception as exc:
                    logger.warning(
                        "Parallel prefilter batch failed; retrying sequentially. Batch start=%d size=%d error=%s",
                        batch[0][0],
                        len(batch),
                        exc,
                    )
                    scored_rows = _score_prefilter_batch(batch, prefilter_index=prefilter_index)

                for absolute_index, row in scored_rows:
                    ordered_results[absolute_index] = row
    except Exception as exc:
        logger.warning(
            "ProcessPool prefilter executor failed; falling back to threaded mode: %s",
            exc,
        )
        ordered_results = [None] * len(target_urls)
        try:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_batch = {
                    executor.submit(_score_prefilter_batch, batch, prefilter_index): batch
                    for batch in batches
                }
                for future in as_completed(future_to_batch):
                    batch = future_to_batch[future]
                    try:
                        scored_rows = future.result()
                    except Exception as thread_exc:
                        logger.warning(
                            "Threaded prefilter batch failed; retrying sequentially. Batch start=%d size=%d error=%s",
                            batch[0][0],
                            len(batch),
                            thread_exc,
                        )
                        scored_rows = _score_prefilter_batch(batch, prefilter_index=prefilter_index)

                    for absolute_index, row in scored_rows:
                        ordered_results[absolute_index] = row
        except Exception as thread_executor_exc:
            logger.warning(
                "Threaded prefilter executor failed; falling back to sequential mode: %s",
                thread_executor_exc,
            )
            ordered_results = [None] * len(target_urls)
            for batch in batches:
                for absolute_index, row in _score_prefilter_batch(batch, prefilter_index=prefilter_index):
                    ordered_results[absolute_index] = row

    missing_indexes = [index for index, row in enumerate(ordered_results) if row is None]
    if missing_indexes:
        logger.warning(
            "Recovered %d missing prefilter rows sequentially after parallel scoring.",
            len(missing_indexes),
        )
        recovery_batch = [(index, target_urls[index]) for index in missing_indexes]
        for absolute_index, row in _score_prefilter_batch(
            recovery_batch,
            prefilter_index=prefilter_index,
        ):
            ordered_results[absolute_index] = row

    return ordered_results


def score_target_url(
    target_url: str,
    prefilter_index: PrefilterIndex | None = None,
) -> dict:
    prefilter_index = prefilter_index or get_prefilter_index()
    return _score_prefilter_batch(
        [(0, target_url)],
        prefilter_index=prefilter_index,
    )[0][1]


def prefilter_target_urls(
    target_urls: list[str],
    threshold: float = 10.0,
    prefilter_index: PrefilterIndex | None = None,
    max_workers: int | None = None,
    batch_size: int | None = None,
) -> tuple[list[str], list[dict]]:
    prefilter_index = prefilter_index or get_prefilter_index()
    scored_rows = _score_target_urls_parallel(
        target_urls,
        prefilter_index=prefilter_index,
        max_workers=max_workers,
        batch_size=batch_size,
    )

    accepted_urls = []
    audit_rows = []
    for row in scored_rows:
        decision = "accepted" if row["prefilter_score"] >= threshold else "rejected"
        audit_rows.append(
            {
                "target_url": row["target_url"],
                "best_entity": row["best_entity"],
                "best_legit_domain": row["best_legit_domain"],
                "prefilter_score": row["prefilter_score"],
                "decision": decision,
            }
        )
        if decision == "accepted":
            accepted_urls.append(row["target_url"])

    return accepted_urls, audit_rows


def write_prefilter_audit(
    audit_rows: list[dict],
    output_path: str = DEFAULT_AUDIT_PATH,
) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "target_url",
                "best_entity",
                "best_legit_domain",
                "prefilter_score",
                "decision",
            ],
        )
        writer.writeheader()
        writer.writerows(audit_rows)


def filter_urls_for_hashing(
    target_urls: list[str],
    threshold: float = 10.0,
    audit_output_path: str = DEFAULT_AUDIT_PATH,
    entity_db_path: str = ENTITY_DB_PATH,
    max_workers: int | None = None,
    batch_size: int | None = None,
) -> tuple[list[str], list[dict]]:
    prefilter_index = get_prefilter_index(entity_db_path)
    accepted_urls, audit_rows = prefilter_target_urls(
        target_urls,
        threshold=threshold,
        prefilter_index=prefilter_index,
        max_workers=max_workers,
        batch_size=batch_size,
    )
    write_prefilter_audit(audit_rows, output_path=audit_output_path)
    return accepted_urls, audit_rows
