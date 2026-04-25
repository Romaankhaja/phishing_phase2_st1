"""Stage 2 hashing, browser-render fingerprinting, and hash evidence scoring."""

from __future__ import annotations

from . import _comparison_legacy as _legacy
from .similarity_hashing import (
    SIMHASH_BITS,
    best_similarity_against_set,
    canonicalize_ssl_identity,
    compute_domain_simhash,
    compute_image_phash,
    compute_simhash,
    compute_ssl_simhash,
    hamming_distance,
    normalized_hamming_similarity,
    normalize_domain_for_simhash,
)


sha256_text = _legacy.sha256_text
phash_distance = _legacy.phash_distance
favicon_hash_async = _legacy.favicon_hash_async
favicon_hash = _legacy.favicon_hash
get_ssl_hash_async = _legacy.get_ssl_hash_async
get_ssl_hash = _legacy.get_ssl_hash

_favicon_hash_sync = _legacy._favicon_hash_sync
_route_nonessential_requests = _legacy._route_nonessential_requests
_render_hash_payload_on_page = _legacy._render_hash_payload_on_page
_enrich_render_payload_for_hashing = _legacy._enrich_render_payload_for_hashing
_finalize_scored_hash_payload = _legacy._finalize_scored_hash_payload
_validate_ray_hash_finalize_transport = _legacy._validate_ray_hash_finalize_transport
_compute_hash_fetch_adjustment = _legacy._compute_hash_fetch_adjustment
_get_hash_runtime_resource_snapshot = _legacy._get_hash_runtime_resource_snapshot
_build_stage2_hash_export_row = _legacy._build_stage2_hash_export_row
_write_stage2_hash_exports = _legacy._write_stage2_hash_exports
_run_hashing_shortlist_streaming_concurrent = _legacy._run_hashing_shortlist_streaming_concurrent
run_hashing_shortlist_streaming = _legacy.run_hashing_shortlist_streaming
run_hashing_shortlist = _legacy.run_hashing_shortlist
run_hashing_shortlist_async = _legacy.run_hashing_shortlist_async


def __getattr__(name: str):
    return getattr(_legacy, name)
