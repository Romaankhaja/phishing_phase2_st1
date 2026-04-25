"""Stage 1 HTTP fetch, redirect, HTML signal, and enrichment pipeline."""

from __future__ import annotations

from . import _comparison_legacy as _legacy


clean_domain = _legacy.clean_domain
is_block_page = _legacy.is_block_page

_AdaptiveFetchLimiter = _legacy._AdaptiveFetchLimiter
_PerHostLimiter = _legacy._PerHostLimiter
_Stage1PerHostLimiter = _legacy._Stage1PerHostLimiter
_compute_stage1_downshift = _legacy._compute_stage1_downshift
_compute_stage1_fetch_limit_adjustment = _legacy._compute_stage1_fetch_limit_adjustment
_classify_fetch_exception = _legacy._classify_fetch_exception
_build_fetch_failure_payload = _legacy._build_fetch_failure_payload
_handle_stage1_fetch_payload = _legacy._handle_stage1_fetch_payload
_fetch_url_payload = _legacy._fetch_url_payload
_analyze_stage1_http_candidates = _legacy._analyze_stage1_http_candidates
_analyze_stage1_http_candidates_pipelined = _legacy._analyze_stage1_http_candidates_pipelined
_run_stage1_http_pipeline = _legacy._run_stage1_http_pipeline
_stage1_parse_payload_sync = _legacy._stage1_parse_payload_sync
_stage1_score_payload_sync = _legacy._stage1_score_payload_sync
_stage1_cpu_pass_sync = _legacy._stage1_cpu_pass_sync
_stage1_fetch_worker = _legacy._stage1_fetch_worker
_stage1_parse_worker = _legacy._stage1_parse_worker
_stage1_score_worker = _legacy._stage1_score_worker
_stage1_enrich_worker = _legacy._stage1_enrich_worker
_stage1_finalize_worker = _legacy._stage1_finalize_worker
_dns_gate_lexical_miss_records = _legacy._dns_gate_lexical_miss_records
_resolve_dns_answers = _legacy._resolve_dns_answers


def __getattr__(name: str):
    return getattr(_legacy, name)
