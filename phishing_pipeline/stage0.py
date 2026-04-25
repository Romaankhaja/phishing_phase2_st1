"""Stage 0 lexical filtering and domain-similarity evaluation."""

from __future__ import annotations

from . import _comparison_legacy as _comparison
from . import _shortlisting_legacy as _shortlisting
from . import stage0_new_lexical as _new_lexical


normalize_url = _comparison.normalize_url
normalize_shortlist_url = _shortlisting.normalize_url
get_clean_parts = _shortlisting.get_clean_parts
get_primary_part = _shortlisting.get_primary_part
is_similar_advanced = _shortlisting.is_similar_advanced

domain_similarity = _comparison.domain_similarity
typosquat_similarity = _comparison.typosquat_similarity
score_all_entities = _comparison.score_all_entities

_load_entity_db = _comparison._load_entity_db
_TargetLexicalFeatures = _comparison._TargetLexicalFeatures
_prepare_target_lexical_features = _comparison._prepare_target_lexical_features
_evaluate_prefetch_lexical_bundle = _comparison._evaluate_prefetch_lexical_bundle
_compute_prefetch_lexical_state_from_normalized_url = _comparison._compute_prefetch_lexical_state_from_normalized_url
_compute_prefetch_lexical_state_batch = _comparison._compute_prefetch_lexical_state_batch
_compute_prefetch_lexical_state = _comparison._compute_prefetch_lexical_state
_compute_stage0_prefetch_metrics_parallel = _comparison._compute_stage0_prefetch_metrics_parallel
_compute_stage0_prefetch_metrics_parallel_streaming = _comparison._compute_stage0_prefetch_metrics_parallel_streaming
_build_entity_index = _comparison._build_entity_index
_build_lexical_cache = _comparison._build_lexical_cache
_build_stage0_debug_rows = _comparison._build_stage0_debug_rows
_write_stage0_debug_csv = _comparison._write_stage0_debug_csv
_passes_lexical_gate = _comparison._passes_lexical_gate

BrandIndex = _new_lexical.BrandIndex
Stage0LexicalEntity = _new_lexical.Stage0LexicalEntity
build_brand_index = _new_lexical.build_brand_index
score_domain = _new_lexical.score_domain
classify_domain = _new_lexical.classify_domain
registrable_domain = _new_lexical.registrable_domain
split_registrable_domain = _new_lexical.split_registrable_domain
flatten_text = _new_lexical.flatten_text
normalize_domain = _new_lexical.normalize_domain
similarity_score = _new_lexical.similarity_score


def __getattr__(name: str):
    if hasattr(_new_lexical, name):
        return getattr(_new_lexical, name)
    if hasattr(_comparison, name):
        return getattr(_comparison, name)
    return getattr(_shortlisting, name)
