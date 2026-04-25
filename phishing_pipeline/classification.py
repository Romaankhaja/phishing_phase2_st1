"""Stage 3 classification, model inference, OCR/TVC, and final label policy."""

from __future__ import annotations

from . import _pipeline_legacy as _legacy


reclassify_label = _legacy.reclassify_label
adjust_source = _legacy.adjust_source
normalize_text = _legacy.normalize_text
domain_tokens_from_url = _legacy.domain_tokens_from_url

_extract_hash_only_ocr_tvc = _legacy._extract_hash_only_ocr_tvc
_hybrid_hash_decision = _legacy._hybrid_hash_decision
_hybrid_hash_classification = _legacy._hybrid_hash_classification
_has_network_corroboration = _legacy._has_network_corroboration
_has_parked_sale_evidence = _legacy._has_parked_sale_evidence
_resolve_effective_detection_target = _legacy._resolve_effective_detection_target
_resolve_redirect_target_flags = _legacy._resolve_redirect_target_flags
_requires_registration_only_enrichment = _legacy._requires_registration_only_enrichment
_build_hash_only_model_frame = _legacy._build_hash_only_model_frame
_safe_predict_top1 = _legacy._safe_predict_top1
_run_hash_only_pipeline = _legacy._run_hash_only_pipeline


def __getattr__(name: str):
    return getattr(_legacy, name)
