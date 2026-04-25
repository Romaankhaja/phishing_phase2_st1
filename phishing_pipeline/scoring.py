"""Scoring constants, thresholds, and score helpers."""

from __future__ import annotations

from . import _comparison_legacy as _comparison
from . import _pipeline_legacy as _pipeline


DEFAULT_SCORING_WEIGHTS = _comparison.DEFAULT_SCORING_WEIGHTS
WEIGHTS = _comparison.WEIGHTS
DEFAULT_HASHING_THRESHOLD = _comparison.DEFAULT_HASHING_THRESHOLD
DEFAULT_DOMAIN_SIMILARITY_THRESHOLD = _comparison.DEFAULT_DOMAIN_SIMILARITY_THRESHOLD
DEFAULT_HIGH_CONFIDENCE_THRESHOLD = _comparison.DEFAULT_HIGH_CONFIDENCE_THRESHOLD
DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD = _comparison.DEFAULT_MEDIUM_CONFIDENCE_THRESHOLD
DEFAULT_TYPO_TOP_K = _comparison.DEFAULT_TYPO_TOP_K
DEFAULT_TYPO_MIN_SCORE = _comparison.DEFAULT_TYPO_MIN_SCORE
DEFAULT_LEXICAL_PASS_MIN_SCORE = _comparison.DEFAULT_LEXICAL_PASS_MIN_SCORE

_DEFAULT_SCORING_CONFIG = _comparison._DEFAULT_SCORING_CONFIG
_resolve_scoring_config = _comparison._resolve_scoring_config
_normalize_scores_with_active_weights = _comparison._normalize_scores_with_active_weights
_confidence_band_from_score = _comparison._confidence_band_from_score
_normalize_confidence_band = _pipeline._normalize_confidence_band


def __getattr__(name: str):
    if hasattr(_comparison, name):
        return getattr(_comparison, name)
    return getattr(_pipeline, name)
