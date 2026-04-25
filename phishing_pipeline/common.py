"""Shared URL/domain helpers.

This module intentionally delegates to the preserved legacy implementations so
the reorganization does not alter URL normalization, homoglyph handling, or
domain parsing semantics.
"""

from __future__ import annotations

from urllib.parse import urlparse

from . import _comparison_legacy as _comparison
from . import _shortlisting_legacy as _shortlisting


normalize_url = _comparison.normalize_url
normalize_shortlist_url = _shortlisting.normalize_url
get_clean_parts = _shortlisting.get_clean_parts
get_primary_part = _shortlisting.get_primary_part
clean_domain = _comparison.clean_domain


def hostname_from_url(value: str) -> str:
    """Return a lowercase hostname using the same tolerant URL handling style."""
    text = str(value or "").strip()
    if not text:
        return ""
    normalized = normalize_url(text)
    return (urlparse(normalized).hostname or "").strip().lower()


def __getattr__(name: str):
    if hasattr(_comparison, name):
        return getattr(_comparison, name)
    return getattr(_shortlisting, name)
