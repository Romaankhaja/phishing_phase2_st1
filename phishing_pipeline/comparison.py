"""Compatibility alias for the legacy comparison module."""

from __future__ import annotations

import sys

from . import _comparison_legacy

sys.modules[__name__] = _comparison_legacy
