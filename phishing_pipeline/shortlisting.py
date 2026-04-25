"""Compatibility alias for the legacy shortlisting module."""

from __future__ import annotations

import sys

from . import _shortlisting_legacy

sys.modules[__name__] = _shortlisting_legacy
