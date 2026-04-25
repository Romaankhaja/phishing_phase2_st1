"""Compatibility alias for the legacy pipeline module."""

from __future__ import annotations

import sys

from . import _pipeline_legacy

sys.modules[__name__] = _pipeline_legacy
