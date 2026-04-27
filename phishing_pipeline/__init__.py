# phishing_pipeline/__init__.py
"""Lightweight package init — avoid importing heavy submodules at import time."""

import os
import tempfile

os.environ.setdefault(
    "TLDEXTRACT_CACHE",
    os.path.join(tempfile.gettempdir(), "phishing-ml-tldextract-cache"),
)
os.makedirs(os.environ["TLDEXTRACT_CACHE"], exist_ok=True)

__version__ = "0.1"
__all__ = ["run_pipeline", "package_results"]

def run_pipeline(*args, **kwargs):
    from .orchestration import run_pipeline as _run_pipeline
    return _run_pipeline(*args, **kwargs)
 
def package_results(*args, **kwargs):
    from .orchestration import package_results as _package_results
    return _package_results(*args, **kwargs)
