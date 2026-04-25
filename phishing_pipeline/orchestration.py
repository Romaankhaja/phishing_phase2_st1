"""Pipeline orchestration and public execution entrypoints."""

from __future__ import annotations

from . import _comparison_legacy as _comparison
from . import _pipeline_legacy as _pipeline
from . import _shortlisting_legacy as _shortlisting


process_urls = _pipeline.process_urls
run_pipeline = _pipeline.run_pipeline
package_results = _pipeline.package_results

run_shortlisting_process = _shortlisting.run_shortlisting_process
generate_shortlisted_csv = _shortlisting.generate_shortlisted_csv

run_hashing_shortlist = _comparison.run_hashing_shortlist
run_hashing_shortlist_async = _comparison.run_hashing_shortlist_async
run_hashing_shortlist_streaming = _comparison.run_hashing_shortlist_streaming


def __getattr__(name: str):
    if hasattr(_pipeline, name):
        return getattr(_pipeline, name)
    if hasattr(_comparison, name):
        return getattr(_comparison, name)
    return getattr(_shortlisting, name)
