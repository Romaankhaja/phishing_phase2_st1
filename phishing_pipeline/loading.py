"""Stage 0 input loading and source-workbook preparation."""

from __future__ import annotations

from . import _shortlisting_legacy as _legacy


normalize_url = _legacy.normalize_url
load_url_records_from_excel_folder = _legacy.load_url_records_from_excel_folder
load_urls_from_excel_folder = _legacy.load_urls_from_excel_folder
load_urls_from_txt = _legacy.load_urls_from_txt
write_list_to_txt = _legacy.write_list_to_txt
run_shortlisting_process = _legacy.run_shortlisting_process
generate_shortlisted_csv = _legacy.generate_shortlisted_csv

_discover_excel_files = _legacy._discover_excel_files
_looks_like_url_value = _legacy._looks_like_url_value
_safe_first_column_url_fallback = _legacy._safe_first_column_url_fallback


def __getattr__(name: str):
    return getattr(_legacy, name)
