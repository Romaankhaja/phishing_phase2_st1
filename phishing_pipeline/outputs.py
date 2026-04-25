"""CSV, review queue, evidence, debug, and packaging outputs."""

from __future__ import annotations

from . import _comparison_legacy as _comparison
from . import _pipeline_legacy as _pipeline


package_results = _pipeline.package_results
format_evidence_filename = _pipeline.format_evidence_filename
move_screenshot_to_evidence = _pipeline.move_screenshot_to_evidence
move_screenshot_to_evidence_from_path = _pipeline.move_screenshot_to_evidence_from_path

_submission_record_columns = _pipeline._submission_record_columns
_build_output_remarks = _pipeline._build_output_remarks
_write_debug_csv = _pipeline._write_debug_csv
_HASH_ONLY_DEBUG_MERGE_KEYS = _pipeline._HASH_ONLY_DEBUG_MERGE_KEYS
_read_existing_review_queue = _pipeline._read_existing_review_queue
_merge_review_queue_frames = _pipeline._merge_review_queue_frames
_write_hash_review_queue = _pipeline._write_hash_review_queue
_stage1_debug_compat_payload = _pipeline._stage1_debug_compat_payload

_build_stage0_debug_rows = _comparison._build_stage0_debug_rows
_write_stage0_debug_csv = _comparison._write_stage0_debug_csv
_build_stage1_debug_rows = _comparison._build_stage1_debug_rows
_write_stage1_debug_csv = _comparison._write_stage1_debug_csv
_write_stage1_debug_csv_outputs = _comparison._write_stage1_debug_csv_outputs
_build_stage1_method_rows = _comparison._build_stage1_method_rows
_write_stage1_method_rows_csv = _comparison._write_stage1_method_rows_csv
_write_stage1_method_artifacts = _comparison._write_stage1_method_artifacts
_write_stage2_hash_exports = _comparison._write_stage2_hash_exports
_build_stage2_hash_export_row = _comparison._build_stage2_hash_export_row
_write_excluded_urls_audit = _comparison._write_excluded_urls_audit


def __getattr__(name: str):
    if hasattr(_pipeline, name):
        return getattr(_pipeline, name)
    return getattr(_comparison, name)
