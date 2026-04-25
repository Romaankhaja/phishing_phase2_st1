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

import os
import glob
import shutil
import logging

logger = logging.getLogger(__name__)

def cleanup_fresh_run_outputs(args_stage_smoke_test: str) -> None:
    """Clean up files and the latest folder before a fresh run."""
    cleanup_patterns = [
        os.path.join("output", "*.zip"),
        os.path.join("output", "output_file.csv"),
        os.path.join("output", "output_file_filtered.csv"),
        os.path.join("output", "hash_review_queue.csv"),
        os.path.join("output", "dns_gate_audit.csv"),
        os.path.join("output", "dns_rejected_lexical_hits.csv"),
        os.path.join("output", "parked_page_exclusions.csv"),
        os.path.join("output", "stage0_lexical_decisions.csv"),
        os.path.join("output", "stage2_model_debug.csv"),
        os.path.join("output", "stage3_classification_debug.csv"),
        os.path.join("output", "pipeline_run_results.csv"),
        os.path.join("output", "pipeline_stage_events.csv"),
        os.path.join("output", "checkpoints.csv"),
        os.path.join("output", "worker_heartbeats.csv"),
        os.path.join("output", "stage_metrics.csv"),
        os.path.join("output", "stall_events.csv"),
        os.path.join("output", "run_manifest.csv"),
        os.path.join("output", "run_manifest.json"),
        os.path.join("output", "run_summary.json"),
    ]
    if args_stage_smoke_test != "classify":
        cleanup_patterns.append(os.path.join("output", "holdout.csv"))
        
    for pattern in cleanup_patterns:
        for f in glob.glob(pattern):
            try:
                os.remove(f)
                logger.info("🧹 Removed old output: %s", f)
            except Exception as e:
                logger.warning("Could not remove %s: %s", f, e)
                
    legacy_checkpoint_dir = os.path.join("output", "checkpoints")
    if os.path.isdir(legacy_checkpoint_dir):
        shutil.rmtree(legacy_checkpoint_dir, ignore_errors=True)
        logger.info("Removed obsolete checkpoint folder: %s", legacy_checkpoint_dir)
        
    latest_dir = os.path.join("output", "latest")
    if os.path.isdir(latest_dir):
        shutil.rmtree(latest_dir, ignore_errors=True)
        logger.info("Removed obsolete latest folder: %s", latest_dir)

def enforce_output_limits() -> None:
    """Enforce limits on the output folders at the end of the pipeline execution."""
    try:
        # Limit hash_folder files to 10
        hash_folder = os.path.join("output", "hash_folder")
        if os.path.isdir(hash_folder):
            files = glob.glob(os.path.join(hash_folder, "*"))
            files.sort(key=os.path.getmtime)
            if len(files) > 10:
                for f in files[:-10]:
                    try:
                        if os.path.isfile(f):
                            os.remove(f)
                        elif os.path.isdir(f):
                            shutil.rmtree(f, ignore_errors=True)
                        logger.info("🧹 Cleaned up old hash file: %s", f)
                    except Exception as e:
                        logger.warning("Could not remove old hash file %s: %s", f, e)
                        
        # Limit runs to only the last run
        runs_folder = os.path.join("output", "runs")
        if os.path.isdir(runs_folder):
            run_dirs = glob.glob(os.path.join(runs_folder, "*"))
            run_dirs = [d for d in run_dirs if os.path.isdir(d)]
            run_dirs.sort(key=os.path.getmtime)
            if len(run_dirs) > 1:
                for d in run_dirs[:-1]:
                    try:
                        shutil.rmtree(d, ignore_errors=True)
                        logger.info("🧹 Cleaned up old run folder: %s", d)
                    except Exception as e:
                        logger.warning("Could not remove old run folder %s: %s", d, e)
    except Exception as exc:
        logger.warning("Output limits cleanup failed: %s", exc)
