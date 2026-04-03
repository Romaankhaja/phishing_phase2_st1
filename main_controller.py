# main_controller.py
"""
CLI controller for the phishing pipeline.
"""

import sys
import os
import argparse
import asyncio
import logging
from typing import Any

# Event loop policy on Windows
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    # Silence "Event loop is closed" error on Windows
    from functools import wraps
    from asyncio.proactor_events import _ProactorBasePipeTransport
    
    def silence_event_loop_closed(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except RuntimeError as e:
                # Ignore this specific error during shutdown
                if str(e) != 'Event loop is closed':
                    raise
        return wrapper

    _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(_ProactorBasePipeTransport.__del__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def _non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be numeric") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("Value must be non-negative")
    return parsed


def _probability_float(value: str) -> float:
    parsed = _non_negative_float(value)
    if parsed > 1:
        raise argparse.ArgumentTypeError("Value must be in [0, 1]")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("Value must be non-negative")
    return parsed


def _positive_int(value: str) -> int:
    parsed = _non_negative_int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be > 0")
    return parsed


def _pipeline_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    allowed = {"hash_only", "legacy_ocr"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"pipeline mode must be one of {sorted(allowed)}")
    return normalized


def _stage_smoke_mode(value: str) -> str:
    normalized = str(value).strip().lower()
    allowed = {"off", "dns", "fetch", "lexical", "score", "classify", "all"}
    if normalized not in allowed:
        raise argparse.ArgumentTypeError(f"stage smoke test must be one of {sorted(allowed)}")
    return normalized


def _load_runtime_components() -> dict[str, Any]:
    """
    Import pipeline modules lazily.

    This avoids import-time side effects when Windows multiprocessing spawns
    worker processes and re-imports this file as ``__mp_main__``.
    """
    components: dict[str, Any] = {
        "FINAL_OUTPUT": None,
        "close_browser": None,
        "run_pipeline": None,
        "package_results": None,
        "shortlisting": None,
        "run_hashing_shortlist_async": None,
    }

    try:
        from phishing_pipeline.config import FINAL_OUTPUT
        components["FINAL_OUTPUT"] = FINAL_OUTPUT
    except Exception as exc:
        logger.warning("Could not import FINAL_OUTPUT from config: %s", exc)

    try:
        from phishing_pipeline.visual_features import close_browser
        components["close_browser"] = close_browser
    except Exception as exc:
        logger.warning("Could not import close_browser from visual_features: %s", exc)

    try:
        from phishing_pipeline import pipeline
        components["run_pipeline"] = pipeline.run_pipeline
        components["package_results"] = pipeline.package_results
        logger.info("Imported run_pipeline and package_results from pipeline.py")
    except ImportError as exc:
        logger.error("Failed to import from pipeline.py: %s", exc)
        raise

    try:
        from phishing_pipeline import shortlisting
        components["shortlisting"] = shortlisting
        logger.info("Imported shortlisting module for utils (shortlisting.py)")
    except ImportError as exc:
        logger.warning("Could not import shortlisting.py: %s", exc)

    try:
        from phishing_pipeline.comparison import run_hashing_shortlist_async
        components["run_hashing_shortlist_async"] = run_hashing_shortlist_async
        logger.info("Imported run_hashing_shortlist_async from phishing_pipeline.comparison")
    except ImportError as exc:
        logger.warning("Could not import phishing_pipeline.comparison: %s", exc)

    return components


def clear_gpu_memory():
    """Clear GPU memory before pipeline run for better performance."""
    try:
        import torch
        import gc
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
            gc.collect()
            free, total = torch.cuda.mem_get_info()
            logger.info(f"🧹 GPU memory cleared. Free: {free/1024**3:.2f} GB / {total/1024**3:.2f} GB")
        else:
            logger.info("No CUDA GPU available, skipping memory cleanup")
    except Exception as e:
        logger.warning(f"Could not clear GPU memory: {e}")


async def main():
    components = _load_runtime_components()
    final_output = components["FINAL_OUTPUT"]
    close_browser = components["close_browser"]
    run_pipeline = components["run_pipeline"]
    package_results = components["package_results"]
    shortlisting = components["shortlisting"]
    run_hashing_shortlist_async = components["run_hashing_shortlist_async"]

    parser = argparse.ArgumentParser(description="Phishing Detection CLI Controller")
    
    parser.add_argument("--whitelist", type=str, default=os.path.join("data", "whitelists", "Stage_2_Legitimate_Domains_80.xlsx"),
                        help="Path to whitelist Excel file")
    parser.add_argument("--shortlisting", type=str, default=os.path.join("data", "holdout_sets"),
                        help="Folder containing shortlisting .xlsx files")
    parser.add_argument("--limit", type=int, default=None,
                        help="Number of whitelisted domains to process (default = ALL)")
    parser.add_argument("--target-limit", type=int, default=None,
                        help="Number of target URLs to load from the shortlisting Excel input before hashing")
    parser.add_argument("--pipeline-mode", type=_pipeline_mode, default="hash_only",
                        help="Pipeline mode: hash_only (default) or legacy_ocr")
    parser.add_argument("--hashing-threshold", type=_non_negative_float, default=65.0,
                        help="Minimum final shortlist score required for a match (default=65)")
    parser.add_argument("--domain-sim-threshold", type=_probability_float, default=0.85,
                        help="Minimum domain similarity in [0,1] required before domain score is counted (default=0.85)")
    parser.add_argument("--high-confidence-threshold", type=_non_negative_float, default=78.0,
                        help="Hash score threshold for High confidence band (default=78)")
    parser.add_argument("--medium-confidence-threshold", type=_non_negative_float, default=68.0,
                        help="Hash score threshold for Medium confidence band (default=68)")
    parser.add_argument("--typo-top-k", type=_positive_int, default=10,
                        help="Top-K typosquat candidate CSEs retained before hash/CLIP scoring (default=10)")
    parser.add_argument("--typo-min-score", type=_probability_float, default=0.45,
                        help="Minimum typosquat similarity to count as typo anchor (default=0.45)")
    parser.add_argument("--lexical-pass-min-score", type=_probability_float, default=0.85,
                        help="Minimum lexical score allowed to pass Stage 1 admission even below hash threshold (default=0.85)")
    parser.add_argument("--clip-margin-min", type=_non_negative_float, default=0.12,
                        help="Minimum score margin for strong CLIP anchor (default=0.12)")
    parser.add_argument("--dns-timeout", type=_non_negative_float, default=3.0,
                        help="DNS gate timeout in seconds (default=3.0)")
    parser.add_argument("--dns-retries", type=_non_negative_int, default=1,
                        help="DNS gate retry count for timeout/resolver errors (default=1)")
    parser.add_argument("--dns-max-workers", type=_positive_int, default=None,
                        help="Optional fixed DNS gate worker count (default=adaptive)")
    parser.add_argument("--weight-domain", type=_non_negative_float, default=30.0,
                        help="Weight for domain similarity score contribution (default=30)")
    parser.add_argument("--weight-screenshot", type=_non_negative_float, default=20.0,
                        help="Weight for CLIP screenshot similarity contribution (default=20)")
    parser.add_argument("--weight-favicon", type=_non_negative_float, default=14.0,
                        help="Weight for favicon hash exact-match contribution (default=14)")
    parser.add_argument("--weight-ssl-hash", type=_non_negative_float, default=12.0,
                        help="Weight for SSL certificate hash exact-match contribution (default=12)")
    parser.add_argument("--weight-html-hash", type=_non_negative_float, default=6.0,
                        help="Weight for HTML hash exact-match contribution (default=6)")
    parser.add_argument("--weight-domain-hash", type=_non_negative_float, default=8.0,
                        help="Weight for domain hash exact-match contribution (default=8)")
    parser.add_argument("--weight-keywords", type=_non_negative_float, default=10.0,
                        help="Weight for keyword overlap contribution (default=10)")
    parser.add_argument("--shortlist-debug-csv", type=str, default=os.path.join("output", "stage1_lexical_debug.csv"),
                        help="Path for Stage 1 lexical/debug CSV (default=output/stage1_lexical_debug.csv)")
    parser.add_argument("--stage-smoke-test", type=_stage_smoke_mode, default="off",
                        help="Optional partial-run mode: off, dns, fetch, lexical, score, classify, all (default=off)")
    args = parser.parse_args()
    if args.high_confidence_threshold < args.medium_confidence_threshold:
        raise ValueError("high-confidence-threshold must be >= medium-confidence-threshold")
    if args.dns_timeout <= 0:
        raise ValueError("dns-timeout must be > 0")

    # ✅ Ensure whitelist file exists
    if not os.path.exists(args.whitelist):
        logger.error("Whitelist file '%s' not found", args.whitelist)
        raise FileNotFoundError(f"Whitelist file '{args.whitelist}' not found")

    # ✅ Ensure shortlisting folder exists
    if not os.path.exists(args.shortlisting):
        logger.error("Shortlisting folder '%s' not found", args.shortlisting)
        raise FileNotFoundError(f"Shortlisting folder '{args.shortlisting}' not found")

    try:
        # 🧹 Clear GPU memory at the start of every run
        clear_gpu_memory()

        # 🧹 Clear stale outputs from previous runs
        import shutil
        import glob

        evidence_dir = os.path.join("phishing_pipeline", "PS-02_ISS_NLP_Evidences")
        packaged_submission_dir = os.path.join("output", "PS-02_ISS_NLP_Submission")
        if os.path.isdir(evidence_dir):
            shutil.rmtree(evidence_dir, ignore_errors=True)
            logger.info("🧹 Cleared previous evidence directory: %s", evidence_dir)
        if os.path.isdir(packaged_submission_dir):
            shutil.rmtree(packaged_submission_dir, ignore_errors=True)
            logger.info("🧹 Cleared stale packaged submission directory: %s", packaged_submission_dir)
        # Remove old submission xlsx (temp file in phishing_pipeline/)
        for xlsx in glob.glob(os.path.join("phishing_pipeline", "PS-02_*_Submission_Set.xlsx")):
            os.remove(xlsx)
            logger.info("🧹 Removed old submission xlsx: %s", xlsx)

        # Remove old submission zip and output CSVs
        cleanup_patterns = [
            os.path.join("output", "*.zip"),
            os.path.join("output", "output_file.csv"),
            os.path.join("output", "output_file_filtered.csv"),
            os.path.join("output", "hash_review_queue.csv"),
            os.path.join("output", "checkpoint_records.csv"),
            os.path.join("output", "stage1_lexical_debug.csv"),
            os.path.join("output", "stage2_model_debug.csv"),
            os.path.join("output", "stage3_classification_debug.csv"),
            os.path.join("output", "parked_page_exclusions.csv"),
        ]
        if args.stage_smoke_test != "classify":
            cleanup_patterns.append(os.path.join("output", "holdout.csv"))
        for pattern in cleanup_patterns:
            for f in glob.glob(pattern):
                os.remove(f)
                logger.info("🧹 Removed old output: %s", f)
        
        logger.info("Using whitelist file: %s", args.whitelist)
        logger.info("Using shortlisting folder: %s", args.shortlisting)
        if args.limit:
            logger.info("Processing first %d whitelisted domains...", args.limit)
        else:
            logger.info("Processing ALL whitelisted domains...")
        if args.target_limit is not None:
            logger.info("Limiting shortlist input to first %d target URLs...", args.target_limit)
        logger.info(
            "Runtime mode=%s | shortlist threshold=%.3f domain_sim_threshold=%.3f "
            "confidence_bands={high>=%.3f, medium>=%.3f} "
            "typo={top_k=%d,min_score=%.3f,lexical_pass_min_score=%.3f,clip_margin_min=%.3f} "
            "dns={timeout=%.2f,retries=%d,max_workers=%s} "
            "weights={domain=%.3f,screenshot=%.3f,favicon=%.3f,ssl_hash=%.3f,html_hash=%.3f,domain_hash=%.3f,keywords=%.3f} "
            "stage_smoke_test=%s shortlist_debug_csv=%s",
            args.pipeline_mode,
            args.hashing_threshold,
            args.domain_sim_threshold,
            args.high_confidence_threshold,
            args.medium_confidence_threshold,
            args.typo_top_k,
            args.typo_min_score,
            args.lexical_pass_min_score,
            args.clip_margin_min,
            args.dns_timeout,
            args.dns_retries,
            args.dns_max_workers if args.dns_max_workers is not None else "adaptive",
            args.weight_domain,
            args.weight_screenshot,
            args.weight_favicon,
            args.weight_ssl_hash,
            args.weight_html_hash,
            args.weight_domain_hash,
            args.weight_keywords,
            args.stage_smoke_test,
            args.shortlist_debug_csv,
        )

        df_out = None

        # Try the new-style orchestration (controller -> comparison -> pipeline)
        if run_hashing_shortlist_async and shortlisting:
            if args.stage_smoke_test == "classify":
                existing_holdout = os.path.join("output", "holdout.csv")
                if not os.path.exists(existing_holdout):
                    raise FileNotFoundError("stage-smoke-test=classify requires an existing output/holdout.csv")
                logger.info("--- Stage Smoke Test classify: Reusing existing holdout.csv ---")
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting,
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    use_existing_holdout=True,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=args.dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                )
                logger.info("--- Finished Stage Smoke Test classify ---")
            else:
            # 1. Run Shortlisting using phishing_pipeline.comparison
                logger.info("--- Starting Step 1: Running Hashing-based Shortlisting ---")
                urls = shortlisting.load_urls_from_excel_folder(
                    args.shortlisting,
                    limit=args.target_limit,
                )
                shortlist_weights = {
                    "domain": args.weight_domain,
                    "screenshot": args.weight_screenshot,
                    "favicon": args.weight_favicon,
                    "ssl_hash": args.weight_ssl_hash,
                    "html_hash": args.weight_html_hash,
                    "domain_hash": args.weight_domain_hash,
                    "keywords": args.weight_keywords,
                }
                
                holdout_df = await run_hashing_shortlist_async(
                    list(urls),
                    threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=args.dns_max_workers,
                    weights=shortlist_weights,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                )
                
                # Save output to holdout.csv
                out_csv = os.path.join("output", "holdout.csv")
                os.makedirs("output", exist_ok=True)
                holdout_df.to_csv(out_csv, index=False)
                logger.info(f"--- Finished Step 1: Shortlisting Complete ({len(holdout_df)} matched) ---")

                if args.stage_smoke_test in {"dns", "fetch", "lexical", "score"}:
                    logger.info("Stage smoke test '%s' requested. Stopping after Step 1.", args.stage_smoke_test)
                    df_out = holdout_df
                    return
                
                # 2. Run Pipeline
                logger.info("--- Starting Step 2: Running Main Pipeline ---")
                
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting, 
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    use_existing_holdout=True,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=args.dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                )
                
                logger.info("--- Finished Step 2: Main Pipeline Complete ---")

        # Fallback to old style (pipeline does everything)
        elif run_pipeline is not None:
            logger.warning("Could not find shortlisting.run_shortlisting_process. Falling back to old pipeline-only mode.")
            try:
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting, 
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None,
                    limit_target_urls=args.target_limit,
                    pipeline_mode=args.pipeline_mode,
                    high_confidence_threshold=args.high_confidence_threshold,
                    medium_confidence_threshold=args.medium_confidence_threshold,
                    hashing_threshold=args.hashing_threshold,
                    domain_similarity_threshold=args.domain_sim_threshold,
                    typo_top_k=args.typo_top_k,
                    typo_min_score=args.typo_min_score,
                    lexical_pass_min_score=args.lexical_pass_min_score,
                    clip_margin_min=args.clip_margin_min,
                    dns_timeout=args.dns_timeout,
                    dns_retries=args.dns_retries,
                    dns_max_workers=args.dns_max_workers,
                    shortlist_debug_csv=args.shortlist_debug_csv,
                )
            except TypeError:
                df_out = await run_pipeline(args.shortlisting, args.whitelist, args.limit)
        else:
            raise RuntimeError("No suitable pipeline entrypoint found (shortlisting.run_shortlisting_process or run_pipeline).")

        # Package results if available
        zip_path = None
        if package_results is not None:
            try:
                input_name = os.path.basename(os.path.normpath(args.shortlisting))
                zip_path = package_results(zip_path=f"Submission-{input_name}.zip")
                logger.info("Packaged results into: %s", zip_path)
            except Exception as exc:
                logger.warning("package_results() failed: %s", exc)

        if final_output:
            logger.info("Final output expected at: %s", final_output)

        # Show small preview if df_out is a DataFrame-like object
        if df_out is not None:
            try:
                print(df_out.head(10))
            except Exception:
                logger.info("Output is not a pandas DataFrame or cannot be printed.")

    finally:
        # Always attempt to close the visual browser (if available)
        if close_browser:
            try:
                close_browser()
                logger.info("Closed visual browser.")
            except Exception as exc:
                logger.warning("close_browser() raised: %s", exc)

        # Kill any orphaned chrome-headless processes
        try:
            import subprocess
            subprocess.run(["pkill", "-f", "chrome-headless"], capture_output=True, timeout=5)
            logger.info("Cleaned up orphaned Chrome processes.")
        except Exception:
            pass  # Expected to fail on Windows


if __name__ == "__main__":
    asyncio.run(main())

