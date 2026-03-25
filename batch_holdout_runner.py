# batch_holdout_runner.py
"""
Batch Holdout Runner — processes each .xlsx file in the holdout folder
individually through the full phishing pipeline, producing a separate
submission zip per file.

Usage:
    python batch_holdout_runner.py
    python batch_holdout_runner.py --dry-run
    python batch_holdout_runner.py --holdout-dir "data/data/holdout_sets/PS-02_hold-out_Set_2"
    python batch_holdout_runner.py --whitelist "data/whitelists/Stage_2_Legitimate_Domains_80.xlsx"
"""

import sys
import os
import argparse
import asyncio
import logging
import shutil
import glob
import tempfile
import time

# ── Windows async event loop policy (must be set before any imports that
#    create event loops) ────────────────────────────────────────────────────
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    from functools import wraps
    from asyncio.proactor_events import _ProactorBasePipeTransport

    def silence_event_loop_closed(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except RuntimeError as e:
                if str(e) != 'Event loop is closed':
                    raise
        return wrapper

    _ProactorBasePipeTransport.__del__ = silence_event_loop_closed(
        _ProactorBasePipeTransport.__del__
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("batch_holdout_runner")

# ── Lazy imports of pipeline modules ──────────────────────────────────────
def _import_pipeline():
    """Import pipeline modules. Returns (run_pipeline, package_results,
    shortlisting, close_browser, config)."""
    from phishing_pipeline import pipeline
    from phishing_pipeline import shortlisting
    from phishing_pipeline.config import (
        FINAL_OUTPUT, CHECKPOINT_CSV, FEATURES_CSV, FEATURES_ENRICH,
        SCREENS_DIR, EVIDENCE_DIR, ROOT_DIR,
    )
    from phishing_pipeline.visual_features import close_browser

    return (
        pipeline.run_pipeline,
        pipeline.package_results,
        shortlisting,
        close_browser,
        {
            "FINAL_OUTPUT": FINAL_OUTPUT,
            "CHECKPOINT_CSV": CHECKPOINT_CSV,
            "FEATURES_CSV": FEATURES_CSV,
            "FEATURES_ENRICH": FEATURES_ENRICH,
            "SCREENS_DIR": SCREENS_DIR,
            "EVIDENCE_DIR": EVIDENCE_DIR,
            "ROOT_DIR": ROOT_DIR,
        },
    )


def clear_gpu_memory():
    """Clear GPU memory between pipeline runs."""
    try:
        import torch
        import gc
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
            gc.collect()
            free, total = torch.cuda.mem_get_info()
            logger.info(
                "🧹 GPU memory cleared. Free: %.2f GB / %.2f GB",
                free / 1024**3, total / 1024**3,
            )
    except Exception as e:
        logger.warning("Could not clear GPU memory: %s", e)


def discover_holdout_files(holdout_dir: str) -> list[str]:
    """Return sorted list of .xlsx files in the holdout directory."""
    patterns = [
        os.path.join(holdout_dir, "*.xlsx"),
        os.path.join(holdout_dir, "*.xls"),
    ]
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))
    # Filter out Excel temp files (~$...)
    files = [f for f in files if not os.path.basename(f).startswith("~$")]
    files.sort()
    return files


def clean_intermediate_artifacts(config: dict):
    """Remove intermediate pipeline outputs so runs don't bleed into each other."""
    # Files to remove
    for key in ("FINAL_OUTPUT", "CHECKPOINT_CSV", "FEATURES_CSV", "FEATURES_ENRICH"):
        path = config.get(key, "")
        if path and os.path.exists(path):
            try:
                os.remove(path)
                logger.info("🗑  Removed: %s", path)
            except Exception as e:
                logger.warning("⚠  Could not remove %s: %s", path, e)

    # Also remove holdout.csv from output/
    holdout_csv = os.path.join(config["ROOT_DIR"], "output", "holdout.csv")
    if os.path.exists(holdout_csv):
        try:
            os.remove(holdout_csv)
        except Exception:
            pass

    # Directories to remove (screenshots & evidence)
    for key in ("SCREENS_DIR", "EVIDENCE_DIR"):
        path = config.get(key, "")
        if path and os.path.exists(path):
            try:
                shutil.rmtree(path)
                logger.info("🗑  Removed folder: %s", path)
            except Exception as e:
                logger.warning("⚠  Could not remove folder %s: %s", path, e)

    # Remove the temp holdout_temp.csv inside phishing_pipeline/
    temp_csv = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "phishing_pipeline", "holdout_temp.csv",
    )
    if os.path.exists(temp_csv):
        try:
            os.remove(temp_csv)
        except Exception:
            pass


def derive_zip_name(xlsx_filename: str) -> str:
    """Derive a submission zip name from the holdout filename.

    Example: 'Unlabelled_Data_2026-03-01.xlsx'
           → 'PS-02_ISS_NLP_Submission_Unlabelled_Data_2026-03-01.zip'
    """
    stem = os.path.splitext(xlsx_filename)[0]
    return f"PS-02_ISS_NLP_Submission_{stem}.zip"


async def run_single_file(
    xlsx_path: str,
    whitelist_path: str,
    run_pipeline_fn,
    package_results_fn,
    shortlisting_mod,
    close_browser_fn,
    config: dict,
) -> str | None:
    """Run the full pipeline for a single holdout .xlsx file.

    Returns the path to the output zip, or None on failure.
    """
    xlsx_filename = os.path.basename(xlsx_path)
    logger.info("=" * 70)
    logger.info("📂 Processing file: %s", xlsx_filename)
    logger.info("=" * 70)

    # 1. Clean intermediates from any previous run
    clean_intermediate_artifacts(config)
    clear_gpu_memory()

    # 2. Create a temporary directory containing only this one .xlsx file
    #    (shortlisting reads all .xlsx files from a *folder*)
    temp_dir = tempfile.mkdtemp(prefix="holdout_single_")
    temp_xlsx = os.path.join(temp_dir, xlsx_filename)
    shutil.copy2(xlsx_path, temp_xlsx)
    logger.info("📋 Copied '%s' → temp folder '%s'", xlsx_filename, temp_dir)

    try:
        # 3. Run shortlisting
        logger.info("--- Step 1: Shortlisting ---")
        if hasattr(shortlisting_mod, "run_shortlisting_process"):
            shortlisting_mod.run_shortlisting_process(
                holdout_folder=temp_dir,
                whitelist_file=whitelist_path,
                limit_whitelisted=None,
                write_outputs=True,
            )
        logger.info("--- Step 1 complete ---")

        # 4. Run the main pipeline
        logger.info("--- Step 2: Main Pipeline ---")
        await run_pipeline_fn(
            holdout_folder=temp_dir,
            ps02_whitelist_file=whitelist_path,
            limit_whitelisted=None,
            use_existing_holdout=True,
        )
        logger.info("--- Step 2 complete ---")

        # 5. Package results (default zip name)
        logger.info("--- Step 3: Packaging ---")
        default_zip = package_results_fn()
        logger.info("--- Step 3 complete ---")

        # 6. Rename the zip to include the file name
        if default_zip and os.path.exists(default_zip):
            new_zip_name = derive_zip_name(xlsx_filename)
            new_zip_path = os.path.join(os.path.dirname(default_zip), new_zip_name)

            # If a zip with this name already exists, remove it first
            if os.path.exists(new_zip_path):
                os.remove(new_zip_path)

            os.rename(default_zip, new_zip_path)
            logger.info("✅ Submission zip: %s", new_zip_path)
            return new_zip_path
        else:
            logger.error("❌ No zip was produced for %s", xlsx_filename)
            return None

    except Exception as e:
        logger.error("❌ Pipeline failed for %s: %s", xlsx_filename, e, exc_info=True)
        return None

    finally:
        # Clean up the temp single-file folder
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

        # Close the visual browser between runs
        if close_browser_fn:
            try:
                close_browser_fn()
            except Exception:
                pass


async def run_batch(holdout_dir: str, whitelist_path: str, dry_run: bool = False):
    """Discover all holdout files and process them one-by-one."""
    files = discover_holdout_files(holdout_dir)

    if not files:
        logger.error("❌ No .xlsx files found in '%s'", holdout_dir)
        return

    print("\n" + "=" * 70)
    print(f"📦 BATCH HOLDOUT RUNNER — {len(files)} file(s) found")
    print("=" * 70)
    for i, f in enumerate(files, 1):
        zip_name = derive_zip_name(os.path.basename(f))
        print(f"  {i:2d}. {os.path.basename(f)}  →  {zip_name}")
    print("=" * 70 + "\n")

    if dry_run:
        print("🔍 Dry-run mode — no pipeline execution. Exiting.")
        return

    # Import pipeline modules (heavy imports happen here)
    logger.info("Loading pipeline modules...")
    (
        run_pipeline_fn,
        package_results_fn,
        shortlisting_mod,
        close_browser_fn,
        config,
    ) = _import_pipeline()

    results: list[tuple[str, str | None]] = []
    total_start = time.time()

    for i, xlsx_path in enumerate(files, 1):
        file_start = time.time()
        print(f"\n{'━' * 70}")
        print(f"  🔄 [{i}/{len(files)}] {os.path.basename(xlsx_path)}")
        print(f"{'━' * 70}\n")

        zip_path = await run_single_file(
            xlsx_path=xlsx_path,
            whitelist_path=whitelist_path,
            run_pipeline_fn=run_pipeline_fn,
            package_results_fn=package_results_fn,
            shortlisting_mod=shortlisting_mod,
            close_browser_fn=close_browser_fn,
            config=config,
        )

        elapsed = time.time() - file_start
        results.append((os.path.basename(xlsx_path), zip_path))
        logger.info(
            "⏱  File %d/%d done in %.1f min", i, len(files), elapsed / 60
        )

    # ── Summary ──────────────────────────────────────────────────────────
    total_elapsed = time.time() - total_start
    print("\n" + "=" * 70)
    print("📊 BATCH PROCESSING COMPLETE")
    print(f"   Total time: {total_elapsed / 60:.1f} minutes")
    print("=" * 70)
    print(f"  {'#':>3}  {'Input File':<45} {'Status'}")
    print(f"  {'─'*3}  {'─'*45} {'─'*20}")
    for i, (fname, zpath) in enumerate(results, 1):
        status = f"✅ {os.path.basename(zpath)}" if zpath else "❌ FAILED"
        print(f"  {i:>3}  {fname:<45} {status}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Batch Holdout Runner — process each holdout .xlsx file "
                    "individually and produce a separate submission zip per file.",
    )
    parser.add_argument(
        "--holdout-dir",
        type=str,
        default=r"data\data\holdout_sets\PS-02_hold-out_Set_2",
        help="Directory containing holdout .xlsx files (default: data\\data\\holdout_sets\\PS-02_hold-out_Set_2)",
    )
    parser.add_argument(
        "--whitelist",
        type=str,
        default=r"data\whitelists\Stage_2_Legitimate_Domains_80.xlsx",
        help="Path to whitelist Excel file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List discovered files and planned zip names without running the pipeline",
    )
    args = parser.parse_args()

    # Validate paths
    if not os.path.isdir(args.holdout_dir):
        logger.error("Holdout directory not found: %s", args.holdout_dir)
        sys.exit(1)
    if not args.dry_run and not os.path.isfile(args.whitelist):
        logger.error("Whitelist file not found: %s", args.whitelist)
        sys.exit(1)

    asyncio.run(run_batch(args.holdout_dir, args.whitelist, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
