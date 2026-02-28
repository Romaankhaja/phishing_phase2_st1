# main_controller.py
"""
CLI controller for the phishing pipeline.
"""

import sys
import os
import argparse
import asyncio
import logging

# Event loop policy on Windows
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

# ---
# --- We have REMOVED the unused EasyOCR initialization that was here ---
# ---

# Import pipeline pieces
run_pipeline = None
package_results = None
FINAL_OUTPUT = None
close_browser = None
shortlisting = None  # Import the whole module

try:
    from phishing_pipeline.config import FINAL_OUTPUT
except Exception as e:
    logger.warning("Could not import FINAL_OUTPUT from config: %s", e)

try:
    from phishing_pipeline.visual_features import close_browser
except Exception as e:
    logger.warning("Could not import close_browser from visual_features: %s", e)

try:
    from phishing_pipeline import pipeline
    run_pipeline = pipeline.run_pipeline
    package_results = pipeline.package_results
    logger.info("Imported run_pipeline and package_results from pipeline.py")
except ImportError as e:
    logger.error("Failed to import from pipeline.py: %s", e)
    sys.exit(1)

try:
    from phishing_pipeline import shortlisting
    logger.info("Imported shortlisting module (shortlisting.py)")
except ImportError as e:
    logger.warning("Could not import shortlisting.py: %s", e)
    shortlisting = None


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
    parser = argparse.ArgumentParser(description="Phishing Detection CLI Controller")
    
    # ---
    # --- FIX 1: Updated default paths to match your new system
    # ---
    parser.add_argument("--whitelist", type=str, default=r"data\whitelists\Stage_2_Legitimate_Domains_80.xlsx",
                        help="Path to whitelist Excel file")
    parser.add_argument("--shortlisting", type=str, default=r"data\holdout_sets\PS-02_hold-out_Set_2",
                        help="Folder containing shortlisting .xlsx files")
    # --- (End of Fix 1) ---
    
    parser.add_argument("--limit", type=int, default=None,
                        help="Number of whitelisted domains to process (default = ALL)")
    args = parser.parse_args()

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
        
        logger.info("Using whitelist file: %s", args.whitelist)
        logger.info("Using shortlisting folder: %s", args.shortlisting)
        if args.limit:
            logger.info("Processing first %d whitelisted domains...", args.limit)
        else:
            logger.info("Processing ALL whitelisted domains...")

        df_out = None

        # Try the new-style orchestration (controller -> shortlisting -> pipeline)
        if shortlisting and hasattr(shortlisting, 'run_shortlisting_process'):
            
            # --- This is your junior's new flow ---
            
            # 1. Run Shortlisting
            logger.info("--- Starting Step 1: Running Shortlisting Process ---")
            holdout_df = shortlisting.run_shortlisting_process(
                holdout_folder=args.shortlisting,
                whitelist_file=args.whitelist,
                limit_whitelisted=args.limit,
                write_outputs=True  # This creates holdout.csv
            )
            logger.info("--- Finished Step 1: Shortlisting Complete ---")
            
            # 2. Run Pipeline
            logger.info("--- Starting Step 2: Running Main Pipeline ---")
            
            df_out = await run_pipeline(
                holdout_folder=args.shortlisting, 
                ps02_whitelist_file=args.whitelist,
                limit_whitelisted=args.limit if args.limit else None,
                use_existing_holdout=True # This tells pipeline.py to *use* holdout.csv
            )
            
            logger.info("--- Finished Step 2: Main Pipeline Complete ---")

        # Fallback to old style (pipeline does everything)
        elif run_pipeline is not None:
            logger.warning("Could not find shortlisting.run_shortlisting_process. Falling back to old pipeline-only mode.")
            try:
                df_out = await run_pipeline(
                    holdout_folder=args.shortlisting, 
                    ps02_whitelist_file=args.whitelist,
                    limit_whitelisted=args.limit if args.limit else None
                )
            except TypeError:
                df_out = await run_pipeline(args.shortlisting, args.whitelist, args.limit)
        else:
            raise RuntimeError("No suitable pipeline entrypoint found (shortlisting.run_shortlisting_process or run_pipeline).")

        # Package results if available
        zip_path = None
        if package_results is not None:
            try:
                zip_path = package_results()
                logger.info("Packaged results into: %s", zip_path)
            except Exception as exc:
                logger.warning("package_results() failed: %s", exc)

        if FINAL_OUTPUT:
            logger.info("Final output expected at: %s", FINAL_OUTPUT)

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


if __name__ == "__main__":
    asyncio.run(main())
    