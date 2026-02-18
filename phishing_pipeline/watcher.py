"""
Automation Watcher for Phishing Pipeline
=========================================
Monitors PHISHING_INPUTS for .xlsx files in today's date folder (YYYY-MM-DD).
When detected, triggers the pipeline and moves the zipped results to PHISHING_OUTPUTS.

Usage:
    python watcher.py            # Run as a long-lived service
    python watcher.py --once     # Check once and exit (for cron/Task Scheduler)
"""

import os
import sys
import time
import shutil
import logging
import subprocess
import argparse
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
INPUT_DIR  = r"C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_INPUTS"
OUTPUT_DIR = r"C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_OUTPUTS"

# Project paths (derived from this file's location)
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))          # phishing_pipeline/
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                         # Phishing/
VENV_PYTHON  = os.path.join(PROJECT_ROOT, "venv", "Scripts", "python.exe")
WHITELIST    = os.path.join(PROJECT_ROOT, "data", "whitelists",
                            "PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("watcher")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def todays_folder() -> str:
    """Return the absolute path to today's date folder inside INPUT_DIR."""
    return os.path.join(INPUT_DIR, datetime.now().strftime("%Y-%m-%d"))


def has_xlsx(folder: str) -> bool:
    """Return True if *folder* contains at least one .xlsx file."""
    if not os.path.isdir(folder):
        return False
    return any(f.lower().endswith(".xlsx") for f in os.listdir(folder))


def run_pipeline(holdout_folder: str) -> bool:
    """
    Invoke the pipeline as a subprocess so we get a clean process and
    avoid any import / event-loop issues.
    Returns True on success.
    """
    cmd = [
        VENV_PYTHON, "-m", "phishing_pipeline.pipeline",
        holdout_folder,
        WHITELIST,
        "--package-results",
    ]
    logger.info("🚀  Launching pipeline: %s", " ".join(cmd))

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)

    if result.returncode == 0:
        logger.info("✅  Pipeline finished successfully.")
        return True
    else:
        logger.error("❌  Pipeline exited with code %d", result.returncode)
        return False


def move_results_to_output(folder_name: str) -> str | None:
    """
    Find the submission zip created by package_results() in PROJECT_ROOT,
    rename it with the date stamp, and move it to PHISHING_OUTPUTS.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # package_results() writes to PROJECT_ROOT / PS-02_ISS_NLP_Submission.zip
    src_zip = os.path.join(PROJECT_ROOT, "PS-02_ISS_NLP_Submission.zip")
    if not os.path.exists(src_zip):
        logger.warning("⚠️  No submission zip found at %s", src_zip)
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_name = f"Submission_{folder_name}_{timestamp}.zip"
    dest_path = os.path.join(OUTPUT_DIR, dest_name)

    shutil.move(src_zip, dest_path)
    logger.info("📦  Results moved to: %s", dest_path)
    return dest_path


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------
def check_and_run() -> bool:
    """
    Check if today's folder exists and contains .xlsx files.
    If so, run the pipeline and move results.
    Returns True if the pipeline was triggered.
    """
    folder = todays_folder()
    folder_name = os.path.basename(folder)

    if not has_xlsx(folder):
        return False

    logger.info("📄  .xlsx file(s) found in today's folder: %s", folder_name)

    success = run_pipeline(folder)
    if success:
        move_results_to_output(folder_name)

    return True


# ---------------------------------------------------------------------------
# Watcher modes
# ---------------------------------------------------------------------------
def watch_with_watchdog():
    """Long-running mode: use watchdog to react to filesystem events."""
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    os.makedirs(INPUT_DIR, exist_ok=True)

    class XlsxHandler(FileSystemEventHandler):
        def __init__(self):
            self.processing = False

        def on_created(self, event):
            if event.is_directory:
                return
            if not event.src_path.lower().endswith(".xlsx"):
                return

            # Verify parent folder is today's date
            parent = os.path.dirname(event.src_path)
            folder_name = os.path.basename(parent)
            try:
                folder_date = datetime.strptime(folder_name, "%Y-%m-%d").date()
            except ValueError:
                return

            if folder_date != datetime.now().date():
                logger.debug("Ignoring %s (not today)", folder_name)
                return

            if self.processing:
                logger.warning("⚠️  Pipeline already running, skipping.")
                return

            logger.info("📄  New .xlsx detected: %s in %s",
                        os.path.basename(event.src_path), folder_name)

            self.processing = True
            try:
                check_and_run()
            finally:
                self.processing = False

    handler  = XlsxHandler()
    observer = Observer()
    observer.schedule(handler, INPUT_DIR, recursive=True)
    observer.start()

    # --- Initial check: process files already sitting in today's folder ---
    if has_xlsx(todays_folder()):
        logger.info("📂  Files already present in today's folder — processing now …")
        handler.processing = True
        try:
            check_and_run()
        finally:
            handler.processing = False

    logger.info("👀  Watching %s for new .xlsx uploads …", INPUT_DIR)
    logger.info("    Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Watcher stopped.")
    observer.join()


def run_once():
    """One-shot mode: check today's folder once and exit."""
    logger.info("🔍  One-shot check for today's folder …")
    triggered = check_and_run()
    if not triggered:
        logger.info("ℹ️  No .xlsx in today's folder (%s). Nothing to do.",
                    os.path.basename(todays_folder()))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing pipeline automation watcher")
    parser.add_argument("--once", action="store_true",
                        help="Check once and exit instead of watching continuously")
    args = parser.parse_args()

    if args.once:
        run_once()
    else:
        watch_with_watchdog()
