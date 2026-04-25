"""
Automation watcher for the phishing pipeline.

Monitors PHISHING_INPUTS for .xlsx files in today's date folder (YYYY-MM-DD).
When detected, triggers the pipeline and moves the packaged results to
PHISHING_OUTPUTS.
"""

import argparse
from datetime import datetime
import glob
import logging
import os
import shutil
import subprocess
import sys
import time


INPUT_DIR = r"C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_INPUTS"
OUTPUT_DIR = r"C:\Users\SATWIK\Documents\PHISHING_UPLOADS\PHISHING_OUTPUTS"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "Scripts", "python.exe")
WHITELIST = os.path.join(
    PROJECT_ROOT,
    "data",
    "whitelists",
    "PS-02_hold-out_Set1_Legitimate_Domains_for_10_CSEs.xlsx",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("watcher")


def todays_folder() -> str:
    return os.path.join(INPUT_DIR, datetime.now().strftime("%Y-%m-%d"))


def has_xlsx(folder: str) -> bool:
    if not os.path.isdir(folder):
        return False
    return any(name.lower().endswith(".xlsx") for name in os.listdir(folder))


def run_pipeline(holdout_folder: str) -> bool:
    cmd = [
        VENV_PYTHON,
        "-m",
        "phishing_pipeline._pipeline_legacy",
        holdout_folder,
        WHITELIST,
        "--package-results",
    ]
    logger.info("Launching pipeline: %s", " ".join(cmd))
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    if result.returncode == 0:
        logger.info("Pipeline finished successfully.")
        return True
    logger.error("Pipeline exited with code %d", result.returncode)
    return False


def move_results_to_output(folder_name: str) -> str | None:
    """
    Find the packaged submission zip in PROJECT_ROOT/output, rename it with the
    date stamp, and move it to PHISHING_OUTPUTS.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    package_output_dir = os.path.join(PROJECT_ROOT, "output")
    preferred_zip = os.path.join(package_output_dir, f"Submission-{folder_name}.zip")
    src_zip = preferred_zip if os.path.exists(preferred_zip) else ""
    if not src_zip:
        candidates = [
            path
            for path in glob.glob(os.path.join(package_output_dir, "Submission-*.zip"))
            if os.path.isfile(path)
        ]
        if candidates:
            src_zip = max(candidates, key=os.path.getmtime)
    if not src_zip or not os.path.exists(src_zip):
        logger.warning("No submission zip found in %s", package_output_dir)
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest_name = f"Submission_{folder_name}_{timestamp}.zip"
    dest_path = os.path.join(OUTPUT_DIR, dest_name)
    shutil.move(src_zip, dest_path)
    logger.info("Results moved to: %s", dest_path)
    return dest_path


def check_and_run() -> bool:
    folder = todays_folder()
    folder_name = os.path.basename(folder)
    if not has_xlsx(folder):
        return False

    logger.info(".xlsx file(s) found in today's folder: %s", folder_name)
    success = run_pipeline(folder)
    if success:
        move_results_to_output(folder_name)
    return True


def watch_with_watchdog():
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    os.makedirs(INPUT_DIR, exist_ok=True)

    class XlsxHandler(FileSystemEventHandler):
        def __init__(self):
            self.processing = False

        def on_created(self, event):
            if event.is_directory or not event.src_path.lower().endswith(".xlsx"):
                return
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
                logger.warning("Pipeline already running, skipping.")
                return

            logger.info("New .xlsx detected: %s in %s", os.path.basename(event.src_path), folder_name)
            self.processing = True
            try:
                check_and_run()
            finally:
                self.processing = False

    handler = XlsxHandler()
    observer = Observer()
    observer.schedule(handler, INPUT_DIR, recursive=True)
    observer.start()

    if has_xlsx(todays_folder()):
        logger.info("Files already present in today's folder, processing now.")
        handler.processing = True
        try:
            check_and_run()
        finally:
            handler.processing = False

    logger.info("Watching %s for new .xlsx uploads.", INPUT_DIR)
    logger.info("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Watcher stopped.")
    observer.join()


def run_once():
    logger.info("One-shot check for today's folder.")
    triggered = check_and_run()
    if not triggered:
        logger.info("No .xlsx in today's folder (%s). Nothing to do.", os.path.basename(todays_folder()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing pipeline automation watcher")
    parser.add_argument("--once", action="store_true", help="Check once and exit instead of watching continuously")
    args = parser.parse_args()
    if args.once:
        run_once()
    else:
        watch_with_watchdog()
