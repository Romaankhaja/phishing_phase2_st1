import csv
import os
import tempfile
import unittest
from unittest import mock

from phishing_pipeline.reliability import (
    CheckpointStore,
    RUN_RESULT_COLUMNS,
    _write_csv_atomic,
    build_run_context,
    make_record_key,
    stage_result_patch,
)


class ReliabilityContractTests(unittest.TestCase):
    def test_write_csv_atomic_retries_transient_replace_lock(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "results.csv")
            original_replace = os.replace
            calls = {"count": 0}

            def flaky_replace(src: str, dst: str) -> None:
                calls["count"] += 1
                if calls["count"] == 1:
                    raise PermissionError(32, "locked")
                original_replace(src, dst)

            with (
                mock.patch("phishing_pipeline.reliability.os.replace", side_effect=flaky_replace),
                mock.patch("phishing_pipeline.reliability.time.sleep", return_value=None),
            ):
                _write_csv_atomic(
                    output_path,
                    RUN_RESULT_COLUMNS,
                    [
                        {
                            "run_id": "run-test",
                            "record_key": "abc",
                            "normalized_url": "https://example.com",
                        }
                    ],
                )

            with open(output_path, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))

            self.assertEqual(calls["count"], 2)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["record_key"], "abc")

    def test_record_key_includes_source_workbook(self):
        key_one = make_record_key("https://example.com", "a.xlsx")
        key_two = make_record_key("https://example.com", "b.xlsx")

        self.assertNotEqual(key_one, key_two)

    def test_checkpoint_store_exports_run_results_and_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ctx = build_run_context(
                output_dir=temp_dir,
                run_id="test_run",
                metadata={"shortlisting": "demo"},
            )
            store = CheckpointStore(ctx)
            store.ensure_url_result(
                raw_url="https://example.com",
                normalized_url="https://example.com",
                source_workbook="demo.xlsx",
            )
            store.upsert_url_result(
                stage_result_patch(
                    run_id=ctx.run_id,
                    raw_url="https://example.com",
                    normalized_url="https://example.com",
                    source_workbook="demo.xlsx",
                    stage_name="stage0",
                    stage_status="lexical_hit",
                    current_stage="stage0",
                )
            )
            store.append_stage_event(
                {
                    "run_id": ctx.run_id,
                    "record_key": make_record_key("https://example.com", "demo.xlsx"),
                    "source_workbook": "demo.xlsx",
                    "normalized_url": "https://example.com",
                    "stage_name": "stage0",
                    "attempt_index": 1,
                    "worker_id": "test-worker",
                    "started_at": "2026-04-06T00:00:00+00:00",
                    "finished_at": "2026-04-06T00:00:01+00:00",
                    "duration_ms": 1000,
                    "status": "lexical_hit",
                    "error_type": "",
                    "error_message": "",
                    "retry_count": 0,
                    "timeout_flag": 0,
                    "fallback_taken": "",
                }
            )
            store.mark_completed()
            store.export_all()

            with open(ctx.run_results_csv, newline="", encoding="utf-8") as fh:
                result_rows = list(csv.DictReader(fh))
            with open(ctx.stage_events_csv, newline="", encoding="utf-8") as fh:
                event_rows = list(csv.DictReader(fh))
            with open(ctx.checkpoints_csv, newline="", encoding="utf-8") as fh:
                checkpoint_rows = list(csv.DictReader(fh))

            self.assertEqual(len(result_rows), 1)
            self.assertEqual(result_rows[0]["stage0_status"], "lexical_hit")
            self.assertEqual(len(event_rows), 1)
            self.assertEqual(event_rows[0]["stage_name"], "stage0")
            self.assertEqual(len(checkpoint_rows), 1)
            self.assertEqual(checkpoint_rows[0]["record_key"], make_record_key("https://example.com", "demo.xlsx"))
            self.assertFalse(os.path.isdir(f"{temp_dir}\\checkpoints"))
            self.assertEqual(store.get_manifest()["status"], "completed")
            store.close()

    def test_checkpoint_store_best_effort_export_defers_locked_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ctx = build_run_context(
                output_dir=temp_dir,
                run_id="test_run",
                metadata={"shortlisting": "demo"},
            )
            store = CheckpointStore(ctx)
            store.upsert_url_result(
                stage_result_patch(
                    run_id=ctx.run_id,
                    raw_url="https://example.com",
                    normalized_url="https://example.com",
                    source_workbook="demo.xlsx",
                    stage_name="stage0",
                    stage_status="lexical_hit",
                    current_stage="stage0",
                )
            )

            with mock.patch(
                "phishing_pipeline.reliability._write_csv_atomic",
                side_effect=PermissionError(32, "locked"),
            ):
                store.export_all(best_effort=True)

            self.assertFalse(os.path.exists(ctx.run_results_csv))

            store.export_all()

            with open(ctx.run_results_csv, newline="", encoding="utf-8") as fh:
                result_rows = list(csv.DictReader(fh))

            self.assertEqual(len(result_rows), 1)
            self.assertEqual(result_rows[0]["stage0_status"], "lexical_hit")
            store.close()


if __name__ == "__main__":
    unittest.main()
