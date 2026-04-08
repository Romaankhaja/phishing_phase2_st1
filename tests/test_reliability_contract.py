import csv
import os
import tempfile
import unittest

from phishing_pipeline.reliability import (
    CheckpointStore,
    build_run_context,
    make_record_key,
    stage_result_patch,
)


class ReliabilityContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
