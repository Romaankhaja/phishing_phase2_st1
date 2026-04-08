import asyncio
import csv
import os
import tempfile
import unittest

from phishing_pipeline import comparison
from phishing_pipeline.reliability import build_run_context


class HashStageScalingTests(unittest.TestCase):
    def test_resolve_effective_headless_target_prefers_redirect_host(self):
        effective_url, effective_domain = comparison._resolve_effective_headless_target(
            "https://crsor.info",
            "https://dcc.crsorgi.gov.in.crsor.info/crs/",
            original_domain="crsor.info",
        )

        self.assertEqual("https://dcc.crsorgi.gov.in.crsor.info/crs/", effective_url)
        self.assertEqual("dcc.crsorgi.gov.in.crsor.info", effective_domain)

    def test_resolve_effective_headless_target_without_redirect_keeps_input_host(self):
        effective_url, effective_domain = comparison._resolve_effective_headless_target(
            "https://crsor.info",
            "",
            original_domain="crsor.info",
        )

        self.assertEqual("https://crsor.info", effective_url)
        self.assertEqual("crsor.info", effective_domain)

    def test_deceptive_host_embedding_detects_embedded_legitimate_domain(self):
        self.assertTrue(
            comparison._has_deceptive_host_embedding(
                "dcc.crsorgi.gov.in.crsor.info",
                "crsorgi.gov.in",
            )
        )

    def test_deceptive_host_embedding_ignores_same_registered_domain_subdomain(self):
        self.assertFalse(
            comparison._has_deceptive_host_embedding(
                "login.crsorgi.gov.in",
                "crsorgi.gov.in",
            )
        )

    def test_commit_legacy_shard_fetch_outcome_defers_successful_payload_counting(self):
        metrics = {
            "processed": 0,
            "hashed_success": 0,
            "fetch_failed": 0,
            "fetch_timed_out": 0,
            "final_matches_above_threshold": 0,
            "finalized": 0,
        }
        decision_rows = []
        review_failures = []
        payload_outcome = {
            "decision_row": None,
            "admitted_prefetch_match": None,
            "queue_payload": {"url": "https://example.test"},
            "metric_key": "hashed_success",
        }
        queue_payload = comparison._commit_legacy_shard_fetch_outcome(
            payload_outcome,
            metrics=metrics,
            decision_rows=decision_rows,
            prefetch_admitted_failures=review_failures,
        )
        self.assertEqual({"url": "https://example.test"}, queue_payload)
        self.assertEqual(0, metrics["processed"])
        self.assertEqual(0, metrics["hashed_success"])
        self.assertEqual(0, metrics["finalized"])
        self.assertEqual([], decision_rows)
        self.assertEqual([], review_failures)

    def test_commit_legacy_shard_fetch_outcome_counts_terminal_failure_once(self):
        metrics = {
            "processed": 0,
            "hashed_success": 0,
            "fetch_failed": 0,
            "fetch_timed_out": 0,
            "final_matches_above_threshold": 0,
            "finalized": 0,
        }
        decision_rows = []
        review_failures = []
        payload_outcome = {
            "decision_row": {"normalized_url": "https://dead.example"},
            "admitted_prefetch_match": None,
            "queue_payload": None,
            "metric_key": "fetch_failed",
        }
        queue_payload = comparison._commit_legacy_shard_fetch_outcome(
            payload_outcome,
            metrics=metrics,
            decision_rows=decision_rows,
            prefetch_admitted_failures=review_failures,
        )
        self.assertIsNone(queue_payload)
        self.assertEqual(1, metrics["processed"])
        self.assertEqual(1, metrics["fetch_failed"])
        self.assertEqual(1, metrics["finalized"])
        self.assertEqual(1, len(decision_rows))
        self.assertEqual([], review_failures)

    def test_hash_adjustment_upshifts_after_two_healthy_windows(self):
        first = comparison._compute_hash_fetch_adjustment(
            current_limit=32,
            max_limit=48,
            floor_limit=16,
            step=8,
            processed_total=800,
            window_processed=200,
            window_failed=5,
            window_timed_out=5,
            render_queue_depth=10,
            aux_queue_depth=5,
            finalize_queue_depth=3,
            result_queue_max=1000,
            fd_usage_ratio=0.20,
            ram_usage_ratio=0.30,
            consecutive_pressure_windows=0,
            consecutive_healthy_windows=0,
        )
        self.assertFalse(first["should_upshift"])
        second = comparison._compute_hash_fetch_adjustment(
            current_limit=32,
            max_limit=48,
            floor_limit=16,
            step=8,
            processed_total=1000,
            window_processed=220,
            window_failed=5,
            window_timed_out=5,
            render_queue_depth=8,
            aux_queue_depth=4,
            finalize_queue_depth=2,
            result_queue_max=1000,
            fd_usage_ratio=0.20,
            ram_usage_ratio=0.30,
            consecutive_pressure_windows=first["next_consecutive_pressure_windows"],
            consecutive_healthy_windows=first["next_consecutive_healthy_windows"],
        )
        self.assertTrue(second["should_upshift"])
        self.assertEqual(40, second["next_limit"])

    def test_hash_adjustment_downshifts_on_pressure(self):
        first = comparison._compute_hash_fetch_adjustment(
            current_limit=64,
            max_limit=96,
            floor_limit=32,
            step=8,
            processed_total=1200,
            window_processed=150,
            window_failed=60,
            window_timed_out=40,
            render_queue_depth=600,
            aux_queue_depth=500,
            finalize_queue_depth=400,
            result_queue_max=800,
            fd_usage_ratio=0.80,
            ram_usage_ratio=0.40,
            consecutive_pressure_windows=0,
            consecutive_healthy_windows=0,
        )
        self.assertFalse(first["should_downshift"])
        second = comparison._compute_hash_fetch_adjustment(
            current_limit=64,
            max_limit=96,
            floor_limit=32,
            step=8,
            processed_total=1400,
            window_processed=150,
            window_failed=60,
            window_timed_out=40,
            render_queue_depth=600,
            aux_queue_depth=500,
            finalize_queue_depth=400,
            result_queue_max=800,
            fd_usage_ratio=0.80,
            ram_usage_ratio=0.40,
            consecutive_pressure_windows=first["next_consecutive_pressure_windows"],
            consecutive_healthy_windows=0,
        )
        self.assertTrue(second["should_downshift"])
        self.assertEqual(56, second["next_limit"])

    def test_desired_hash_worker_nodes_respects_pages_per_node_limits(self):
        desired = comparison._desired_hash_worker_nodes(64)
        self.assertGreaterEqual(desired, comparison.HASH_WORKER_NODES_START)
        self.assertLessEqual(desired, comparison.HASH_WORKER_NODES_MAX)

    def test_drain_asyncio_queue_nowait_drains_all_items(self):
        async def _exercise():
            queue = asyncio.Queue()
            for value in (1, 2, 3):
                await queue.put(value)
            drained = comparison._drain_asyncio_queue_nowait(queue)
            self.assertEqual(3, drained)
            self.assertEqual(0, queue.qsize())
            await asyncio.wait_for(queue.join(), timeout=0.1)

        asyncio.run(_exercise())

    def test_build_stage2_hash_export_row_exact_mode_includes_raw_and_derived_fields(self):
        row = comparison._build_stage2_hash_export_row(
            {
                "hashed_at_utc": "2026-04-07T10:11:12Z",
                "source_workbook": "A.xlsx",
                "raw_url": "https://phish.example/login",
                "normalized_url": "https://phish.example/login",
                "final_landing_url": "https://phish.example/login",
                "domain": "phish.example",
                "final_domain": "phish.example",
                "hash_mode": "exact",
                "fetch_status": "fetched",
                "visual_status": "available",
                "target_url_sha256": "urlsha",
                "favicon_hash_raw": "favsha",
                "ssl_hash_raw": "sslsha",
                "html_hash_raw": "htmlsha",
                "page_hash_raw": "",
                "domain_hash_raw": "domainsha",
                "best_entity": "Brand",
                "best_matching_domain": "brand.com",
                "best_score": 71.25,
                "confidence_band": "High",
                "score_margin": 12.5,
                "lexical_score": 0.91,
                "favicon_hash_similarity": 1.0,
                "favicon_hash_distance": 0,
                "page_hash_similarity": 1.0,
                "page_hash_distance": 0,
                "domain_hash_similarity": 1.0,
                "domain_hash_distance": 0,
                "ssl_hash_similarity": 1.0,
                "ssl_hash_distance": 0,
                "signal_hit_favicon": True,
                "signal_hit_ssl_hash": True,
                "signal_hit_html_hash": True,
                "signal_hit_domain_hash": True,
                "hash_anchor": True,
                "admission_path": "exact_hash_anchor",
                "review_reason": "",
            },
            run_id="run_test",
            export_workbook="A.xlsx",
        )
        self.assertEqual("exact", row["hash_mode"])
        self.assertEqual("htmlsha", row["html_hash_raw"])
        self.assertEqual("", row["page_hash_raw"])
        self.assertEqual("favsha", row["favicon_hash_raw"])
        self.assertEqual(71.25, row["hash_score"])
        self.assertTrue(row["signal_hit_html_hash"])

    def test_build_stage2_hash_export_row_similarity_mode_uses_page_hash_raw(self):
        row = comparison._build_stage2_hash_export_row(
            {
                "hashed_at_utc": "2026-04-07T10:11:12Z",
                "source_workbook": "A.xlsx",
                "raw_url": "https://phish.example/login",
                "normalized_url": "https://phish.example/login",
                "final_landing_url": "https://landing.example/login",
                "domain": "phish.example",
                "final_domain": "landing.example",
                "hash_mode": "similarity",
                "fetch_status": "fetched",
                "visual_status": "available",
                "target_url_sha256": "urlsha",
                "favicon_hash_raw": "favsha",
                "ssl_hash_raw": "sslsha",
                "html_hash_raw": "",
                "page_hash_raw": "pagesha",
                "domain_hash_raw": "domainsha",
                "best_entity": "Brand",
                "best_matching_domain": "brand.com",
                "hash_score": 66.5,
                "confidence_band": "Medium",
                "score_margin": 8.5,
                "lexical_score": 0.85,
            },
            run_id="run_test",
            export_workbook="A.xlsx",
        )
        self.assertEqual("similarity", row["hash_mode"])
        self.assertEqual("", row["html_hash_raw"])
        self.assertEqual("pagesha", row["page_hash_raw"])
        self.assertEqual("landing.example", row["final_domain"])

    def test_write_stage2_hash_exports_duplicates_multi_workbook_rows(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run_context = build_run_context(output_dir=temp_dir, run_id="run_test")
            run_context.started_at = "2026-04-07T10:11:12Z"
            written_paths = comparison._write_stage2_hash_exports(
                [
                    {
                        "source_workbook": "A.xlsx|B.xlsx",
                        "raw_url": "https://phish.example/login",
                        "normalized_url": "https://phish.example/login",
                        "domain": "phish.example",
                        "final_domain": "phish.example",
                        "hash_mode": "exact",
                        "hashed_at_utc": "2026-04-07T10:11:12Z",
                    }
                ],
                run_context=run_context,
            )
            self.assertEqual(2, len(written_paths))
            basenames = {os.path.basename(path) for path in written_paths}
            self.assertIn("A__stage2_hashes__20260407_101112.csv", basenames)
            self.assertIn("B__stage2_hashes__20260407_101112.csv", basenames)
            for export_path in written_paths:
                with open(export_path, newline="", encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
                self.assertEqual(1, len(rows))
                self.assertEqual("A.xlsx|B.xlsx", rows[0]["source_workbook"])
                self.assertIn(rows[0]["export_workbook"], {"A.xlsx", "B.xlsx"})

    def test_write_stage2_hash_exports_keeps_failure_rows(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            run_context = build_run_context(output_dir=temp_dir, run_id="run_test")
            written_paths = comparison._write_stage2_hash_exports(
                [
                    {
                        "source_workbook": "A.xlsx",
                        "raw_url": "https://dead.example",
                        "normalized_url": "https://dead.example",
                        "fetch_status": "failed",
                        "visual_status": "not_attempted",
                        "fetch_error_type": "navigation_timeout",
                        "fetch_error_detail": "timed out",
                        "domain": "dead.example",
                        "hash_mode": "exact",
                        "hashed_at_utc": "2026-04-07T10:11:12Z",
                    }
                ],
                run_context=run_context,
            )
            self.assertEqual(1, len(written_paths))
            with open(written_paths[0], newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(1, len(rows))
            self.assertEqual("failed", rows[0]["fetch_status"])
            self.assertEqual("navigation_timeout", rows[0]["fetch_error_type"])
            self.assertEqual("", rows[0]["favicon_hash_raw"])
            self.assertEqual("", rows[0]["html_hash_raw"])

    def test_write_stage1_debug_csv_ignores_additive_hash_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "stage1_debug.csv")
            written_path = comparison._write_stage1_debug_csv(
                [
                    {
                        "input_position": 1,
                        "input_url": "airindiaair.com",
                        "normalized_url": "https://airindiaair.com",
                        "source_workbook": "A.xlsx",
                        "reason": "",
                        "hash_mode": "exact",
                        "raw_url": "https://airindiaair.com",
                        "hashed_at_utc": "2026-04-07T14:41:01Z",
                        "target_url_sha256": "abc",
                        "favicon_hash_raw": "fav",
                        "review_reason": "strict_lexical_below_holdout_threshold",
                    }
                ],
                output_path=output_path,
            )
            with open(written_path, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(1, len(rows))
            self.assertEqual("exact", rows[0]["hash_mode"])
            self.assertEqual("fav", rows[0]["favicon_hash_raw"])
            self.assertEqual("strict_lexical_below_holdout_threshold", rows[0]["review_reason"])


if __name__ == "__main__":
    unittest.main()
