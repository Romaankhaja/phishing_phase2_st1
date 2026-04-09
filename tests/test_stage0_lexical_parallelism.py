import unittest
from unittest import mock

import numpy as np

from phishing_pipeline import comparison


class Stage0LexicalParallelismTests(unittest.TestCase):
    def setUp(self):
        self.scoring_config = comparison._DEFAULT_SCORING_CONFIG
        self.urls = [
            "https://login-sbi-secure-example.com",
            "https://airindia-support-check.com",
            "https://nic-gov-portal-login.net",
            "https://axis-bank-verify.example",
            "https://gov-in-service-center-help.org",
            "https://customer-portal-example.net",
        ]

    def _assert_prefetch_state_equal(self, expected: dict, actual: dict):
        exact_keys = (
            "normalized_url",
            "domain",
            "best_idx",
            "best_entity",
            "best_matching_domain",
            "candidate_generation_reason",
            "lexical_rule_hit",
            "brand_token_hit",
            "generic_token_only_match",
            "hybrid_lexical_hit",
            "strict_lexical_hit",
            "lexical_score_pass",
            "fallback_rank_only",
            "old_fuzzy_hit",
            "old_fuzzy_cse",
            "old_fuzzy_domain",
            "candidate_reasons",
            "best_matching_domains",
        )
        float_keys = (
            "best_lexical_score",
            "best_jw_score",
            "best_token_score",
            "best_typo_similarity",
            "old_fuzzy_score",
        )
        array_keys = (
            "lexical_scores",
            "jw_scores",
            "token_scores",
            "typo_scores",
            "lexical_rule_hits",
            "brand_token_hits",
            "generic_token_only_hits",
            "candidate_mask",
        )

        for key in exact_keys:
            self.assertEqual(expected[key], actual[key], key)
        for key in float_keys:
            self.assertAlmostEqual(expected[key], actual[key], places=12, msg=key)
        for key in array_keys:
            np.testing.assert_array_equal(expected[key], actual[key], err_msg=key)

    def test_prefetch_batch_matches_single_item_evaluator(self):
        normalized_urls = [comparison.normalize_url(url) for url in self.urls]
        lexical_eval_config = (
            int(self.scoring_config["typo_top_k"]),
            float(self.scoring_config["lexical_pass_min_score"]),
        )

        expected_results = [
            comparison._compute_prefetch_lexical_state(url, self.scoring_config)
            for url in self.urls
        ]
        actual_results = comparison._compute_prefetch_lexical_state_batch(
            normalized_urls,
            lexical_eval_config,
        )

        self.assertEqual(len(expected_results), len(actual_results))
        for expected, actual in zip(expected_results, actual_results):
            self._assert_prefetch_state_equal(expected, actual)

    def test_stage0_process_pool_matches_single_item_evaluator(self):
        normalized_urls = [comparison.normalize_url(url) for url in self.urls]
        expected_map = {
            normalized_url: comparison._compute_prefetch_lexical_state(url, self.scoring_config)
            for url, normalized_url in zip(self.urls, normalized_urls)
        }

        with (
            mock.patch.object(comparison, "LEXICAL_WORKERS", 2),
            mock.patch.object(comparison, "LEXICAL_BATCH_SIZE", 2),
            mock.patch.object(comparison, "LEXICAL_INFLIGHT_BATCHES", 2),
            mock.patch.object(comparison, "LEXICAL_PROGRESS_INTERVAL_S", 60.0),
        ):
            try:
                actual_map, stats = comparison._compute_stage0_prefetch_metrics_parallel(
                    normalized_urls,
                    self.scoring_config,
                    original_count=len(normalized_urls),
                    metric_input_counts={url: 1 for url in normalized_urls},
                )
            except PermissionError as exc:
                self.skipTest(f"ProcessPoolExecutor unavailable in this environment: {exc}")

        self.assertEqual(stats["metric_urls_total"], len(normalized_urls))
        self.assertEqual(stats["metric_urls_completed"], len(normalized_urls))
        self.assertEqual(stats["batches_completed"], stats["batches_total"])
        self.assertGreaterEqual(stats["avg_batch_latency_ms"], 0.0)

        for normalized_url in normalized_urls:
            self._assert_prefetch_state_equal(
                expected_map[normalized_url],
                actual_map[normalized_url],
            )

    def test_stage0_thread_executor_keeps_prefetch_logic_unchanged(self):
        normalized_urls = [comparison.normalize_url(url) for url in self.urls]
        expected_map = {
            normalized_url: comparison._compute_prefetch_lexical_state(url, self.scoring_config)
            for url, normalized_url in zip(self.urls, normalized_urls)
        }

        with (
            mock.patch.object(comparison, "_resolve_shortlist_cpu_executor_mode", return_value="thread"),
            mock.patch.object(comparison, "ProcessPoolExecutor", side_effect=AssertionError("process pool should not be used")),
            mock.patch.object(comparison, "LEXICAL_WORKERS", 2),
            mock.patch.object(comparison, "LEXICAL_BATCH_SIZE", 2),
            mock.patch.object(comparison, "LEXICAL_INFLIGHT_BATCHES", 2),
            mock.patch.object(comparison, "LEXICAL_PROGRESS_INTERVAL_S", 60.0),
        ):
            actual_map, stats = comparison._compute_stage0_prefetch_metrics_parallel(
                normalized_urls,
                self.scoring_config,
                original_count=len(normalized_urls),
                metric_input_counts={url: 1 for url in normalized_urls},
            )

        self.assertEqual(stats["metric_urls_total"], len(normalized_urls))
        self.assertEqual(stats["metric_urls_completed"], len(normalized_urls))
        self.assertEqual(stats["batches_completed"], stats["batches_total"])

        for normalized_url in normalized_urls:
            self._assert_prefetch_state_equal(
                expected_map[normalized_url],
                actual_map[normalized_url],
            )


if __name__ == "__main__":
    unittest.main()
