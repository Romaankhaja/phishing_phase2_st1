import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd
from pandas.errors import EmptyDataError

from phishing_pipeline import comparison, pipeline


class LexicalGateTests(unittest.TestCase):
    def test_strict_hit_passes_lexical_gate(self):
        self.assertTrue(
            comparison._passes_lexical_gate(
                {
                    "strict_lexical_hit": True,
                    "lexical_score_pass": False,
                    "fallback_rank_only": True,
                }
            )
        )

    def test_score_pass_without_fallback_passes_lexical_gate(self):
        self.assertTrue(
            comparison._passes_lexical_gate(
                {
                    "strict_lexical_hit": False,
                    "lexical_score_pass": True,
                    "fallback_rank_only": False,
                }
            )
        )

    def test_fallback_only_candidate_fails_lexical_gate(self):
        self.assertFalse(
            comparison._passes_lexical_gate(
                {
                    "strict_lexical_hit": False,
                    "lexical_score_pass": True,
                    "fallback_rank_only": True,
                }
            )
        )


class Stage1FetchPayloadTests(unittest.TestCase):
    def test_fetched_visual_missing_stays_in_scoring_queue(self):
        outcome = comparison._handle_stage1_fetch_payload(
            payload={
                "url": "https://brand-login-check.com",
                "normalized_url": "https://brand-login-check.com",
                "fetch_status": "fetched_visual_missing",
                "visual_status": "missing",
                "fetch_error_type": "screenshot_timeout",
                "fetch_error_detail": "screenshot timed out",
            },
            normalized_url="https://brand-login-check.com",
            prefetch_metrics={
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "best_lexical_score": 0.98,
                "best_typo_similarity": 0.91,
                "old_fuzzy_hit": False,
                "old_fuzzy_cse": "",
                "hybrid_lexical_hit": True,
                "candidate_generation_reason": "brand_token_match|jw_primary",
                "best_entity": "State Bank of India (SBI)",
            },
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertIsNone(outcome["decision_row"])
        self.assertIsNone(outcome["admitted_prefetch_match"])
        self.assertIsNotNone(outcome["queue_payload"])
        self.assertEqual(outcome["metric_key"], "hashed_success")


class AccuracyFirstPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_fetched_visual_missing_uses_fetched_classification_path(self):
        classification = pipeline._hybrid_hash_classification(
            row={
                "fetch_status": "fetched_visual_missing",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": True,
                "clip_anchor": False,
                "signal_hit_domain": True,
                "signal_hit_keywords": False,
                "typo_anchor": True,
                "lexical_score": 0.95,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NameCheap, Inc.",
            hosting_isp="Cloudflare, Inc.",
            dns_records="A:1.1.1.1",
        )

        self.assertEqual(classification, "Phishing")

    async def test_failed_rows_can_be_routed_to_review_with_rescue_threshold(self):
        df_filtered = pd.DataFrame(
            [
                {
                    "Cooresponding CSE": "State Bank of India (SBI)",
                    "Legitimate Domains": "sbi.co.in",
                    "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
                    "hash_score": 0.0,
                    "confidence_band": "Low",
                    "score_margin": 0.0,
                    "evidence_tier": "weak_evidence",
                    "lexical_score": 0.98,
                    "jw_primary": 0.98,
                    "token_set_primary": 0.94,
                    "skeleton_similarity": 0.91,
                    "lexical_rule_hit": True,
                    "brand_token_hit": True,
                    "candidate_generation_reason": "brand_token_match|jw_primary",
                    "dominant_signal_family": "lexical",
                    "old_fuzzy_hit": False,
                    "old_fuzzy_cse": "",
                    "hybrid_lexical_hit": True,
                    "strict_lexical_hit": True,
                    "lexical_score_pass": True,
                    "fallback_rank_only": False,
                    "admission_reason": "strict_lexical_hit",
                    "admission_path": "strict_lexical_hit",
                    "fetch_status": "timeout",
                    "visual_status": "not_attempted",
                    "fetch_error_type": "navigation_timeout",
                    "fetch_error_detail": "timed out",
                    "best_score": 0.0,
                    "domain_component": 29.4,
                    "clip_component": 0.0,
                    "hash_component": 0.0,
                    "typo_similarity": 0.91,
                    "typo_min_score_used": 0.45,
                    "typo_decision_reason": "anchor_typo",
                    "clip_similarity": 0.0,
                    "typo_anchor": False,
                    "hash_anchor": False,
                    "clip_anchor": False,
                    "signal_hit_screenshot": False,
                    "signal_hit_typo": False,
                    "signal_hit_domain": False,
                    "signal_hit_favicon": False,
                    "signal_hit_ssl_hash": False,
                    "signal_hit_html_hash": False,
                    "signal_hit_domain_hash": False,
                    "signal_hit_keywords": False,
                    "screenshot_path": "",
                    "html_title_text": "",
                    "visible_text_excerpt": "",
                }
            ]
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            final_output = tmpdir_path / "output_file.csv"
            review_queue = tmpdir_path / "hash_review_queue.csv"
            stage2_debug = tmpdir_path / "stage2_model_debug.csv"
            stage3_debug = tmpdir_path / "stage3_classification_debug.csv"
            checkpoint = tmpdir_path / "checkpoint_records.csv"

            with (
                mock.patch.object(pipeline, "FINAL_OUTPUT", str(final_output)),
                mock.patch.object(pipeline, "HASH_REVIEW_QUEUE_PATH", str(review_queue)),
                mock.patch.object(pipeline, "STAGE2_MODEL_DEBUG_PATH", str(stage2_debug)),
                mock.patch.object(pipeline, "STAGE3_CLASSIFICATION_DEBUG_PATH", str(stage3_debug)),
                mock.patch.object(pipeline, "CHECKPOINT_CSV", str(checkpoint)),
                mock.patch.object(pipeline, "load_models_and_preproc", side_effect=RuntimeError("models not needed")),
            ):
                result = await pipeline._run_hash_only_pipeline(
                    df_filtered=df_filtered,
                    whois_rate_limiter=mock.AsyncMock(),
                    high_confidence_threshold=78.0,
                    medium_confidence_threshold=68.0,
                    failed_fetch_review_min=0.90,
                )

            self.assertEqual(len(result), 1)
            final_df = pd.read_csv(final_output)
            self.assertEqual(len(final_df), 1)
            self.assertEqual(
                final_df.loc[0, "Phishing/Suspected Domains (i.e. Class Label)"],
                "Suspected",
            )
            review_df = pd.read_csv(review_queue)
            self.assertEqual(len(review_df), 0)
            try:
                stage2_df = pd.read_csv(stage2_debug)
            except EmptyDataError:
                stage2_df = pd.DataFrame()
            try:
                stage3_df = pd.read_csv(stage3_debug)
            except EmptyDataError:
                stage3_df = pd.DataFrame()
            self.assertEqual(len(stage2_df), 1)
            self.assertEqual(
                stage2_df.loc[0, "model_feature_status"],
                "skipped_non_fetched_fetch_evidence_unavailable",
            )
            self.assertEqual(len(stage3_df), 1)
            self.assertEqual(stage3_df.loc[0, "classification"], "Suspected")
            self.assertEqual(
                stage3_df.loc[0, "classification_gate_reason"],
                "strict_lexical_fetch_evidence_unavailable_suspected",
            )


if __name__ == "__main__":
    unittest.main()
