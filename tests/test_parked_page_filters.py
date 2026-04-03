import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

from phishing_pipeline import comparison, pipeline


def _prefetch_metrics(**overrides):
    metrics = {
        "strict_lexical_hit": True,
        "lexical_score_pass": True,
        "fallback_rank_only": False,
        "old_fuzzy_hit": False,
        "old_fuzzy_cse": "",
        "hybrid_lexical_hit": True,
        "candidate_generation_reason": "brand_token_match|jw_primary",
        "best_entity": "State Bank of India (SBI)",
        "best_lexical_score": 0.98,
        "best_typo_similarity": 0.91,
        "best_jw_score": 0.98,
        "best_token_score": 0.94,
        "lexical_rule_hit": True,
        "brand_token_hit": True,
    }
    metrics.update(overrides)
    return metrics


class _DummyRateLimiter:
    async def acquire(self):
        return None


class ParkedPageDetectorTests(unittest.TestCase):
    def test_detects_provider_redirect(self):
        detected = comparison.detect_parked_page_signals(
            original_url="https://brand-login-check.com",
            final_landing_url="https://www.afternic.com/forsale/brand-login-check.com",
            title_text="Buy this domain",
            visible_text="This domain is for sale",
        )

        self.assertTrue(detected["is_parked"])
        self.assertEqual(detected["parking_provider"], "GoDaddy/Afternic")
        self.assertEqual(detected["parking_reason"], "provider_host_redirect")

    def test_detects_branded_sale_template(self):
        detected = comparison.detect_parked_page_signals(
            original_url="https://brand-login-check.com",
            final_landing_url="https://brand-login-check.com",
            title_text="Buy this domain",
            visible_text="Lease to own this premium domain on Dan.com",
        )

        self.assertTrue(detected["is_parked"])
        self.assertEqual(detected["parking_provider"], "Dan")
        self.assertEqual(detected["parking_reason"], "provider_branded_parking_template")

    def test_ignores_regular_content_with_registrar_mention(self):
        detected = comparison.detect_parked_page_signals(
            original_url="https://example.org",
            final_landing_url="https://example.org",
            title_text="Example Org",
            visible_text="Our migration away from GoDaddy hosting finished last week.",
        )

        self.assertFalse(detected["is_parked"])

    def test_parked_payload_is_not_shortlisted_even_with_high_lexical_score(self):
        payload_outcome = comparison._handle_stage1_fetch_payload(
            payload={
                "url": "https://brand-login-check.com",
                "normalized_url": "https://brand-login-check.com",
                "fetch_status": "parked",
                "final_landing_url": "https://www.afternic.com/forsale/brand-login-check.com",
                "parking_provider": "GoDaddy/Afternic",
                "parking_reason": "provider_host_redirect",
            },
            normalized_url="https://brand-login-check.com",
            prefetch_metrics=_prefetch_metrics(best_lexical_score=0.995),
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertIsNone(payload_outcome["queue_payload"])
        self.assertIsNone(payload_outcome["admitted_prefetch_match"])
        self.assertEqual(payload_outcome["metric_key"], "fetch_parked")
        self.assertFalse(payload_outcome["decision_row"]["admitted"])
        self.assertEqual(payload_outcome["decision_row"]["reason"], "parked_page")

    def test_parked_rows_are_written_to_dedicated_audit(self):
        input_url = "brand-login-check.com"
        normalized_url = comparison.normalize_url(input_url)
        prefetch = _prefetch_metrics()
        stage1_rows = comparison._build_stage1_debug_rows(
            input_urls=[input_url],
            audit_rows=[{"dns_status": "resolved", "decision": "accepted"}],
            decision_rows=[
                comparison._build_prefetch_decision_row(
                    normalized_url=normalized_url,
                    fetch_status="parked",
                    prefetch_metrics=prefetch,
                    scoring_config=comparison._DEFAULT_SCORING_CONFIG,
                    final_landing_url="https://www.afternic.com/forsale/brand-login-check.com",
                    parking_provider="GoDaddy/Afternic",
                    parking_reason="provider_host_redirect",
                )
            ],
            prefetch_metrics_map={normalized_url: prefetch},
        )

        self.assertEqual(stage1_rows[0]["reason"], "parked_page")
        self.assertEqual(stage1_rows[0]["parking_provider"], "GoDaddy/Afternic")

        with tempfile.TemporaryDirectory() as tmpdir:
            parked_audit_path = Path(tmpdir) / "parked_page_exclusions.csv"
            comparison._write_stage1_subset_csv(
                stage1_rows,
                str(parked_audit_path),
                lambda row: row.get("reason") == "parked_page",
            )
            parked_df = pd.read_csv(parked_audit_path)

        self.assertEqual(len(parked_df), 1)
        self.assertEqual(parked_df.loc[0, "parking_provider"], "GoDaddy/Afternic")
        self.assertEqual(parked_df.loc[0, "parking_reason"], "provider_host_redirect")


class HashOnlyClassificationTests(unittest.TestCase):
    def test_fetch_failed_lexical_only_defaults_to_legitimate(self):
        classification = pipeline._hybrid_hash_classification(
            row={
                "fetch_status": "timeout",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "clip_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "typo_anchor": False,
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(classification, "Legitimate")

    def test_fetch_failed_with_suspicious_infra_stays_suspected(self):
        classification = pipeline._hybrid_hash_classification(
            row={
                "fetch_status": "failed",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "clip_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "typo_anchor": False,
            },
            registrar="NameCheap, Inc.",
            hosting_isp="NA",
            dns_records="A:1.1.1.1",
        )

        self.assertEqual(classification, "Suspected")


class ParkedHoldoutReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_reused_holdout_parked_row_is_skipped_from_final_output(self):
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
                    "fetch_status": "fetched",
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
                    "html_title_text": "Buy this domain | HugeDomains",
                    "visible_text_excerpt": "This domain is for sale. Buy this domain from HugeDomains today.",
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
                    whois_rate_limiter=_DummyRateLimiter(),
                    high_confidence_threshold=78.0,
                    medium_confidence_threshold=68.0,
                )

            self.assertEqual(len(result), 0)
            final_df = pd.read_csv(final_output)
            self.assertEqual(len(final_df), 0)
            stage3_df = pd.read_csv(stage3_debug)
            self.assertEqual(len(stage3_df), 1)
            self.assertEqual(stage3_df.loc[0, "classification"], "SKIPPED_PARKED_PAGE")
            self.assertEqual(stage3_df.loc[0, "parking_provider"], "HugeDomains")


if __name__ == "__main__":
    unittest.main()
