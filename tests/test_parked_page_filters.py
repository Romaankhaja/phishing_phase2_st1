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


class Stage1PayloadTests(unittest.TestCase):
    def test_failed_payload_no_longer_uses_parking_exclusion_reason(self):
        payload_outcome = comparison._handle_stage1_fetch_payload(
            payload={
                "url": "https://brand-login-check.com",
                "normalized_url": "https://brand-login-check.com",
                "fetch_status": "failed",
                "parking_provider": "HugeDomains",
                "parking_reason": "provider_branded_parking_template",
            },
            normalized_url="https://brand-login-check.com",
            prefetch_metrics=_prefetch_metrics(best_lexical_score=0.995),
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertIsNone(payload_outcome["queue_payload"])
        self.assertEqual(payload_outcome["metric_key"], "fetch_failed")
        self.assertEqual(payload_outcome["decision_row"].get("reason", ""), "")
        self.assertEqual(
            payload_outcome["decision_row"].get("parking_reason", ""),
            "provider_branded_parking_template",
        )

    def test_failed_strict_lexical_payload_is_not_rescued_into_holdout(self):
        payload_outcome = comparison._handle_stage1_fetch_payload(
            payload={
                "url": "https://brand-login-check.com",
                "normalized_url": "https://brand-login-check.com",
                "fetch_status": "failed",
                "visual_status": "not_attempted",
                "fetch_error_type": "navigation_error",
                "fetch_error_detail": "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://brand-login-check.com/",
            },
            normalized_url="https://brand-login-check.com",
            prefetch_metrics=_prefetch_metrics(best_lexical_score=0.995),
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertIsNone(payload_outcome["queue_payload"])
        self.assertIsNone(payload_outcome["admitted_prefetch_match"])


class HashOnlyClassificationTests(unittest.TestCase):
    def test_hybrid_decision_treats_parking_fields_as_suspicious(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "placeholder_or_parking_reason": "provider_branded_parking_template",
                "parking_reason": "provider_branded_parking_template",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "typo_anchor": True,
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertEqual(decision["classification_gate_reason"], "parked_sale_lexical_suspected")


class HoldoutReplayTests(unittest.IsolatedAsyncioTestCase):
    async def test_reused_holdout_with_parking_fields_is_suspected(self):
        base_row = {
            "Cooresponding CSE": "State Bank of India (SBI)",
            "Legitimate Domains": "sbi.co.in",
            "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            "hash_score": 66.0,
            "confidence_band": "Low",
            "score_margin": 1.0,
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
            "visual_status": "available",
            "fetch_error_type": "",
            "fetch_error_detail": "",
            "final_landing_url": "https://brand-login-check.com/login",
            "parking_provider": "HugeDomains",
            "parking_reason": "provider_branded_parking_template",
            "best_score": 66.0,
            "domain_component": 29.4,
            "hash_component": 0.0,
            "typo_similarity": 0.91,
            "typo_min_score_used": 0.45,
            "typo_decision_reason": "anchor_typo",
            "typo_anchor": True,
            "hash_anchor": False,
            "signal_hit_typo": True,
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

        class _FakeResponse:
            status_code = 500

            def json(self):
                return {}

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, *args, **kwargs):
                return _FakeResponse()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            holdout_csv = tmpdir_path / "holdout.csv"
            final_output = tmpdir_path / "output_file.csv"
            review_queue = tmpdir_path / "hash_review_queue.csv"
            stage2_debug = tmpdir_path / "stage2_model_debug.csv"
            stage3_debug = tmpdir_path / "stage3_classification_debug.csv"
            checkpoint = tmpdir_path / "checkpoint_records.csv"

            pd.DataFrame([base_row]).to_csv(holdout_csv, index=False)
            replayed_df = pd.read_csv(holdout_csv)

            with (
                mock.patch.object(pipeline, "FINAL_OUTPUT", str(final_output)),
                mock.patch.object(pipeline, "HASH_REVIEW_QUEUE_PATH", str(review_queue)),
                mock.patch.object(pipeline, "STAGE2_MODEL_DEBUG_PATH", str(stage2_debug)),
                mock.patch.object(pipeline, "STAGE3_CLASSIFICATION_DEBUG_PATH", str(stage3_debug)),
                mock.patch.object(pipeline, "CHECKPOINT_CSV", str(checkpoint)),
                mock.patch.object(pipeline, "load_models_and_preproc", side_effect=RuntimeError("models not needed")),
                mock.patch.object(pipeline, "extract_network_features_async", new=mock.AsyncMock(return_value={"ip_address": "1.2.3.4"})),
                mock.patch.object(
                    pipeline,
                    "enrich_with_geoip",
                    side_effect=lambda df, *_args, **_kwargs: df.assign(asn_org="NA", country="NA"),
                ),
                mock.patch.object(pipeline.httpx, "AsyncClient", _FakeAsyncClient),
                mock.patch.object(pipeline.socket, "gethostbyname", side_effect=OSError("offline")),
                mock.patch.object(pipeline.whois, "whois", side_effect=RuntimeError("offline")),
                mock.patch.object(pipeline.dns.resolver, "resolve", side_effect=RuntimeError("offline")),
            ):
                result = await pipeline._run_hash_only_pipeline(
                    df_filtered=replayed_df,
                    whois_rate_limiter=_DummyRateLimiter(),
                    high_confidence_threshold=78.0,
                    medium_confidence_threshold=68.0,
                )

            filtered_output = Path(str(final_output).replace(".csv", "_filtered.csv"))
            self.assertEqual(len(result), 1)
            final_df = pd.read_csv(final_output)
            self.assertEqual(len(final_df), 1)
            self.assertEqual(
                final_df.loc[0, "Phishing/Suspected Domains (i.e. Class Label)"],
                "Suspected",
            )
            filtered_df = pd.read_csv(filtered_output)
            self.assertEqual(len(filtered_df), 1)
            review_df = pd.read_csv(review_queue)
            self.assertEqual(len(review_df), 0)
            stage3_df = pd.read_csv(stage3_debug)
            self.assertEqual(len(stage3_df), 1)
            self.assertEqual(stage3_df.loc[0, "classification"], "Suspected")
            self.assertEqual(
                stage3_df.loc[0, "classification_gate_reason"],
                "parked_sale_lexical_suspected",
            )

    async def test_zero_corroboration_legitimate_row_goes_to_review_queue_only(self):
        df_filtered = pd.DataFrame(
            [
                {
                    "Cooresponding CSE": "State Bank of India (SBI)",
                    "Legitimate Domains": "sbi.co.in",
                    "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
                    "hash_score": 66.0,
                    "confidence_band": "Low",
                    "evidence_tier": "weak_evidence",
                    "lexical_score": 0.98,
                    "strict_lexical_hit": True,
                    "lexical_score_pass": True,
                    "fallback_rank_only": False,
                    "fetch_status": "fetched",
                    "visual_status": "available",
                    "final_landing_url": "https://brand-login-check.com/login",
                    "hash_anchor": False,
                    "direct_brand_evidence_count": 0,
                    "signal_hit_domain": False,
                    "signal_hit_keywords": False,
                    "screenshot_path": "",
                    "html_title_text": "Customer Login",
                    "visible_text_excerpt": "Secure account sign-in page for customers.",
                }
            ]
        )

        class _FakeResponse:
            status_code = 500

            def json(self):
                return {}

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, *args, **kwargs):
                return _FakeResponse()

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
                mock.patch.object(pipeline, "extract_network_features_async", new=mock.AsyncMock(return_value={})),
                mock.patch.object(
                    pipeline,
                    "enrich_with_geoip",
                    side_effect=lambda df, *_args, **_kwargs: df.assign(asn_org="NA", country="NA", ip_address="NA"),
                ),
                mock.patch.object(pipeline.httpx, "AsyncClient", _FakeAsyncClient),
                mock.patch.object(pipeline.socket, "gethostbyname", side_effect=OSError("offline")),
                mock.patch.object(pipeline.whois, "whois", side_effect=RuntimeError("offline")),
                mock.patch.object(pipeline.dns.resolver, "resolve", side_effect=RuntimeError("offline")),
            ):
                result = await pipeline._run_hash_only_pipeline(
                    df_filtered=df_filtered,
                    whois_rate_limiter=_DummyRateLimiter(),
                    high_confidence_threshold=78.0,
                    medium_confidence_threshold=68.0,
                )

            filtered_output = Path(str(final_output).replace(".csv", "_filtered.csv"))
            self.assertEqual(len(result), 0)
            final_df = pd.read_csv(final_output)
            self.assertEqual(len(final_df), 0)
            filtered_df = pd.read_csv(filtered_output)
            self.assertEqual(len(filtered_df), 0)
            review_df = pd.read_csv(review_queue)
            self.assertEqual(len(review_df), 1)
            self.assertEqual(review_df.loc[0, "final_classification"], "Legitimate")
            stage3_df = pd.read_csv(stage3_debug)
            self.assertEqual(stage3_df.loc[0, "classification"], "Legitimate")
            self.assertEqual(
                stage3_df.loc[0, "classification_gate_reason"],
                "lexical_without_any_corroboration_legitimate_review",
            )

    async def test_not_registered_domain_routes_to_suspected(self):
        df_filtered = pd.DataFrame(
            [
                {
                    "Cooresponding CSE": "National Informatics Centre",
                    "Legitimate Domains": "nic.in",
                    "Identified Phishing/Suspected Domain Name": "https://unused-example-domain.click",
                    "hash_score": 69.0,
                    "confidence_band": "Medium",
                    "evidence_tier": "weak_evidence",
                    "lexical_score": 0.92,
                    "strict_lexical_hit": True,
                    "lexical_score_pass": True,
                    "fallback_rank_only": False,
                    "fetch_status": "fetched",
                    "visual_status": "available",
                    "final_landing_url": "https://unused-example-domain.click",
                    "hash_anchor": False,
                    "direct_brand_evidence_count": 0,
                    "signal_hit_keywords": False,
                }
            ]
        )

        class _Fake404Response:
            status_code = 404

            def json(self):
                return {}

        class _FakeAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, *args, **kwargs):
                return _Fake404Response()

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
                mock.patch.object(pipeline, "extract_network_features_async", new=mock.AsyncMock(return_value={"ip_address": "1.2.3.4"})),
                mock.patch.object(pipeline.httpx, "AsyncClient", _FakeAsyncClient),
                mock.patch.object(pipeline.socket, "gethostbyname", side_effect=OSError("offline")),
            ):
                result = await pipeline._run_hash_only_pipeline(
                    df_filtered=df_filtered,
                    whois_rate_limiter=_DummyRateLimiter(),
                    high_confidence_threshold=78.0,
                    medium_confidence_threshold=68.0,
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
            stage3_df = pd.read_csv(stage3_debug)
            self.assertEqual(stage3_df.loc[0, "classification"], "Suspected")
            self.assertEqual(
                stage3_df.loc[0, "classification_gate_reason"],
                "not_registered_domain_suspected",
            )


if __name__ == "__main__":
    unittest.main()
