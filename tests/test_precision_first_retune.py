import unittest
from unittest import mock

from phishing_pipeline import comparison, pipeline, utils


class Stage1AdmissionRetuneTests(unittest.TestCase):
    def test_strict_lexical_below_threshold_stays_review_only(self):
        decision = comparison._classify_stage1_admission(
            best_score=62.0,
            threshold=68.0,
            strict_lexical_hit=True,
            lexical_score_pass=True,
            hash_anchor=False,
        )

        self.assertFalse(decision["admitted_to_holdout"])
        self.assertTrue(decision["kept_for_review_only"])
        self.assertEqual(decision["review_only_reason"], "strict_lexical_below_holdout_threshold")

    def test_strict_lexical_with_network_corroboration_admits_to_holdout(self):
        decision = comparison._classify_stage1_admission(
            best_score=47.0,
            threshold=68.0,
            strict_lexical_hit=True,
            lexical_score_pass=True,
            hash_anchor=False,
            network_corroborated=True,
        )

        self.assertTrue(decision["admitted_to_holdout"])
        self.assertFalse(decision["kept_for_review_only"])
        self.assertIn("network_corroboration", decision["admission_paths"])

    def test_strict_lexical_with_parked_signal_admits_to_holdout(self):
        decision = comparison._classify_stage1_admission(
            best_score=47.0,
            threshold=68.0,
            strict_lexical_hit=True,
            lexical_score_pass=True,
            hash_anchor=False,
            parked_sale_signal=True,
        )

        self.assertTrue(decision["admitted_to_holdout"])
        self.assertFalse(decision["kept_for_review_only"])
        self.assertIn("parked_sale_signal", decision["admission_paths"])

    def test_hash_anchor_bypasses_threshold(self):
        decision = comparison._classify_stage1_admission(
            best_score=62.0,
            threshold=68.0,
            strict_lexical_hit=True,
            lexical_score_pass=True,
            hash_anchor=True,
        )

        self.assertTrue(decision["admitted_to_holdout"])
        self.assertFalse(decision["kept_for_review_only"])
        self.assertIn("hash_bypass_hit", decision["admission_paths"])

    def test_stage1_failed_miss_targeted_rescue_requires_high_risk_seed(self):
        should_rescue = comparison._should_rescue_stage1_failure_to_hashing(
            {
                "strict_lexical_hit": False,
                "lexical_score_pass": False,
                "fallback_rank_only": False,
                "old_fuzzy_hit": False,
                "best_lexical_score": 0.79,
                "best_typo_similarity": 0.82,
            },
            {
                "fetch_status": "failed",
                "fetch_error_type": "navigation_error",
                "fetch_error_detail": "ERR_NAME_NOT_RESOLVED",
            },
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertTrue(should_rescue)

    def test_stage1_failed_miss_without_high_risk_seed_is_not_rescued(self):
        should_rescue = comparison._should_rescue_stage1_failure_to_hashing(
            {
                "strict_lexical_hit": False,
                "lexical_score_pass": False,
                "fallback_rank_only": False,
                "old_fuzzy_hit": False,
                "best_lexical_score": 0.42,
                "best_typo_similarity": 0.31,
            },
            {
                "fetch_status": "failed",
                "fetch_error_type": "navigation_error",
                "fetch_error_detail": "ERR_NAME_NOT_RESOLVED",
            },
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertFalse(should_rescue)

    def test_high_risk_hash_candidate_gets_retry_attempt(self):
        should_retry = comparison._should_retry_high_risk_hash_fetch(
            {
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "best_lexical_score": 0.96,
                "best_typo_similarity": 0.91,
            },
            {},
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertTrue(should_retry)

    def test_low_risk_hash_candidate_does_not_get_retry_attempt(self):
        should_retry = comparison._should_retry_high_risk_hash_fetch(
            {
                "strict_lexical_hit": False,
                "lexical_score_pass": False,
                "fallback_rank_only": False,
                "old_fuzzy_hit": False,
                "best_lexical_score": 0.41,
                "best_typo_similarity": 0.29,
            },
            {},
            scoring_config=comparison._DEFAULT_SCORING_CONFIG,
        )

        self.assertFalse(should_retry)


class TvcStrictnessTests(unittest.TestCase):
    def _catalog(self):
        catalog = {}
        utils._add_brand_catalog_entry(
            catalog,
            "nic",
            aliases={"nic", "national informatics centre"},
            domains={"nic.in", "gov.in"},
            spoof_aliases={"national informatics centre"},
            auto_promote_primary_detection=True,
            auto_promote_primary_spoof=False,
        )
        utils._add_brand_catalog_entry(
            catalog,
            "sbi",
            aliases={"sbi", "state bank of india", "onlinesbi"},
            domains={"sbi.co.in", "onlinesbi.com"},
            spoof_aliases={"sbi", "state bank of india", "onlinesbi"},
            auto_promote_primary_detection=True,
            auto_promote_primary_spoof=False,
        )
        return catalog

    def test_html_only_generic_alias_does_not_spoof(self):
        catalog = self._catalog()
        with mock.patch.object(utils, "_get_tvc_brand_catalog", return_value=catalog):
            features = utils.extract_tvc_features(
                url="https://cloud-portal-login.com",
                ocr_header_text="",
                ocr_footer_text="",
                ocr_full_text="",
                html_text="NIC cloud access portal",
                shortlisted_cse="National Informatics Centre",
                shortlisted_domain="nic.in",
            )

        self.assertTrue(features["tvc_brand_detected"])
        self.assertFalse(features["tvc_brand_spoofed"])
        self.assertFalse(features["tvc_spoof_strong"])
        self.assertEqual(features["tvc_match_surface"], "html")
        self.assertEqual(features["tvc_matched_alias"], "nic")

    def test_ocr_brand_match_can_raise_strong_spoof(self):
        catalog = self._catalog()
        with mock.patch.object(utils, "_get_tvc_brand_catalog", return_value=catalog):
            features = utils.extract_tvc_features(
                url="https://evil-login-example.com",
                ocr_header_text="State Bank of India",
                ocr_footer_text="",
                ocr_full_text="Secure login for State Bank of India customers",
                html_text="",
                shortlisted_cse="State Bank of India",
                shortlisted_domain="sbi.co.in",
            )

        self.assertTrue(features["tvc_brand_spoofed"])
        self.assertTrue(features["tvc_spoof_strong"])
        self.assertEqual(features["tvc_match_surface"], "ocr_header_footer")
        self.assertEqual(features["tvc_matched_alias"], "state bank of india")


class Stage3DecisionRetuneTests(unittest.TestCase):
    def test_redirect_surface_counts_as_direct_brand_evidence(self):
        mock_entity_index = {
            "names": ["Civil Registration System, MHA (RGCCI)"],
            "brand_tokens": [set(["crsorgi"])],
            "kw_sets": [set()],
        }
        with mock.patch.object(comparison, "_entity_index", mock_entity_index):
            evidence_count = comparison._count_shortlist_aligned_page_brand_evidence(
                0,
                {
                    "html_title_text": "home | civil registration system | government of india",
                    "visible_text_excerpt": "welcome to the revamped crs portal",
                    "final_landing_url": "https://dcc.crsorgi.gov.in.crsor.info/crs/",
                    "final_domain": "dcc.crsorgi.gov.in.crsor.info",
                },
            )

        self.assertGreaterEqual(evidence_count, 1)

    def test_crsor_style_redirect_with_direct_evidence_is_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "direct_brand_evidence_count": 1,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://crsor.info",
                "final_landing_url": "https://dcc.crsorgi.gov.in.crsor.info/crs/",
                "final_domain": "dcc.crsorgi.gov.in.crsor.info",
            },
            registrar="OwnRegistrar, Inc.",
            hosting_isp="Hetzner Online GmbH",
            dns_records="A:95.217.44.98",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])

    def test_zero_corroboration_row_stays_legitimate(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Legitimate")
        self.assertTrue(decision["emit_output"])
        self.assertEqual(decision["non_lexical_corroboration_count"], 0)
        self.assertEqual(
            decision["classification_gate_reason"],
            "lexical_without_any_corroboration_legitimate_review",
        )

    def test_network_corroborated_row_becomes_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NameCheap, Inc.",
            hosting_isp="NA",
            dns_records="A:1.1.1.1",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])
        self.assertEqual(
            decision["classification_gate_reason"],
            "lexical_gate_plus_network_corroboration",
        )

    def test_strong_hash_anchor_can_still_classify_as_phishing(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": True,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Phishing")
        self.assertTrue(decision["emit_output"])

    def test_weak_tvc_plus_unknown_infra_is_not_phishing(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "signal_hit_domain": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
            tvc_brand_spoofed=True,
            tvc_brand_spoof_strong=False,
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])
        self.assertNotEqual(decision["classification"], "Phishing")

    def test_direct_brand_evidence_without_hash_is_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "direct_brand_evidence_count": 1,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NameCheap, Inc.",
            hosting_isp="NA",
            dns_records="A:1.1.1.1",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])

    def test_content_spoof_strong_promotes_to_phishing(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "deceptive_host_embedding": True,
                "direct_brand_evidence_count": 3,
                "content_spoof_strong": True,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://crsor.info",
                "final_landing_url": "https://dcc.crsorgi.gov.in.crsor.info/crs/",
                "final_domain": "dcc.crsorgi.gov.in.crsor.info",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Phishing")
        self.assertTrue(decision["emit_output"])

    def test_embedded_host_below_brand_evidence_threshold_stays_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "deceptive_host_embedding": True,
                "direct_brand_evidence_count": 2,
                "content_spoof_strong": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://crsor.info",
                "final_landing_url": "https://dcc.crsorgi.gov.in.crsor.info/crs/",
                "final_domain": "dcc.crsorgi.gov.in.crsor.info",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])

    def test_high_brand_evidence_without_deceptive_embedding_stays_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "deceptive_host_embedding": False,
                "direct_brand_evidence_count": 4,
                "content_spoof_strong": False,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])

    def test_failed_fetch_strict_lexical_can_be_rescued_to_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "timeout",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "lexical_score": 0.92,
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
            failed_fetch_suspected_min=0.90,
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])
        self.assertEqual(
            decision["classification_gate_reason"],
            "strict_lexical_fetch_evidence_unavailable_suspected",
        )

    def test_failed_fetch_strict_lexical_defaults_to_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "failed",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "lexical_score": 0.84,
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Suspected")
        self.assertTrue(decision["emit_output"])
        self.assertEqual(
            decision["classification_gate_reason"],
            "strict_lexical_fetch_evidence_unavailable_suspected",
        )


if __name__ == "__main__":
    unittest.main()
