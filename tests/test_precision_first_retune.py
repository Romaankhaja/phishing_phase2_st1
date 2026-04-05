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
            clip_anchor=False,
        )

        self.assertFalse(decision["admitted_to_holdout"])
        self.assertTrue(decision["kept_for_review_only"])
        self.assertEqual(decision["review_only_reason"], "strict_lexical_below_holdout_threshold")

    def test_hash_anchor_bypasses_threshold(self):
        decision = comparison._classify_stage1_admission(
            best_score=62.0,
            threshold=68.0,
            strict_lexical_hit=True,
            lexical_score_pass=True,
            hash_anchor=True,
            clip_anchor=False,
        )

        self.assertTrue(decision["admitted_to_holdout"])
        self.assertFalse(decision["kept_for_review_only"])
        self.assertIn("hash_bypass_hit", decision["admission_paths"])


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
    def test_lexical_only_row_becomes_legitimate(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "clip_anchor": False,
                "signal_hit_domain": True,
                "signal_hit_keywords": False,
                "typo_anchor": True,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Legitimate")
        self.assertTrue(decision["emit_output"])
        self.assertEqual(decision["non_lexical_corroboration_count"], 0)

    def test_strong_hash_anchor_can_still_classify_as_phishing(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": True,
                "clip_anchor": False,
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
                "clip_anchor": False,
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

    def test_clip_only_row_without_brand_corroboration_is_legitimate(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "clip_anchor": True,
                "clip_corroborated": False,
                "direct_brand_evidence_count": 0,
                "signal_hit_keywords": False,
                "Identified Phishing/Suspected Domain Name": "https://brand-login-check.com",
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
        )

        self.assertEqual(decision["classification"], "Legitimate")
        self.assertTrue(decision["emit_output"])

    def test_direct_brand_evidence_without_hash_is_suspected(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "fetched",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "hash_anchor": False,
                "clip_anchor": False,
                "clip_corroborated": False,
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
            "failed_fetch_strict_lexical_rescue",
        )

    def test_failed_fetch_strict_lexical_can_be_routed_to_review(self):
        decision = pipeline._hybrid_hash_decision(
            row={
                "fetch_status": "dns_rejected",
                "strict_lexical_hit": True,
                "lexical_score_pass": True,
                "fallback_rank_only": False,
                "lexical_score": 0.84,
            },
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
            failed_fetch_suspected_min=0.90,
            failed_fetch_review_min=0.80,
        )

        self.assertEqual(decision["classification"], "REVIEW_ONLY")
        self.assertFalse(decision["emit_output"])
        self.assertEqual(
            decision["classification_gate_reason"],
            "failed_fetch_strict_lexical_review",
        )


if __name__ == "__main__":
    unittest.main()
