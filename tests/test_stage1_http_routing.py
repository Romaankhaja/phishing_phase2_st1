import unittest

from phishing_pipeline import comparison
from phishing_pipeline.config import STAGE1_HTTP_CONFIG
from phishing_pipeline.stage1_http_analyzer import (
    build_stage1_concurrency_controls,
    score_stage1_http_signals,
)


def _entity_context():
    ordered_entities = ("CSC",)
    context = {
        "CSC": {
            "aliases": (
                "csc",
                "common service centre",
                "common service center",
            ),
            "domains": ("csc.gov.in",),
        }
    }
    return context, ordered_entities


def _prefetch_metrics(**overrides):
    metrics = {
        "strict_lexical_hit": False,
        "lexical_score_pass": False,
        "fallback_rank_only": False,
        "old_fuzzy_hit": False,
        "old_fuzzy_cse": "",
        "hybrid_lexical_hit": False,
        "candidate_generation_reason": "",
        "best_entity": "",
        "best_matching_domain": "",
        "best_lexical_score": 0.0,
        "best_typo_similarity": 0.0,
        "generic_token_only_match": False,
    }
    metrics.update(overrides)
    return metrics


class Stage1HttpRoutingTests(unittest.TestCase):
    def test_stage1_concurrency_controls_split_url_and_aux_limits(self):
        controls = build_stage1_concurrency_controls(STAGE1_HTTP_CONFIG)

        self.assertEqual(STAGE1_HTTP_CONFIG["concurrency"], 200)
        self.assertEqual(controls.url_semaphore._value, STAGE1_HTTP_CONFIG["concurrency"])
        self.assertEqual(controls.http_semaphore._value, STAGE1_HTTP_CONFIG["http_concurrency"])
        self.assertEqual(controls.dns_semaphore._value, STAGE1_HTTP_CONFIG["dns_concurrency"])
        self.assertEqual(controls.rdap_semaphore._value, STAGE1_HTTP_CONFIG["rdap_concurrency"])
        self.assertEqual(controls.tls_semaphore._value, STAGE1_HTTP_CONFIG["tls_concurrency"])

    def test_lexical_csc_phishing_url_bypasses_http_stage(self):
        prefetch_metrics = _prefetch_metrics(
            strict_lexical_hit=True,
            lexical_score_pass=True,
            best_lexical_score=0.97,
            best_typo_similarity=0.91,
            best_entity="CSC",
            best_matching_domain="csc.gov.in",
            candidate_generation_reason="brand_token_match|jw_primary",
        )

        self.assertTrue(comparison._passes_lexical_gate(prefetch_metrics))

        lexical_state = comparison._build_lexical_stage1_state(prefetch_metrics)
        self.assertTrue(lexical_state["lexical_hit"])
        self.assertTrue(lexical_state["escalate_to_hashing"])
        self.assertEqual(lexical_state["escalate_reason"], "lexical_hit")
        self.assertEqual(lexical_state["stage1_reasons"], "lexical_hit")

    def test_non_lexical_csc_phishing_html_escalates_and_seeds_entity(self):
        entity_context, ordered_entities = _entity_context()
        scored = score_stage1_http_signals(
            {
                "normalized_url": "https://portal-login-check.com/start",
                "original_domain": "portal-login-check.com",
                "final_landing_url": "https://portal-login-check.com/auth/login",
                "final_domain": "portal-login-check.com",
                "title_text": "CSC account verification",
                "meta_description": "Secure CSC access portal",
                "visible_text": "CSC users must verify account access before login.",
                "submit_texts": ["Login to CSC"],
                "redirect_chain": ["https://portal-login-check.com/start"],
                "favicon_url": "https://portal-login-check.com/assets/csc-logo.png",
                "form_count": 1,
                "input_count": 3,
                "password_count": 1,
                "action_urls": ["https://collector.bad/submit"],
                "action_domains": ["collector.bad"],
                "page_has_login_form": True,
                "iframe_count": 0,
                "img_count": 1,
                "meta_refresh": False,
                "js_redirect": False,
                "text_word_count": 12,
                "rdap_age_days": 5,
                "asn_org": "Namecheap, Inc.",
                "cert_cn": "portal-login-check.com",
                "cert_issuer": "Let's Encrypt",
                "html_bytes_read": 4096,
            },
            entity_context=entity_context,
            ordered_entities=ordered_entities,
        )

        self.assertEqual(scored["best_entity"], "CSC")
        self.assertEqual(scored["best_matching_domain"], "csc.gov.in")
        self.assertEqual(scored["candidate_entities"][0], "CSC")
        self.assertGreaterEqual(scored["brand_score"], STAGE1_HTTP_CONFIG["brand_min"])
        self.assertGreaterEqual(scored["credential_score"], STAGE1_HTTP_CONFIG["credential_min"])
        self.assertTrue(scored["hard_trigger_hit"])
        self.assertTrue(scored["escalate_to_hashing"])
        self.assertIn("hard_trigger_hit", scored["escalate_reason"])

    def test_benign_page_mentioning_csc_does_not_escalate(self):
        entity_context, ordered_entities = _entity_context()
        input_url = "https://district-bulletin.example.org/post"
        normalized_url = comparison.normalize_url(input_url)
        scored = score_stage1_http_signals(
            {
                "normalized_url": normalized_url,
                "original_domain": "district-bulletin.example.org",
                "final_landing_url": normalized_url,
                "final_domain": "district-bulletin.example.org",
                "title_text": "District bulletin",
                "meta_description": "",
                "visible_text": "Local administration shared a CSC progress update for citizen services.",
                "submit_texts": [],
                "redirect_chain": [],
                "favicon_url": "",
                "form_count": 0,
                "input_count": 0,
                "password_count": 0,
                "action_urls": [],
                "action_domains": [],
                "page_has_login_form": False,
                "iframe_count": 0,
                "img_count": 1,
                "meta_refresh": False,
                "js_redirect": False,
                "text_word_count": 18,
                "rdap_age_days": 600,
                "asn_org": "Example ISP",
                "cert_cn": "district-bulletin.example.org",
                "cert_issuer": "Let's Encrypt",
                "html_bytes_read": 2048,
            },
            entity_context=entity_context,
            ordered_entities=ordered_entities,
        )

        self.assertGreater(scored["brand_score"], 0)
        self.assertEqual(scored["credential_score"], 0)
        self.assertFalse(scored["hard_trigger_hit"])
        self.assertFalse(scored["escalate_to_hashing"])
        self.assertIn(
            scored["escalate_reason"],
            {"stage1_low_suspicion", "stage1_suspected_non_escalated"},
        )

        stage1_rows = comparison._build_stage1_debug_rows(
            input_urls=[input_url],
            audit_rows=[],
            decision_rows=[],
            prefetch_metrics_map={normalized_url: _prefetch_metrics()},
            stage1_analysis_map={normalized_url: scored},
        )
        self.assertEqual(stage1_rows[0]["dns_status"], "skipped")
        self.assertIn(
            stage1_rows[0]["reason"],
            {"stage1_low_suspicion", "stage1_suspected_non_escalated"},
        )

    def test_suspicious_form_without_brand_signals_stays_stage1_review_only(self):
        entity_context, ordered_entities = _entity_context()
        input_url = "https://employee-gateway-check.net/login"
        normalized_url = comparison.normalize_url(input_url)
        scored = score_stage1_http_signals(
            {
                "normalized_url": normalized_url,
                "original_domain": "employee-gateway-check.net",
                "final_landing_url": normalized_url,
                "final_domain": "employee-gateway-check.net",
                "title_text": "Secure employee portal",
                "meta_description": "",
                "visible_text": "Secure login portal for employees. Enter your password to continue.",
                "submit_texts": ["Sign in"],
                "redirect_chain": [],
                "favicon_url": "",
                "form_count": 1,
                "input_count": 4,
                "password_count": 1,
                "action_urls": ["https://collector.bad/submit"],
                "action_domains": ["collector.bad"],
                "page_has_login_form": True,
                "iframe_count": 0,
                "img_count": 1,
                "meta_refresh": False,
                "js_redirect": False,
                "text_word_count": 16,
                "rdap_age_days": 365,
                "asn_org": "Example ISP",
                "cert_cn": "employee-gateway-check.net",
                "cert_issuer": "Let's Encrypt",
                "html_bytes_read": 3072,
            },
            entity_context=entity_context,
            ordered_entities=ordered_entities,
        )

        self.assertEqual(scored["brand_score"], 0)
        self.assertGreater(scored["credential_score"], 0)
        self.assertLess(scored["total_stage1_score"], STAGE1_HTTP_CONFIG["escalate_total_threshold"])
        self.assertFalse(scored["hard_trigger_hit"])
        self.assertFalse(scored["escalate_to_hashing"])
        self.assertEqual(scored["escalate_reason"], "stage1_suspected_non_escalated")

        stage1_rows = comparison._build_stage1_debug_rows(
            input_urls=[input_url],
            audit_rows=[],
            decision_rows=[],
            prefetch_metrics_map={normalized_url: _prefetch_metrics()},
            stage1_analysis_map={normalized_url: scored},
        )
        self.assertEqual(stage1_rows[0]["dns_status"], "skipped")
        self.assertEqual(stage1_rows[0]["reason"], "stage1_suspected_non_escalated")

    def test_stage1_suspected_can_passthrough_to_holdout(self):
        entity_context, ordered_entities = _entity_context()
        input_url = "https://employee-gateway-check.net/login"
        normalized_url = comparison.normalize_url(input_url)
        scored = score_stage1_http_signals(
            {
                "normalized_url": normalized_url,
                "original_domain": "employee-gateway-check.net",
                "final_landing_url": normalized_url,
                "final_domain": "employee-gateway-check.net",
                "title_text": "Secure employee portal",
                "meta_description": "",
                "visible_text": "Secure login portal for employees. Enter your password to continue.",
                "submit_texts": ["Sign in"],
                "redirect_chain": [],
                "favicon_url": "",
                "form_count": 1,
                "input_count": 4,
                "password_count": 1,
                "action_urls": ["https://collector.bad/submit"],
                "action_domains": ["collector.bad"],
                "page_has_login_form": True,
                "iframe_count": 0,
                "img_count": 1,
                "meta_refresh": False,
                "js_redirect": False,
                "text_word_count": 16,
                "rdap_age_days": 365,
                "asn_org": "Example ISP",
                "cert_cn": "employee-gateway-check.net",
                "cert_issuer": "Let's Encrypt",
                "html_bytes_read": 3072,
            },
            entity_context=entity_context,
            ordered_entities=ordered_entities,
        )
        scoring_config = comparison._resolve_scoring_config(keep_stage1_suspected=True)

        stage1_rows = comparison._build_stage1_debug_rows(
            input_urls=[input_url],
            audit_rows=[],
            decision_rows=[],
            prefetch_metrics_map={normalized_url: _prefetch_metrics()},
            stage1_analysis_map={normalized_url: scored},
            scoring_config=scoring_config,
        )

        self.assertTrue(stage1_rows[0]["stage1_passthrough"])
        self.assertEqual(stage1_rows[0]["survival_path"], "stage1_suspected_passthrough")
        holdout_row = comparison._build_stage1_passthrough_holdout_row(stage1_rows[0], scoring_config)
        self.assertTrue(holdout_row["stage1_passthrough"])
        self.assertEqual(holdout_row["admission_path"], "stage1_suspected_passthrough")

    def test_dns_rejected_strict_lexical_passthrough_marks_dns_fetch_status(self):
        input_url = "https://csc-login-check.example"
        normalized_url = comparison.normalize_url(input_url)
        prefetch_metrics = _prefetch_metrics(
            strict_lexical_hit=True,
            lexical_score_pass=True,
            best_lexical_score=0.97,
            best_typo_similarity=0.91,
            best_entity="CSC",
            best_matching_domain="csc.gov.in",
            candidate_generation_reason="brand_token_match|jw_primary",
        )
        scoring_config = comparison._resolve_scoring_config(
            keep_dns_rejected_strict_lexical=True,
        )

        stage1_rows = comparison._build_stage1_debug_rows(
            input_urls=[input_url],
            audit_rows=[
                {
                    "target_url": input_url,
                    "dns_status": "dns_error",
                    "decision": "rejected",
                }
            ],
            decision_rows=[],
            prefetch_metrics_map={normalized_url: prefetch_metrics},
            stage1_analysis_map={
                normalized_url: comparison._build_lexical_stage1_state(prefetch_metrics)
            },
            scoring_config=scoring_config,
        )

        self.assertEqual(stage1_rows[0]["reason"], "dns_rejected")
        self.assertTrue(stage1_rows[0]["stage1_passthrough"])
        self.assertEqual(
            stage1_rows[0]["survival_path"],
            "dns_rejected_strict_lexical_passthrough",
        )
        holdout_row = comparison._build_stage1_passthrough_holdout_row(stage1_rows[0], scoring_config)
        self.assertEqual(holdout_row["fetch_status"], "dns_rejected")
        self.assertTrue(holdout_row["stage1_passthrough"])


if __name__ == "__main__":
    unittest.main()
