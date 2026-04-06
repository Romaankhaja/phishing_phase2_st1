import unittest
from unittest import mock

import numpy as np

from phishing_pipeline import comparison
from phishing_pipeline.similarity_hashing import (
    best_similarity_against_set,
    canonicalize_ssl_identity,
    compute_domain_simhash,
    hamming_distance,
    normalized_hamming_similarity,
)


class SimilarityHashHelperTests(unittest.TestCase):
    def test_identical_hashes_have_zero_distance_and_full_similarity(self):
        left = "0123456789abcdef"
        right = "0123456789abcdef"

        self.assertEqual(hamming_distance(left, right), 0)
        self.assertEqual(normalized_hamming_similarity(left, right), 1.0)

    def test_max_distance_hashes_have_zero_similarity(self):
        left = "0000000000000000"
        right = "ffffffffffffffff"

        self.assertEqual(hamming_distance(left, right), 64)
        self.assertEqual(normalized_hamming_similarity(left, right), 0.0)

    def test_best_similarity_against_set_ignores_invalid_hashes(self):
        similarity, distance = best_similarity_against_set(
            "f0f0f0f0f0f0f0f0",
            ["not-a-hex-hash", "f0f0f0f0f0f0f0f0"],
        )

        self.assertEqual(distance, 0)
        self.assertEqual(similarity, 1.0)

    def test_domain_simhash_is_deterministic(self):
        first = compute_domain_simhash("Login.Example-Bank.com")
        second = compute_domain_simhash("login.example-bank.com")

        self.assertEqual(first, second)
        self.assertEqual(len(first), 16)

    def test_canonicalize_ssl_identity_normalizes_expected_fields(self):
        canonical = canonicalize_ssl_identity(
            {
                "subject": ((("commonName", "Example Cert"),), (("organizationName", "Example Org"),)),
                "issuer": ((("commonName", "Example Issuer"),),),
                "subjectAltName": [("DNS", "WWW.Example.com"), ("DNS", "login.example.com")],
            }
        )

        self.assertIn("subject_cn=example cert", canonical)
        self.assertIn("subject_o=example org", canonical)
        self.assertIn("issuer_cn=example issuer", canonical)
        self.assertIn("san=login.example.com|www.example.com", canonical)


class SimilarityHashScoringTests(unittest.TestCase):
    def test_build_entity_index_warns_for_legacy_hash_schema(self):
        legacy_db = {
            "Example Entity": {
                "domains": ["example.com"],
                "screenshot_clip": [],
                "favicon_hashes": ["abc123"],
                "ssl_hashes": ["def456"],
                "html_hashes": ["789abc"],
                "domain_hashes": ["fedcba"],
                "keywords": ["portal"],
            }
        }

        with mock.patch.object(comparison, "_entity_db_meta", {}):
            with self.assertLogs(comparison._clip_logger.name, level="WARNING") as logs:
                entity_index = comparison._build_entity_index(legacy_db)

        self.assertFalse(entity_index["use_similarity_hashing"])
        self.assertTrue(any("legacy hash schema" in line for line in logs.output))

    def test_build_entity_index_reads_similarity_hash_fields(self):
        similarity_db = {
            "Example Entity": {
                "domains": ["example.com"],
                "screenshot_clip": [],
                "favicon_phashes": ["aaaaaaaaaaaaaaaa"],
                "ssl_simhashes": ["bbbbbbbbbbbbbbbb"],
                "page_phashes": ["cccccccccccccccc"],
                "domain_simhashes": ["dddddddddddddddd"],
                "keywords": ["portal"],
            }
        }

        with mock.patch.object(comparison, "_entity_db_meta", {"hash_schema_version": 2}):
            entity_index = comparison._build_entity_index(similarity_db)

        self.assertTrue(entity_index["use_similarity_hashing"])
        self.assertEqual(entity_index["fav_similarity_refs"][0], ("aaaaaaaaaaaaaaaa",))
        self.assertEqual(entity_index["ssl_similarity_refs"][0], ("bbbbbbbbbbbbbbbb",))
        self.assertEqual(entity_index["page_similarity_refs"][0], ("cccccccccccccccc",))
        self.assertEqual(entity_index["domain_similarity_refs"][0], ("dddddddddddddddd",))

    def test_similarity_arrays_apply_distance_thresholds(self):
        similarity, distance, hit, anchor = comparison._similarity_arrays_from_reference_sets(
            "ffffffffffffffff",
            [("ffffffffffffffff",), ("0000000000000000",)],
            hit_distance=8,
            anchor_distance=4,
        )

        self.assertEqual(distance.tolist(), [0, 64])
        self.assertEqual(similarity.tolist(), [1.0, 0.0])
        self.assertEqual(hit.tolist(), [True, False])
        self.assertEqual(anchor.tolist(), [True, False])

    def test_finalize_scored_payload_uses_weighted_similarity_and_multi_hit_anchor(self):
        payload = {
            "url": "https://login-example.com",
            "normalized_url": "https://login-example.com",
            "source_workbook": "holdout.xlsx",
            "fetch_status": "fetched",
            "visual_status": "captured",
            "lexical_scores": np.array([0.91]),
            "jw_scores": np.array([0.91]),
            "token_scores": np.array([0.89]),
            "typo_scores": np.array([0.83]),
            "lexical_rule_hit": np.array([True]),
            "brand_token_hit": np.array([False]),
            "generic_token_only_hit": np.array([False]),
            "domain_hit": np.array([True]),
            "keyword_hit": np.array([False]),
            "favicon_hit": np.array([True]),
            "favicon_anchor": np.array([False]),
            "favicon_hash_similarity": np.array([0.90]),
            "favicon_hash_distance": np.array([6]),
            "ssl_hash_hit": np.array([True]),
            "ssl_hash_anchor": np.array([False]),
            "ssl_hash_similarity": np.array([0.875]),
            "ssl_hash_distance": np.array([8]),
            "html_hash_hit": np.array([False]),
            "html_hash_anchor": np.array([False]),
            "page_hash_similarity": np.array([0.0]),
            "page_hash_distance": np.array([-1]),
            "domain_hash_hit": np.array([False]),
            "domain_hash_anchor": np.array([False]),
            "domain_hash_similarity": np.array([0.0]),
            "domain_hash_distance": np.array([-1]),
            "candidate_reasons": ["lexical_rule_hit"],
            "best_matching_domains": ["example.com"],
            "strict_lexical_hit": True,
            "lexical_score_pass": True,
            "fallback_rank_only": False,
            "html_title_text": "",
            "visible_text_excerpt": "",
        }
        scores = np.array([72.0])
        denominators = np.array([100.0])
        metrics = {"final_matches_above_threshold": 0}
        results = []
        review_results = []
        decision_rows = []

        patched_index = {
            "names": ["Example Entity"],
            "brand_tokens": [set()],
            "kw_sets": [set()],
            "domains": [["example.com"]],
        }

        with mock.patch.object(comparison, "_entity_index", patched_index):
            comparison._finalize_scored_hash_payload(
                payload=payload,
                scores=scores,
                denominators=denominators,
                screenshot_hit=np.array([False]),
                screenshot_similarity=np.array([0.0]),
                metrics=metrics,
                results=results,
                review_results=review_results,
                decision_rows=decision_rows,
                threshold=68.0,
                scoring_config=comparison._DEFAULT_SCORING_CONFIG,
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(metrics["final_matches_above_threshold"], 1)
        self.assertTrue(results[0]["hash_anchor"])
        self.assertAlmostEqual(results[0]["hash_component"], 23.1, places=4)
        self.assertEqual(results[0]["signal_hit_favicon"], True)
        self.assertEqual(results[0]["signal_hit_ssl_hash"], True)
        self.assertEqual(results[0]["signal_hit_domain_hash"], False)
        self.assertAlmostEqual(decision_rows[0]["hash_component"], 23.1, places=4)

    def test_domain_similarity_hit_contributes_without_standalone_hash_anchor(self):
        payload = {
            "url": "https://login-example.com",
            "normalized_url": "https://login-example.com",
            "fetch_status": "fetched",
            "visual_status": "captured",
            "lexical_scores": np.array([0.88]),
            "jw_scores": np.array([0.88]),
            "token_scores": np.array([0.86]),
            "typo_scores": np.array([0.79]),
            "lexical_rule_hit": np.array([True]),
            "brand_token_hit": np.array([False]),
            "generic_token_only_hit": np.array([False]),
            "domain_hit": np.array([True]),
            "keyword_hit": np.array([False]),
            "favicon_hit": np.array([False]),
            "favicon_anchor": np.array([False]),
            "favicon_hash_similarity": np.array([0.0]),
            "favicon_hash_distance": np.array([-1]),
            "ssl_hash_hit": np.array([False]),
            "ssl_hash_anchor": np.array([False]),
            "ssl_hash_similarity": np.array([0.0]),
            "ssl_hash_distance": np.array([-1]),
            "html_hash_hit": np.array([False]),
            "html_hash_anchor": np.array([False]),
            "page_hash_similarity": np.array([0.0]),
            "page_hash_distance": np.array([-1]),
            "domain_hash_hit": np.array([True]),
            "domain_hash_anchor": np.array([False]),
            "domain_hash_similarity": np.array([0.9375]),
            "domain_hash_distance": np.array([4]),
            "candidate_reasons": ["lexical_rule_hit"],
            "best_matching_domains": ["example.com"],
            "strict_lexical_hit": True,
            "lexical_score_pass": True,
            "fallback_rank_only": False,
            "html_title_text": "",
            "visible_text_excerpt": "",
        }
        scores = np.array([70.0])
        denominators = np.array([100.0])
        results = []
        patched_index = {
            "names": ["Example Entity"],
            "brand_tokens": [set()],
            "kw_sets": [set()],
            "domains": [["example.com"]],
        }

        with mock.patch.object(comparison, "_entity_index", patched_index):
            comparison._finalize_scored_hash_payload(
                payload=payload,
                scores=scores,
                denominators=denominators,
                screenshot_hit=np.array([False]),
                screenshot_similarity=np.array([0.0]),
                metrics={"final_matches_above_threshold": 0},
                results=results,
                review_results=[],
                decision_rows=[],
                threshold=68.0,
                scoring_config=comparison._DEFAULT_SCORING_CONFIG,
            )

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["hash_anchor"])
        self.assertAlmostEqual(results[0]["hash_component"], 7.5, places=4)
        self.assertTrue(results[0]["signal_hit_domain_hash"])


if __name__ == "__main__":
    unittest.main()
