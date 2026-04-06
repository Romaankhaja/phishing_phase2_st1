import unittest

import httpx

from phishing_pipeline.stage1_http_analyzer import _default_stage1_result, analyze_stage1_url


class Stage1HttpReliabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_url_returns_structured_failure_metadata(self):
        async with httpx.AsyncClient() as client:
            result = await analyze_stage1_url("", client)

        self.assertEqual(result["fetch_error_type"], "invalid_url")
        self.assertEqual(result["stage1_error_type"], "invalid_url")
        self.assertEqual(result["stage1_error_message"], "empty url")
        self.assertFalse(result["escalate_to_hashing"])

    def test_default_stage1_result_contains_reliability_fields(self):
        result = _default_stage1_result("https://example.com")

        self.assertIn("stage1_error_type", result)
        self.assertIn("stage1_error_message", result)
        self.assertIn("stage1_retry_count", result)
        self.assertIn("stage1_timeout_hit", result)
        self.assertIn("html_truncated", result)
        self.assertFalse(result["html_truncated"])


if __name__ == "__main__":
    unittest.main()
