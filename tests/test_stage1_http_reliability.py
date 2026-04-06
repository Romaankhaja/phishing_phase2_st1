import unittest
from unittest.mock import AsyncMock, patch

import httpx

from phishing_pipeline.stage1_http_analyzer import (
    _default_stage1_result,
    analyze_stage1_url,
    enrich_stage1_result,
)


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

    async def test_enrich_stage1_result_reuses_dns_prefetch_for_same_domain(self):
        base_result = _default_stage1_result("https://example.com")
        base_result.update(
            {
                "normalized_url": "https://example.com",
                "original_domain": "example.com",
                "final_landing_url": "https://example.com/login",
                "final_domain": "example.com",
            }
        )
        async with httpx.AsyncClient() as client:
            with patch("phishing_pipeline.stage1_http_analyzer._resolve_dns_answers", new=AsyncMock()) as dns_mock, \
                 patch("phishing_pipeline.stage1_http_analyzer.lookup_rdap", new=AsyncMock(return_value={"creation_date": "2026-01-01T00:00:00Z"})), \
                 patch("phishing_pipeline.stage1_http_analyzer._fetch_tls_summary", new=AsyncMock(return_value={"cert_cn": "example.com", "cert_san": [], "cert_issuer": "Let's Encrypt"})):
                enriched = await enrich_stage1_result(
                    base_result,
                    client,
                    dns_prefetch={
                        "resolved_ips": ["1.2.3.4"],
                        "dns_answer_count": 1,
                        "asn": 12345,
                        "asn_org": "Example ISP",
                        "country": "US",
                    },
                )

        dns_mock.assert_not_called()
        self.assertEqual(enriched["resolved_ips"], ["1.2.3.4"])
        self.assertEqual(enriched["asn_org"], "Example ISP")

    async def test_enrich_stage1_result_resolves_dns_for_redirected_domain(self):
        base_result = _default_stage1_result("https://example.com")
        base_result.update(
            {
                "normalized_url": "https://example.com",
                "original_domain": "example.com",
                "final_landing_url": "https://redirected.example.net/login",
                "final_domain": "redirected.example.net",
            }
        )
        async with httpx.AsyncClient() as client:
            with patch("phishing_pipeline.stage1_http_analyzer._resolve_dns_answers", new=AsyncMock(return_value={"resolved_ips": ["5.6.7.8"], "dns_answer_count": 1})) as dns_mock, \
                 patch("phishing_pipeline.stage1_http_analyzer.lookup_rdap", new=AsyncMock(return_value={"creation_date": "2026-01-01T00:00:00Z"})), \
                 patch("phishing_pipeline.stage1_http_analyzer._fetch_tls_summary", new=AsyncMock(return_value={"cert_cn": "redirected.example.net", "cert_san": [], "cert_issuer": "Let's Encrypt"})), \
                 patch("phishing_pipeline.stage1_http_analyzer.lookup_geoip_summary", return_value={"asn": 67890, "asn_org": "Redirect ISP", "country": "DE"}):
                enriched = await enrich_stage1_result(base_result, client, dns_prefetch={"resolved_ips": ["1.2.3.4"]})

        dns_mock.assert_awaited_once()
        self.assertEqual(enriched["resolved_ips"], ["5.6.7.8"])
        self.assertEqual(enriched["asn_org"], "Redirect ISP")


if __name__ == "__main__":
    unittest.main()
