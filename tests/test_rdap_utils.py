import asyncio
import unittest
from unittest import mock

import httpx

from phishing_pipeline import rdap_utils


class _FakeResponse:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    async def get(self, url, timeout=None):
        self.calls += 1
        if not self._responses:
            raise AssertionError("No fake responses left")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _GateClient:
    def __init__(self, response):
        self._response = response
        self.calls = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def get(self, url, timeout=None):
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return self._response


class _EmptyMessageRequestError(httpx.RequestError):
    def __str__(self):
        return ""


class RdapUtilsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        rdap_utils.reset_rdap_state()

    async def test_lookup_rdap_caches_successful_result_for_exact_domain(self):
        client = _FakeClient(
            [
                _FakeResponse(
                    200,
                    {
                        "events": [{"eventAction": "registration", "eventDate": "2024-01-01T00:00:00Z"}],
                        "entities": [],
                        "nameservers": [{"ldhName": "ns1.example.com"}],
                        "status": ["active"],
                    },
                )
            ]
        )

        first = await rdap_utils.lookup_rdap("example.com", client=client, timeout=1.0)
        second = await rdap_utils.lookup_rdap("example.com", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertEqual(first["creation_date"], "2024-01-01T00:00:00Z")
        self.assertEqual(second["name_servers"], "ns1.example.com")
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["success"], 1)
        self.assertEqual(snapshot["cache_hit"], 1)

    async def test_lookup_rdap_caches_empty_result_after_single_429(self):
        client = _FakeClient(
            [
                _FakeResponse(429),
                _FakeResponse(429),
                _FakeResponse(429),
            ]
        )

        with mock.patch("phishing_pipeline.rdap_utils.random.uniform", return_value=0.0), mock.patch(
            "phishing_pipeline.rdap_utils.asyncio.sleep",
            new=mock.AsyncMock(),
        ):
            first = await rdap_utils.lookup_rdap("limited.example", client=client, timeout=1.0)
            second = await rdap_utils.lookup_rdap("limited.example", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertEqual(first["creation_date"], None)
        self.assertEqual(second["raw_rdap"], {})
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["429"], 1)
        self.assertEqual(snapshot["retry_exhausted"], 1)
        self.assertEqual(snapshot["cooldown_hit"], 1)

    async def test_lookup_rdap_shares_inflight_request_for_concurrent_exact_domain_calls(self):
        client = _GateClient(
            _FakeResponse(
                200,
                {
                    "events": [{"eventAction": "registration", "eventDate": "2024-03-03T00:00:00Z"}],
                    "entities": [],
                    "nameservers": [],
                    "status": ["active"],
                },
            )
        )

        first_task = asyncio.create_task(rdap_utils.lookup_rdap("shared.example", client=client, timeout=1.0))
        await asyncio.wait_for(client.entered.wait(), timeout=1.0)
        second_task = asyncio.create_task(rdap_utils.lookup_rdap("shared.example", client=client, timeout=1.0))
        await asyncio.sleep(0)
        client.release.set()
        first, second = await asyncio.gather(first_task, second_task)

        self.assertEqual(client.calls, 1)
        self.assertEqual(first["creation_date"], "2024-03-03T00:00:00Z")
        self.assertEqual(second["creation_date"], "2024-03-03T00:00:00Z")
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["success"], 1)
        self.assertEqual(snapshot["inflight_wait"], 1)

    async def test_lookup_rdap_does_not_retry_429_then_succeeds_on_later_run_only(self):
        client = _FakeClient(
            [
                _FakeResponse(429),
                _FakeResponse(
                    200,
                    {
                        "events": [{"eventAction": "registration", "eventDate": "2024-02-02T00:00:00Z"}],
                        "entities": [],
                        "nameservers": [],
                        "status": ["active"],
                    },
                ),
            ]
        )

        with mock.patch("phishing_pipeline.rdap_utils.random.uniform", return_value=0.0), mock.patch(
            "phishing_pipeline.rdap_utils.asyncio.sleep",
            new=mock.AsyncMock(),
        ):
            result = await rdap_utils.lookup_rdap("retry.example", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertEqual(
            set(result.keys()),
            {"creation_date", "registrar", "registrant_name", "registrant_country", "name_servers", "status", "raw_rdap"},
        )
        self.assertEqual(result["creation_date"], None)
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["429"], 1)
        self.assertEqual(snapshot["success"], 0)
        self.assertEqual(snapshot["retry_success"], 0)

    async def test_lookup_rdap_logs_exception_type_when_message_is_empty(self):
        request = httpx.Request("GET", "https://rdap.org/domain/silent.example")
        client = _FakeClient(
            [
                _EmptyMessageRequestError("ignored", request=request),
            ]
        )

        with mock.patch("phishing_pipeline.rdap_utils.random.uniform", return_value=0.0), mock.patch(
            "phishing_pipeline.rdap_utils.asyncio.sleep",
            new=mock.AsyncMock(),
        ), self.assertLogs("phishing_pipeline.rdap_utils", level="DEBUG") as logs:
            await rdap_utils.lookup_rdap("silent.example", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertTrue(any("EmptyMessageRequestError" in line for line in logs.output))

    async def test_lookup_rdap_applies_cooldown_after_read_timeout_exhaustion(self):
        request = httpx.Request("GET", "https://rdap.org/domain/timeout.example")
        client = _FakeClient(
            [
                httpx.ReadTimeout("slow", request=request),
            ]
        )

        with mock.patch("phishing_pipeline.rdap_utils.random.uniform", return_value=0.0), mock.patch(
            "phishing_pipeline.rdap_utils.asyncio.sleep",
            new=mock.AsyncMock(),
        ):
            first = await rdap_utils.lookup_rdap("timeout.example", client=client, timeout=1.0)
            second = await rdap_utils.lookup_rdap("timeout.example", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertEqual(first["raw_rdap"], {})
        self.assertEqual(second["raw_rdap"], {})
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["retry_exhausted"], 1)
        self.assertEqual(snapshot["cooldown_hit"], 1)

    async def test_lookup_rdap_does_not_retry_non_transport_exception(self):
        client = _FakeClient([ValueError("boom")])

        with self.assertLogs("phishing_pipeline.rdap_utils", level="DEBUG") as logs:
            result = await rdap_utils.lookup_rdap("boom.example", client=client, timeout=1.0)

        self.assertEqual(client.calls, 1)
        self.assertEqual(result["raw_rdap"], {})
        self.assertTrue(any("boom" in line for line in logs.output))
        snapshot = rdap_utils.get_rdap_metrics_snapshot()
        self.assertEqual(snapshot["exception"], 1)
        self.assertEqual(snapshot["retry_exhausted"], 0)


if __name__ == "__main__":
    unittest.main()
