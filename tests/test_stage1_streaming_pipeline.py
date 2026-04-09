import asyncio
import csv
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import httpx

from phishing_pipeline import comparison
from phishing_pipeline.config import resolve_stage1_http_config
from phishing_pipeline.reliability import CheckpointStore, build_run_context
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
    def test_stage1_cpu_executor_uses_threads_when_shortlist_cpu_mode_is_thread(self):
        entity_context, ordered_entities = _entity_context()
        stage1_http_config = resolve_stage1_http_config({"stage1_cpu_workers": 2, "stage1_parse_workers": 2})

        with (
            mock.patch.object(comparison, "_resolve_shortlist_cpu_executor_mode", return_value="thread"),
            mock.patch.object(comparison, "ProcessPoolExecutor", side_effect=AssertionError("process pool should not be used")),
        ):
            executor, executor_kind = comparison._create_stage1_cpu_executor(
                2,
                entity_context,
                ordered_entities,
                stage1_http_config,
            )

        self.assertEqual(executor_kind, "thread")
        executor.shutdown(wait=True, cancel_futures=True)

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
                "stage1_fetch_concurrency_floor": 1,
                "stage1_http_connection_limit": 4,
                "stage1_http_keepalive_limit": 2,
                "stage1_cpu_workers": 2,
                "stage1_parse_workers": 2,
                "stage1_enrich_dns_concurrency": 4,
                "stage1_enrich_rdap_concurrency": 2,
                "stage1_enrich_tls_concurrency": 2,
                "stage1_fetch_queue_max": 8,
                "stage1_cpu_queue_max": 8,
                "stage1_parse_queue_max": 8,
                "stage1_score_queue_max": 8,
                "stage1_enrich_queue_max": 8,
                "stage1_result_queue_max": 8,
                "stage1_control_interval_seconds": 0.25,
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
                await on_admit(
                    item["raw_url"],
                    normalized_url,
                    stage1_analysis_map[normalized_url],
                    item["source_workbook"],
                )
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

        async def fake_run_hash_browser_node(*, render_queue, **kwargs):
            while True:
                item = await render_queue.get()
                if item is None:
                    render_queue.task_done()
                    break
                states["hash_started_before_stage1_done"] = not states["stage1_done"]
                render_queue.task_done()

        async def fake_hash_aux_worker(*, aux_queue, **kwargs):
            while True:
                item = await aux_queue.get()
                aux_queue.task_done()
                if item is None:
                    break

        async def fake_gpu_scorer(gpu_queue, *args, **kwargs):
            while True:
                item = await gpu_queue.get()
                gpu_queue.task_done()
                if item is None:
                    break

        with (
            mock.patch.object(comparison, "_compute_stage0_prefetch_metrics_parallel_streaming", side_effect=fake_stage0_stream),
            mock.patch.object(comparison, "_run_stage1_http_pipeline", side_effect=fake_stage1_pipeline),
            mock.patch.object(comparison, "_run_hash_browser_node", side_effect=fake_run_hash_browser_node),
            mock.patch.object(comparison, "_run_hash_aux_worker", side_effect=fake_hash_aux_worker),
            mock.patch.object(comparison, "_gpu_microbatch_scorer", side_effect=fake_gpu_scorer),
            mock.patch.object(comparison, "_finish_hashing_shortlist_output", return_value={"done": True}),
            mock.patch.object(comparison, "BROWSER_SHARDS", 1),
            mock.patch.object(comparison, "SCRAPER_PAGE_CONCURRENCY", 1),
            mock.patch.object(comparison, "HASH_PAGES_PER_NODE", 1),
            mock.patch.object(comparison, "HASH_RENDER_WORKER_COUNT", 1),
            mock.patch.object(comparison, "AUX_NET_CONCURRENCY_LIMIT", 1),
            mock.patch.object(comparison, "_has_aiohttp", False),
        ):
            result = await comparison.run_hashing_shortlist_streaming(["https://miss.example.org"])

        self.assertEqual({"done": True}, result)
        self.assertTrue(states["stage1_started_before_stage0_done"])
        self.assertTrue(states["hash_started_before_stage1_done"])

    def test_hash_stage1_backlog_cap_uses_stage1_queue_pressure(self):
        self.assertEqual(
            8,
            comparison._compute_hash_stage1_backlog_cap(
                full_limit=64,
                stage1_snapshot={
                    "cpu_backlog_s": 2.5,
                    "ingress_queue_ratio": 0.80,
                    "cpu_queue_ratio": 0.90,
                    "hash_reserved_floor": 8,
                },
                stage1_done=False,
            ),
        )
        self.assertEqual(
            16,
            comparison._compute_hash_stage1_backlog_cap(
                full_limit=64,
                stage1_snapshot={
                    "cpu_backlog_s": 0.80,
                    "ingress_queue_ratio": 0.30,
                    "cpu_queue_ratio": 0.30,
                    "hash_reserved_floor": 8,
                },
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

    def test_stage1_fetch_controller_balances_cpu_backlog(self):
        downshift = comparison._compute_stage1_fetch_limit_adjustment(
            current_limit=256,
            floor_limit=64,
            max_limit=512,
            ingress_queue_depth=512,
            ingress_queue_limit=4096,
            cpu_queue_depth=1400,
            cpu_queue_limit=2048,
            cpu_completed_rate=300.0,
            timeout_ratio=0.05,
            fd_ratio=0.10,
            ram_usage_ratio=0.10,
            step=32,
        )
        self.assertEqual("downshift", downshift["action"])
        self.assertLess(downshift["next_limit"], 256)

        upshift = comparison._compute_stage1_fetch_limit_adjustment(
            current_limit=192,
            floor_limit=64,
            max_limit=512,
            ingress_queue_depth=256,
            ingress_queue_limit=4096,
            cpu_queue_depth=120,
            cpu_queue_limit=2048,
            cpu_completed_rate=400.0,
            timeout_ratio=0.05,
            fd_ratio=0.10,
            ram_usage_ratio=0.10,
            step=32,
        )
        self.assertEqual("upshift", upshift["action"])
        self.assertEqual(224, upshift["next_limit"])

    async def test_fetch_workers_do_not_overpull_ingress_beyond_fetch_limit(self):
        started = asyncio.Event()
        release = asyncio.Event()
        state = {"active": 0, "max_active": 0}

        stage1_http_config = resolve_stage1_http_config(
            {
                "concurrency": 2,
                "http_concurrency": 2,
                "dns_concurrency": 2,
                "rdap_concurrency": 1,
                "tls_concurrency": 1,
                "stage1_fetch_concurrency_start": 2,
                "stage1_fetch_concurrency_max": 2,
                "stage1_fetch_concurrency_floor": 1,
                "stage1_http_connection_limit": 2,
                "stage1_http_keepalive_limit": 2,
                "stage1_cpu_workers": 2,
                "stage1_parse_workers": 2,
                "stage1_enrich_dns_concurrency": 2,
                "stage1_enrich_rdap_concurrency": 1,
                "stage1_enrich_tls_concurrency": 1,
                "stage1_fetch_queue_max": 8,
                "stage1_cpu_queue_max": 8,
                "stage1_parse_queue_max": 8,
                "stage1_score_queue_max": 4,
                "stage1_enrich_queue_max": 4,
                "stage1_result_queue_max": 8,
                "stage1_control_interval_seconds": 0.25,
            }
        )

        async def fake_fetch(url, client, **kwargs):
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            if state["active"] >= 2:
                started.set()
            await release.wait()
            state["active"] -= 1
            result = _default_stage1_result(url)
            result.update(
                {
                    "fetch_status": "fetched",
                    "status_code": 200,
                    "final_landing_url": comparison.normalize_url(url),
                    "final_domain": comparison.normalize_url(url).split("//", 1)[-1],
                    "content_type": "text/html",
                }
            )
            return {"result": result, "html_bytes": b"<html></html>", "response_encoding": "utf-8"}

        ingress_queue = asyncio.Queue(maxsize=8)
        for index in range(5):
            url = f"https://steady-{index}.example.org"
            await ingress_queue.put(
                {
                    "raw_url": url,
                    "normalized_url": comparison.normalize_url(url),
                    "source_workbook": "",
                    "ingress_enqueued_monotonic": comparison.time.perf_counter(),
                }
            )

        producer_done_event = asyncio.Event()
        producer_done_event.set()
        progress = comparison.ProgressTracker(total=5)
        results = {}

        with (
            mock.patch.object(comparison, "fetch_stage1_http_artifacts", side_effect=fake_fetch),
            mock.patch.object(
                comparison,
                "_create_stage1_cpu_executor",
                return_value=(ThreadPoolExecutor(max_workers=2), "thread-test"),
            ),
        ):
            pipeline_task = asyncio.create_task(
                comparison._run_stage1_http_pipeline(
                    ingress_queue=ingress_queue,
                    producer_done_event=producer_done_event,
                    stage1_http_config=stage1_http_config,
                    progress=progress,
                    stage1_analysis_map=results,
                )
            )
            await asyncio.wait_for(started.wait(), timeout=2.0)
            await asyncio.sleep(0.05)
            self.assertEqual(3, ingress_queue.qsize())
            release.set()
            await asyncio.wait_for(pipeline_task, timeout=5.0)

        self.assertLessEqual(state["max_active"], 2)

    async def test_fetch_workers_do_not_hold_permits_while_ingress_is_empty(self):
        ctx = {
            "fetch_limiter": comparison._AdaptiveFetchLimiter(2),
            "ingress_queue": asyncio.Queue(),
            "producer_done_event": asyncio.Event(),
            "source_workbook_map": {},
            "lane_counters": {"fetch_started": 0, "fetch_completed": 0, "ingress_wait_s": 0.0},
            "active_workers": {},
        }

        worker_task = asyncio.create_task(
            comparison._stage1_fetch_worker(
                0,
                mock.Mock(),
                ctx,
            )
        )

        await asyncio.sleep(0.1)
        self.assertEqual(0, ctx["fetch_limiter"].active)

        ctx["producer_done_event"].set()
        await asyncio.wait_for(worker_task, timeout=1.0)

    async def test_streaming_shortlist_writes_stage0_and_hash_stage_events(self):
        url = "https://hit.example.org"
        normalized_url = comparison.normalize_url(url)

        async def fake_stage0_stream(metric_urls, scoring_config, *, on_batch_complete=None, **kwargs):
            await on_batch_complete(
                [normalized_url],
                [
                    {
                        "strict_lexical_hit": True,
                        "lexical_score_pass": False,
                        "fallback_rank_only": False,
                        "source_workbook": "demo.xlsx",
                    }
                ],
            )
            return {
                "metric_urls_total": 1,
                "metric_urls_completed": 1,
                "input_urls_completed": 1,
                "batches_total": 1,
                "batches_completed": 1,
                "avg_batch_latency_ms": 1.0,
            }

        async def fake_stage1_pipeline(**kwargs):
            kwargs["producer_done_event"].set()
            return {
                "results": kwargs["stage1_analysis_map"],
                "progress": {},
                "elapsed_s": 0.0,
                "fetch_limit": 1,
                "queue_snapshot": {},
            }

        async def fake_run_hash_browser_node(*, render_queue, **kwargs):
            while True:
                item = await render_queue.get()
                if item is None:
                    render_queue.task_done()
                    break
                render_queue.task_done()

        async def fake_hash_aux_worker(*, aux_queue, **kwargs):
            while True:
                item = await aux_queue.get()
                aux_queue.task_done()
                if item is None:
                    break

        async def fake_gpu_scorer(gpu_queue, *args, **kwargs):
            while True:
                item = await gpu_queue.get()
                gpu_queue.task_done()
                if item is None:
                    break

        with tempfile.TemporaryDirectory() as temp_dir:
            run_context = build_run_context(output_dir=temp_dir, run_id="streaming_stage_events")
            checkpoint_store = CheckpointStore(run_context)
            with (
                mock.patch.object(comparison, "_compute_stage0_prefetch_metrics_parallel_streaming", side_effect=fake_stage0_stream),
                mock.patch.object(comparison, "_run_stage1_http_pipeline", side_effect=fake_stage1_pipeline),
                mock.patch.object(comparison, "_run_hash_browser_node", side_effect=fake_run_hash_browser_node),
                mock.patch.object(comparison, "_run_hash_aux_worker", side_effect=fake_hash_aux_worker),
                mock.patch.object(comparison, "_gpu_microbatch_scorer", side_effect=fake_gpu_scorer),
                mock.patch.object(comparison, "_finish_hashing_shortlist_output", return_value={"done": True}),
                mock.patch.object(comparison, "BROWSER_SHARDS", 1),
                mock.patch.object(comparison, "SCRAPER_PAGE_CONCURRENCY", 1),
                mock.patch.object(comparison, "HASH_PAGES_PER_NODE", 1),
                mock.patch.object(comparison, "HASH_RENDER_WORKER_COUNT", 1),
                mock.patch.object(comparison, "AUX_NET_CONCURRENCY_LIMIT", 1),
                mock.patch.object(comparison, "_has_aiohttp", False),
            ):
                result = await comparison.run_hashing_shortlist_streaming(
                    [url],
                    url_sources={url: "demo.xlsx"},
                    run_context=run_context,
                    checkpoint_store=checkpoint_store,
                )

            self.assertEqual({"done": True}, result)
            checkpoint_store.export_all()
            with open(run_context.stage_events_csv, newline="", encoding="utf-8") as fh:
                events = list(csv.DictReader(fh))
            self.assertIn("stage0", {row["stage_name"] for row in events})
            self.assertIn("hash", {row["stage_name"] for row in events})
            self.assertIn("lexical_hit", {row["status"] for row in events})
            self.assertIn("admitted", {row["status"] for row in events})


if __name__ == "__main__":
    unittest.main()
