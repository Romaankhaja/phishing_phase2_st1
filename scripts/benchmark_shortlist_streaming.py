import argparse
import asyncio
import os
import sys
import time
from unittest import mock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phishing_pipeline import _comparison_legacy as comparison


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synthetic shortlist streaming benchmark")
    parser.add_argument("--urls", type=int, default=5000, help="Number of synthetic URLs to benchmark")
    parser.add_argument("--stage0-batch-ms", type=float, default=15.0, help="Synthetic Stage0 batch latency")
    parser.add_argument("--stage1-fetch-ms", type=float, default=8.0, help="Synthetic Stage1 fetch latency")
    parser.add_argument("--stage1-enrich-ms", type=float, default=3.0, help="Synthetic Stage1 enrich latency")
    parser.add_argument("--hash-ms", type=float, default=12.0, help="Synthetic hash lane latency")
    return parser.parse_args()


async def _run_benchmark(args: argparse.Namespace) -> None:
    urls = [f"https://synthetic-{index}.example.org" for index in range(args.urls)]

    async def fake_stage0_stream(metric_urls, scoring_config, *, on_batch_complete=None, **kwargs):
        batch_size = max(1, min(2048, len(metric_urls)))
        completed = 0
        batch_id = 0
        while completed < len(metric_urls):
            chunk = metric_urls[completed:completed + batch_size]
            await asyncio.sleep(args.stage0_batch_ms / 1000.0)
            await on_batch_complete(
                chunk,
                [
                    {
                        "strict_lexical_hit": False,
                        "lexical_score_pass": False,
                        "fallback_rank_only": False,
                        "source_workbook": "",
                    }
                    for _ in chunk
                ],
            )
            completed += len(chunk)
            batch_id += 1
        return {
            "metric_urls_total": len(metric_urls),
            "metric_urls_completed": len(metric_urls),
            "input_urls_completed": len(metric_urls),
            "batches_total": batch_id,
            "batches_completed": batch_id,
            "avg_batch_latency_ms": args.stage0_batch_ms,
        }

    async def fake_stage1_pipeline(*, ingress_queue, producer_done_event, progress, stage1_analysis_map, on_admit=None, admitted_urls=None, **kwargs):
        processed = 0
        while True:
            try:
                item = await asyncio.wait_for(ingress_queue.get(), timeout=0.05)
            except asyncio.TimeoutError:
                if producer_done_event.is_set() and ingress_queue.empty():
                    break
                continue
            await asyncio.sleep(args.stage1_fetch_ms / 1000.0)
            await asyncio.sleep(args.stage1_enrich_ms / 1000.0)
            normalized_url = item["normalized_url"]
            stage1_analysis_map[normalized_url] = {
                **comparison._stage1_signal_defaults(),
                "fetch_status": "fetched",
                "escalate_to_hashing": True,
                "escalate_reason": "synthetic",
            }
            if admitted_urls is not None:
                admitted_urls.append(item["raw_url"])
            if on_admit is not None:
                await on_admit(item["raw_url"], normalized_url, stage1_analysis_map[normalized_url])
            progress.mark_completed(final_status="stage1_completed")
            processed += 1
            ingress_queue.task_done()
        return {
            "results": stage1_analysis_map,
            "progress": {"processed": processed},
            "elapsed_s": processed * (args.stage1_fetch_ms + args.stage1_enrich_ms) / 1000.0,
            "fetch_limit": 1,
            "queue_snapshot": {},
        }

    async def fake_run_browser_shard(*worker_args, **kwargs):
        url_queue = worker_args[1]
        gpu_queue = worker_args[2]
        while True:
            item = await url_queue.get()
            if item is None:
                url_queue.task_done()
                break
            await asyncio.sleep(args.hash_ms / 1000.0)
            await gpu_queue.put({"url": item})
            url_queue.task_done()

    async def fake_gpu_microbatch_scorer(gpu_queue, results, review_results, decision_rows, metrics, threshold, scoring_config, hash_progress=None):
        while True:
            item = await gpu_queue.get()
            if item is None:
                gpu_queue.task_done()
                break
            metrics["gpu_batches_flushed"] += 1
            metrics["gpu_items_scored"] += 1
            metrics["avg_gpu_batch_size"] = 1.0
            metrics["hashed_success"] += 1
            metrics["processed"] += 1
            metrics["finalized"] += 1
            if hash_progress is not None:
                hash_progress.mark_completed(final_status="hashed_success")
            gpu_queue.task_done()

    start = time.perf_counter()
    with (
        mock.patch.object(comparison, "_compute_stage0_prefetch_metrics_parallel_streaming", side_effect=fake_stage0_stream),
        mock.patch.object(comparison, "_run_stage1_http_pipeline", side_effect=fake_stage1_pipeline),
        mock.patch.object(comparison, "_run_browser_shard", side_effect=fake_run_browser_shard),
        mock.patch.object(comparison, "_gpu_microbatch_scorer", side_effect=fake_gpu_microbatch_scorer),
        mock.patch.object(comparison, "_finish_hashing_shortlist_output", return_value={"done": True}),
        mock.patch.object(comparison, "BROWSER_SHARDS", 1),
        mock.patch.object(comparison, "SCRAPER_PAGE_CONCURRENCY", 1),
        mock.patch.object(comparison, "_has_aiohttp", False),
    ):
        await comparison.run_hashing_shortlist_streaming(urls)
    elapsed = max(0.001, time.perf_counter() - start)
    print(f"synthetic_urls={args.urls}")
    print(f"elapsed_s={elapsed:.3f}")
    print(f"urls_per_sec={args.urls / elapsed:.2f}")


def main() -> None:
    args = _parse_args()
    asyncio.run(_run_benchmark(args))


if __name__ == "__main__":
    main()
