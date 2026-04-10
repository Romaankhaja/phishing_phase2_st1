import unittest
from types import SimpleNamespace
from unittest import mock

import pandas as pd

import main_controller
from phishing_pipeline import comparison, pipeline
from phishing_pipeline.config import resolve_ray_runtime_config


class RayBackendDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_shortlist_async_dispatches_to_ray_backend(self):
        sentinel = pd.DataFrame([{"ok": 1}])
        with (
            mock.patch("phishing_pipeline.ray_runtime.run_hashing_shortlist_with_ray", new=mock.AsyncMock(return_value=sentinel)) as ray_impl,
            mock.patch.object(comparison, "run_hashing_shortlist_streaming", new=mock.AsyncMock()) as legacy_impl,
        ):
            result = await comparison.run_hashing_shortlist_async(
                ["https://example.com"],
                execution_backend="ray",
                progress_mode="compact",
            )

        self.assertIs(result, sentinel)
        ray_impl.assert_awaited_once()
        self.assertEqual("compact", ray_impl.await_args.kwargs.get("progress_mode"))
        legacy_impl.assert_not_awaited()

    async def test_pipeline_hash_only_auto_uses_ray_backend(self):
        holdout_df = pd.DataFrame(
            [
                {
                    "Identified Phishing/Suspected Domain Name": "https://example.com",
                    "Legitimate Domains": "legit.example",
                    "Cooresponding CSE": "Example CSE",
                    "hash_score": 88.0,
                    "fetch_status": "fetched",
                }
            ]
        )
        whitelist_df = pd.DataFrame({"Legitimate Domains": ["legit.example"]})
        sentinel = pd.DataFrame([{"Application_ID": "x"}])

        with (
            mock.patch.object(pipeline.pd, "read_excel", return_value=whitelist_df),
            mock.patch.object(pipeline.pd, "read_csv", return_value=holdout_df),
            mock.patch.object(pipeline.os.path, "exists", return_value=True),
            mock.patch("phishing_pipeline.ray_runtime.run_hash_only_pipeline_with_ray", new=mock.AsyncMock(return_value=sentinel)) as ray_impl,
            mock.patch.object(pipeline, "_run_hash_only_pipeline", new=mock.AsyncMock()) as legacy_impl,
        ):
            result = await pipeline.run_pipeline(
                holdout_folder="ignored",
                ps02_whitelist_file="ignored.xlsx",
                use_existing_holdout=True,
                pipeline_mode="hash_only",
                execution_backend="auto",
                progress_mode="compact",
            )

        self.assertIs(result, sentinel)
        ray_impl.assert_awaited_once()
        self.assertEqual("compact", ray_impl.await_args.kwargs.get("progress_mode"))
        legacy_impl.assert_not_awaited()

    async def test_pipeline_hash_only_legacy_backend_uses_legacy_classifier(self):
        holdout_df = pd.DataFrame(
            [
                {
                    "Identified Phishing/Suspected Domain Name": "https://example.com",
                    "Legitimate Domains": "legit.example",
                    "Cooresponding CSE": "Example CSE",
                    "hash_score": 72.0,
                    "fetch_status": "fetched",
                }
            ]
        )
        whitelist_df = pd.DataFrame({"Legitimate Domains": ["legit.example"]})
        sentinel = pd.DataFrame([{"Application_ID": "legacy"}])

        with (
            mock.patch.object(pipeline.pd, "read_excel", return_value=whitelist_df),
            mock.patch.object(pipeline.pd, "read_csv", return_value=holdout_df),
            mock.patch.object(pipeline.os.path, "exists", return_value=True),
            mock.patch("phishing_pipeline.ray_runtime.run_hash_only_pipeline_with_ray", new=mock.AsyncMock()) as ray_impl,
            mock.patch.object(pipeline, "_run_hash_only_pipeline", new=mock.AsyncMock(return_value=sentinel)) as legacy_impl,
        ):
            result = await pipeline.run_pipeline(
                holdout_folder="ignored",
                ps02_whitelist_file="ignored.xlsx",
                use_existing_holdout=True,
                pipeline_mode="hash_only",
                execution_backend="legacy",
            )

        self.assertIs(result, sentinel)
        legacy_impl.assert_awaited_once()
        ray_impl.assert_not_awaited()

    def test_resolve_ray_runtime_config_bounds_actor_counts(self):
        fake_vm = SimpleNamespace(total=64 * 1024 ** 3, available=48 * 1024 ** 3)
        with mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)):
            config = resolve_ray_runtime_config(
                {
                    "stage0_batch_size": 1,
                    "stage0_inflight": 0,
                    "stage1_fetch_actors": 10_000,
                    "stage1_enrich_actors": 10_000,
                    "hash_browser_actors": 10_000,
                    "hash_tabs_per_actor": 0,
                    "hash_finalize_batch": 0,
                    "classify_actors": 10_000,
                    "ocr_actors": 0,
                    "metrics_interval_seconds": 0,
                }
            )

        self.assertGreaterEqual(config["stage0_batch_size"], 64)
        self.assertGreaterEqual(config["stage0_inflight"], 1)
        self.assertGreaterEqual(config["stage1_fetch_actors"], 4)
        self.assertGreaterEqual(config["stage1_enrich_actors"], 1)
        self.assertGreaterEqual(config["hash_browser_actors"], 1)
        self.assertGreaterEqual(config["hash_tabs_per_actor"], 1)
        self.assertGreaterEqual(config["hash_finalize_batch"], 1)
        self.assertGreaterEqual(config["classify_actors"], 2)
        self.assertGreaterEqual(config["ocr_actors"], 1)
        self.assertGreaterEqual(config["metrics_interval_seconds"], 1.0)

    def test_resolve_ray_runtime_config_enters_low_memory_failsafe_on_windows(self):
        fake_vm = SimpleNamespace(total=int(7.5 * 1024 ** 3), available=int(1.0 * 1024 ** 3))
        with (
            mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)),
            mock.patch("phishing_pipeline.config.sys.platform", "win32"),
        ):
            config = resolve_ray_runtime_config(
                {
                    "stage0_inflight": 8,
                    "stage1_fetch_actors": 24,
                    "stage1_enrich_actors": 12,
                    "hash_browser_actors": 6,
                    "hash_tabs_per_actor": 4,
                    "classify_actors": 12,
                }
            )

        self.assertFalse(config["local_mode"])
        self.assertEqual(config["stage0_inflight"], 1)
        self.assertEqual(config["stage1_fetch_actors"], 1)
        self.assertEqual(config["stage1_enrich_actors"], 1)
        self.assertEqual(config["hash_browser_actors"], 1)
        self.assertEqual(config["hash_tabs_per_actor"], 1)
        self.assertEqual(config["classify_actors"], 1)

    def test_auto_runtime_profile_resolves_server_balanced_for_large_host(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "auto",
            resource_info={"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 80.0, "platform": "linux"},
        )

        self.assertEqual("server-balanced", settings["resolved_profile"])
        self.assertEqual(10, settings["reliability"]["append_flush_interval_seconds"])
        self.assertEqual("staged", settings["env"]["PHISHING_RAY_PREWARM_MODE"])
        self.assertEqual("true", settings["env"]["PHISHING_RAY_PREWARM_ACTORS"])

    def test_cpu_recall_alias_resolves_to_server_throughput(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "cpu-recall",
            resource_info={"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 80.0, "platform": "linux"},
        )

        self.assertEqual("server-throughput", settings["resolved_profile"])

    def test_auto_runtime_profile_keeps_cpu_safe_for_laptop_host(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "auto",
            resource_info={"cpu_cores": 12, "ram_gb": 7.7, "vram_gb": 4.0, "platform": "win32"},
        )

        self.assertEqual("cpu-safe", settings["resolved_profile"])

    def test_resolve_ray_runtime_config_server_defaults(self):
        fake_vm = SimpleNamespace(total=int(250 * 1024 ** 3), available=int(220 * 1024 ** 3))
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)),
            mock.patch("phishing_pipeline.config.os.cpu_count", return_value=48),
        ):
            config = resolve_ray_runtime_config()

        self.assertTrue(config["server_mode"])
        self.assertEqual(config["stage0_batch_size"], 1024)
        self.assertEqual(config["stage0_inflight"], 4)
        self.assertEqual(config["stage1_fetch_actors"], 12)
        self.assertEqual(config["stage1_enrich_actors"], 6)
        self.assertEqual(config["hash_browser_actors"], 8)
        self.assertEqual(config["hash_tabs_per_actor"], 2)
        self.assertEqual(config["hash_finalize_batch"], 32)
        self.assertEqual(config["classify_actors"], 8)
        self.assertEqual(config["classify_inflight"], 8)
        self.assertEqual(config["ocr_actors"], 1)
        self.assertEqual(config["ocr_batch_size"], 32)
        self.assertEqual(config["ocr_batch_delay_ms"], 25)
        self.assertEqual(config["stage1_fetch_actor_max_concurrency"], 4)
        self.assertEqual(config["stage1_enrich_actor_max_concurrency"], 2)
        self.assertEqual(config["stage1_pending_cap"], 48)
        self.assertEqual(config["hash_pending_cap"], 16)
        self.assertEqual(config["stage1_http_connection_cap"], 192)
        self.assertEqual(config["stage1_http_keepalive_cap"], 96)
        self.assertTrue(config["prewarm_actors"])
        self.assertEqual(config["prewarm_mode"], "staged")

    def test_effective_detection_target_promotes_cross_domain_final_url(self):
        target = pipeline._resolve_effective_detection_target(
            {
                "Identified Phishing/Suspected Domain Name": "https://crsor.info",
                "final_landing_url": "https://portal.crsorgi.gov.in/login",
                "fetch_status": "fetched",
            }
        )

        self.assertTrue(target["redirect_promoted"])
        self.assertEqual(target["effective_url"], "https://portal.crsorgi.gov.in/login")
        self.assertEqual(target["effective_host"], "portal.crsorgi.gov.in")

    def test_effective_detection_target_keeps_original_for_same_registered_domain(self):
        target = pipeline._resolve_effective_detection_target(
            {
                "Identified Phishing/Suspected Domain Name": "https://login.example.com/start",
                "final_landing_url": "https://www.example.com/dashboard",
                "fetch_status": "fetched",
            }
        )

        self.assertFalse(target["redirect_promoted"])
        self.assertEqual(target["effective_url"], "https://login.example.com/start")
        self.assertEqual(target["effective_host"], "login.example.com")
