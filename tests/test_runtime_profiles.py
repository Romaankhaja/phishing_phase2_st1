import unittest
from types import SimpleNamespace
from unittest import mock

import main_controller
from phishing_pipeline.config import (
    FINAL_OUTPUT,
    PATHS_CONFIG,
    resolve_ray_runtime_config,
    resolve_reliability_config,
    resolve_runtime_profile,
    resolve_stage_config,
)


class RuntimeProfileTests(unittest.TestCase):
    def test_config_runtime_profile_matches_controller_wrapper(self):
        resource_info = {"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 80.0, "platform": "linux"}

        direct = resolve_runtime_profile("auto", resource_info=resource_info)
        via_controller = main_controller._resolve_runtime_profile_settings("auto", resource_info=resource_info)

        self.assertEqual(direct, via_controller)

    def test_auto_runtime_profile_resolves_server_balanced_for_large_host(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "auto",
            resource_info={"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 80.0, "platform": "linux"},
        )

        self.assertEqual("server-balanced", settings["resolved_profile"])
        self.assertEqual("staged", settings["env"]["PHISHING_RAY_PREWARM_MODE"])
        self.assertEqual("true", settings["env"]["PHISHING_RAY_ENABLE_DYNAMIC_CONTROL"])
        self.assertEqual(10, settings["reliability"]["append_flush_interval_seconds"])

    def test_resolve_ray_runtime_config_server_defaults_are_balanced(self):
        fake_vm = SimpleNamespace(total=int(250 * 1024 ** 3), available=int(220 * 1024 ** 3))
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)),
            mock.patch("phishing_pipeline.config.os.cpu_count", return_value=48),
        ):
            config = resolve_ray_runtime_config()

        self.assertTrue(config["server_mode"])
        self.assertEqual(1024, config["stage0_batch_size"])
        self.assertEqual(8, config["stage0_inflight"])
        self.assertEqual(24, config["stage1_fetch_actors"])
        self.assertEqual(12, config["stage1_enrich_actors"])
        self.assertEqual(12, config["hash_browser_actors"])
        self.assertEqual(3, config["hash_tabs_per_actor"])
        self.assertEqual(64, config["hash_finalize_batch"])
        self.assertEqual(16, config["classify_actors"])
        self.assertEqual(48, config["classify_inflight"])
        self.assertEqual(4, config["ocr_actors"])
        self.assertEqual(192, config["stage1_pending_cap"])
        self.assertEqual(96, config["hash_pending_cap"])
        self.assertEqual(768, config["stage1_http_connection_cap"])
        self.assertEqual(384, config["stage1_http_keepalive_cap"])
        self.assertEqual("staged", config["prewarm_mode"])
        self.assertTrue(config["enable_dynamic_control"])

    def test_resolve_ray_runtime_config_keeps_server_env_minima_under_budget(self):
        fake_vm = SimpleNamespace(total=int(250 * 1024 ** 3), available=int(220 * 1024 ** 3))
        env = {
            "PHISHING_RAY_HASH_BROWSER_ACTORS": "8",
            "PHISHING_RAY_HASH_TABS_PER_ACTOR": "2",
            "PHISHING_RAY_STAGE1_FETCH_ACTOR_MAX_CONCURRENCY": "4",
            "PHISHING_RAY_OCR_ACTORS": "4",
            "PHISHING_RAY_PREWARM_ACTORS": "true",
        }
        with (
            mock.patch.dict("os.environ", env, clear=True),
            mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)),
            mock.patch("phishing_pipeline.config.os.cpu_count", return_value=48),
        ):
            config = resolve_ray_runtime_config()

        self.assertTrue(config["server_mode"])
        self.assertGreaterEqual(config["hash_browser_actors"], 8)
        self.assertGreaterEqual(config["hash_tabs_per_actor"], 2)
        self.assertGreaterEqual(config["stage1_fetch_actor_max_concurrency"], 4)
        self.assertGreaterEqual(config["ocr_actors"], 4)
        self.assertTrue(config["prewarm_actors"])
        self.assertLessEqual(float(config["total_cpu_demand"]), float(config["planned_total_cpu_budget"]))

    def test_resolve_ray_runtime_config_clamps_cpu_budget(self):
        fake_vm = SimpleNamespace(total=int(250 * 1024 ** 3), available=int(220 * 1024 ** 3))
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("phishing_pipeline.config.psutil", new=SimpleNamespace(virtual_memory=lambda: fake_vm)),
            mock.patch("phishing_pipeline.config.os.cpu_count", return_value=48),
        ):
            config = resolve_ray_runtime_config(
                {
                    "stage0_inflight": 64,
                    "stage1_fetch_actors": 96,
                    "stage1_enrich_actors": 48,
                    "hash_browser_actors": 48,
                    "hash_tabs_per_actor": 8,
                    "classify_actors": 64,
                    "classify_inflight": 128,
                    "stage1_fetch_actor_max_concurrency": 16,
                    "stage1_enrich_actor_max_concurrency": 8,
                    "stage1_pending_cap": 512,
                    "hash_pending_cap": 256,
                }
            )

        self.assertTrue(config["budget_clamped"])
        self.assertLessEqual(float(config["actor_cpu_demand"]), float(config["actor_cpu_budget"]))
        self.assertLessEqual(float(config["total_cpu_demand"]), float(config["planned_total_cpu_budget"]))
        self.assertGreaterEqual(int(config["stage1_fetch_actors"]), 4)
        self.assertGreaterEqual(int(config["classify_inflight"]), 8)

    def test_stage_config_resolvers_apply_profile_overrides_from_config_module(self):
        resource_info = {"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 0.0, "platform": "linux"}
        runtime_profile = resolve_runtime_profile("auto", resource_info=resource_info)
        stage_config = resolve_stage_config(
            profile_name="auto",
            resource_info=resource_info,
            runtime_profile_settings=runtime_profile,
        )

        self.assertEqual("server-balanced", stage_config["runtime_profile"]["resolved_profile"])
        self.assertEqual(10, stage_config["reliability"]["append_flush_interval_seconds"])
        self.assertEqual(16, stage_config["stage0"]["lexical_workers"])

    def test_paths_config_keeps_legacy_final_output_alias(self):
        self.assertEqual(PATHS_CONFIG["final_output_csv"], FINAL_OUTPUT)

    def test_resolve_reliability_config_applies_profile_overlay(self):
        settings = resolve_runtime_profile(
            "server-balanced",
            resource_info={"cpu_cores": 48, "ram_gb": 250.0, "vram_gb": 0.0, "platform": "linux"},
        )
        config = resolve_reliability_config(runtime_profile_settings=settings)

        self.assertEqual(10, config["append_flush_interval_seconds"])
        self.assertEqual(10000, config["append_flush_row_interval"])


if __name__ == "__main__":
    unittest.main()
