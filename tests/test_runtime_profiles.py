import unittest
from types import SimpleNamespace
from unittest import mock

import main_controller
from phishing_pipeline.config import resolve_ray_runtime_config


class RuntimeProfileTests(unittest.TestCase):
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
        self.assertEqual(4, config["stage0_inflight"])
        self.assertEqual(12, config["stage1_fetch_actors"])
        self.assertEqual(6, config["stage1_enrich_actors"])
        self.assertEqual(8, config["hash_browser_actors"])
        self.assertEqual(2, config["hash_tabs_per_actor"])
        self.assertEqual(32, config["hash_finalize_batch"])
        self.assertEqual(8, config["classify_actors"])
        self.assertEqual(8, config["classify_inflight"])
        self.assertEqual(48, config["stage1_pending_cap"])
        self.assertEqual(16, config["hash_pending_cap"])
        self.assertEqual(192, config["stage1_http_connection_cap"])
        self.assertEqual(96, config["stage1_http_keepalive_cap"])
        self.assertEqual("staged", config["prewarm_mode"])
        self.assertTrue(config["enable_dynamic_control"])

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


if __name__ == "__main__":
    unittest.main()
