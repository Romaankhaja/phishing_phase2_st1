import os
import unittest
from unittest import mock

import main_controller


class RuntimeProfileTests(unittest.TestCase):
    def test_auto_profile_resolves_small_laptop_to_cpu_safe(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "auto",
            resource_info={
                "cpu_cores": 12,
                "ram_gb": 7.7,
                "vram_gb": 4.0,
                "platform": "win32",
            },
        )

        self.assertEqual(settings["requested_profile"], "auto")
        self.assertEqual(settings["resolved_profile"], "cpu-safe")
        self.assertEqual(settings["name"], "cpu-safe")

    def test_default_alias_resolves_like_auto(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "default",
            resource_info={
                "cpu_cores": 12,
                "ram_gb": 7.7,
                "vram_gb": 4.0,
                "platform": "win32",
            },
        )

        self.assertEqual(settings["requested_profile"], "default")
        self.assertEqual(settings["resolved_profile"], "cpu-safe")

    def test_auto_profile_resolves_large_cpu_only_server_to_cpu_recall(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "auto",
            resource_info={
                "cpu_cores": 48,
                "ram_gb": 250.0,
                "vram_gb": 0.0,
                "platform": "linux",
            },
        )

        self.assertEqual(settings["resolved_profile"], "cpu-recall")

    def test_explicit_profile_bypasses_auto_resolution(self):
        settings = main_controller._resolve_runtime_profile_settings(
            "cpu-fast",
            resource_info={
                "cpu_cores": 12,
                "ram_gb": 7.7,
                "vram_gb": 4.0,
                "platform": "win32",
            },
        )

        self.assertEqual(settings["requested_profile"], "cpu-fast")
        self.assertEqual(settings["resolved_profile"], "cpu-fast")

    def test_cpu_safe_profile_has_expected_concurrency_values(self):
        settings = main_controller._resolve_runtime_profile_settings("cpu-safe")

        self.assertEqual(settings["dns_max_workers"], 192)
        self.assertEqual(settings["stage1_http"]["concurrency"], 96)
        self.assertEqual(settings["stage1_http"]["rdap_concurrency"], 4)
        self.assertEqual(settings["env"]["PHISHING_HASH_PAGES"], 16)
        self.assertEqual(settings["env"]["PHISHING_HASH_HTTP_LIMIT"], 64)

    def test_cpu_recall_profile_has_expected_concurrency_values(self):
        settings = main_controller._resolve_runtime_profile_settings("cpu-recall")

        self.assertEqual(settings["dns_max_workers"], 256)
        self.assertEqual(settings["stage1_http"]["concurrency"], 128)
        self.assertEqual(settings["stage1_http"]["rdap_concurrency"], 4)
        self.assertEqual(settings["env"]["PHISHING_HASH_PAGES"], 20)

    def test_apply_runtime_profile_env_sets_overrides(self):
        settings = main_controller._resolve_runtime_profile_settings("cpu-fast")

        with mock.patch.dict(os.environ, {}, clear=True):
            main_controller._apply_runtime_profile_env(settings)

            self.assertEqual(os.environ["PHISHING_HASH_PAGES"], "24")
            self.assertEqual(os.environ["PHISHING_HASH_HTTP_LIMIT"], "96")
            self.assertEqual(os.environ["PHISHING_DNS_GATE_MAX_WORKERS"], "256")

    def test_apply_stage1_http_runtime_profile_updates_existing_config(self):
        settings = main_controller._resolve_runtime_profile_settings("cpu-safe")
        base_config = {
            "concurrency": 200,
            "http_concurrency": 200,
            "dns_concurrency": 200,
            "rdap_concurrency": 10,
            "tls_concurrency": 32,
            "escalate_total_threshold": 60,
            "brand_min": 18,
            "credential_min": 18,
            "low_band_min": 20,
            "hard_trigger_brand_min": 10,
            "keep_stage1_suspected": False,
            "failed_fetch_suspected_min": None,
        }

        updated = main_controller._apply_stage1_http_runtime_profile(base_config, settings)

        self.assertIs(updated, base_config)
        self.assertEqual(updated["concurrency"], 96)
        self.assertEqual(updated["http_concurrency"], 96)
        self.assertEqual(updated["dns_concurrency"], 96)
        self.assertEqual(updated["rdap_concurrency"], 4)
        self.assertEqual(updated["tls_concurrency"], 16)
        self.assertEqual(updated["escalate_total_threshold"], 60)
        self.assertEqual(updated["brand_min"], 18)
        self.assertEqual(updated["credential_min"], 18)
        self.assertEqual(updated["low_band_min"], 20)
        self.assertEqual(updated["hard_trigger_brand_min"], 10)
        self.assertFalse(updated["keep_stage1_suspected"])
        self.assertIsNone(updated["failed_fetch_suspected_min"])


if __name__ == "__main__":
    unittest.main()
