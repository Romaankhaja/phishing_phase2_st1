import asyncio
import unittest
from unittest import mock

from phishing_pipeline import ray_runtime


class RayRuntimeServerProfileTests(unittest.IsolatedAsyncioTestCase):
    async def test_ocr_worker_batches_concurrent_extract_requests(self):
        worker = ray_runtime._OcrWorkerActorImpl(max_batch_size=32, max_batch_delay_ms=50)
        worker._prewarmed = True

        async def fake_extract(domain_url, screenshot_path, shortlisted_cse="", shortlisted_domain="", html_text=""):
            await asyncio.sleep(0.01)
            return {
                "ocr_text": domain_url,
                "screenshot_path": screenshot_path,
                "tvc_brand_spoofed": False,
                "tvc_spoof_strong": False,
            }

        try:
            with mock.patch("phishing_pipeline.pipeline._extract_hash_only_ocr_tvc", new=fake_extract):
                tasks = [
                    asyncio.create_task(
                        worker.extract(
                            {
                                "domain_url": f"https://example{i}.test",
                                "screenshot_path": f"shot{i}.png",
                            }
                        )
                    )
                    for i in range(3)
                ]
                results = await asyncio.gather(*tasks)
                stats = worker.stats()
        finally:
            await worker.close()

        self.assertEqual(3, len(results))
        self.assertEqual("https://example0.test", results[0]["ocr_text"])
        self.assertEqual(1, stats["batches_processed"])
        self.assertEqual(3, stats["last_batch_size"])
        self.assertEqual(3, stats["items_processed"])


if __name__ == "__main__":
    unittest.main()
