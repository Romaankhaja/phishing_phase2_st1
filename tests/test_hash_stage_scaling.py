import unittest

from phishing_pipeline import comparison


class HashStageScalingTests(unittest.TestCase):
    def test_hash_adjustment_upshifts_after_two_healthy_windows(self):
        first = comparison._compute_hash_fetch_adjustment(
            current_limit=32,
            max_limit=48,
            floor_limit=16,
            step=8,
            processed_total=800,
            window_processed=200,
            window_failed=5,
            window_timed_out=5,
            render_queue_depth=10,
            aux_queue_depth=5,
            finalize_queue_depth=3,
            result_queue_max=1000,
            fd_usage_ratio=0.20,
            ram_usage_ratio=0.30,
            consecutive_pressure_windows=0,
            consecutive_healthy_windows=0,
        )
        self.assertFalse(first["should_upshift"])
        second = comparison._compute_hash_fetch_adjustment(
            current_limit=32,
            max_limit=48,
            floor_limit=16,
            step=8,
            processed_total=1000,
            window_processed=220,
            window_failed=5,
            window_timed_out=5,
            render_queue_depth=8,
            aux_queue_depth=4,
            finalize_queue_depth=2,
            result_queue_max=1000,
            fd_usage_ratio=0.20,
            ram_usage_ratio=0.30,
            consecutive_pressure_windows=first["next_consecutive_pressure_windows"],
            consecutive_healthy_windows=first["next_consecutive_healthy_windows"],
        )
        self.assertTrue(second["should_upshift"])
        self.assertEqual(40, second["next_limit"])

    def test_hash_adjustment_downshifts_on_pressure(self):
        first = comparison._compute_hash_fetch_adjustment(
            current_limit=64,
            max_limit=96,
            floor_limit=32,
            step=8,
            processed_total=1200,
            window_processed=150,
            window_failed=60,
            window_timed_out=40,
            render_queue_depth=600,
            aux_queue_depth=500,
            finalize_queue_depth=400,
            result_queue_max=800,
            fd_usage_ratio=0.80,
            ram_usage_ratio=0.40,
            consecutive_pressure_windows=0,
            consecutive_healthy_windows=0,
        )
        self.assertFalse(first["should_downshift"])
        second = comparison._compute_hash_fetch_adjustment(
            current_limit=64,
            max_limit=96,
            floor_limit=32,
            step=8,
            processed_total=1400,
            window_processed=150,
            window_failed=60,
            window_timed_out=40,
            render_queue_depth=600,
            aux_queue_depth=500,
            finalize_queue_depth=400,
            result_queue_max=800,
            fd_usage_ratio=0.80,
            ram_usage_ratio=0.40,
            consecutive_pressure_windows=first["next_consecutive_pressure_windows"],
            consecutive_healthy_windows=0,
        )
        self.assertTrue(second["should_downshift"])
        self.assertEqual(56, second["next_limit"])


if __name__ == "__main__":
    unittest.main()
