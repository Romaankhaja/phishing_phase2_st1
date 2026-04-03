import unittest

from phishing_pipeline import comparison


class Stage1AdaptiveDownshiftTests(unittest.TestCase):
    def test_requires_two_pressure_windows_before_downshift(self):
        first = comparison._compute_stage1_downshift(
            current_limit=48,
            floor_limit=24,
            step=8,
            processed_total=600,
            window_processed=250,
            window_failed=90,
            window_timed_out=100,
            gpu_queue_depth=0,
            gpu_backlog_threshold=48,
            consecutive_pressure_windows=0,
        )

        self.assertFalse(first["should_downshift"])
        self.assertEqual(first["next_limit"], 48)
        self.assertEqual(first["next_consecutive_pressure_windows"], 1)

        second = comparison._compute_stage1_downshift(
            current_limit=48,
            floor_limit=24,
            step=8,
            processed_total=900,
            window_processed=250,
            window_failed=90,
            window_timed_out=100,
            gpu_queue_depth=0,
            gpu_backlog_threshold=48,
            consecutive_pressure_windows=first["next_consecutive_pressure_windows"],
        )

        self.assertTrue(second["should_downshift"])
        self.assertEqual(second["next_limit"], 40)
        self.assertEqual(second["next_consecutive_pressure_windows"], 0)

    def test_continues_stepping_down_to_floor(self):
        limit = 48
        consecutive = 0
        expected_limits = [40, 32, 24]

        for expected_limit in expected_limits:
            comparison._compute_stage1_downshift(
                current_limit=limit,
                floor_limit=24,
                step=8,
                processed_total=1200,
                window_processed=300,
                window_failed=120,
                window_timed_out=120,
                gpu_queue_depth=0,
                gpu_backlog_threshold=48,
                consecutive_pressure_windows=consecutive,
            )
            decision = comparison._compute_stage1_downshift(
                current_limit=limit,
                floor_limit=24,
                step=8,
                processed_total=1500,
                window_processed=300,
                window_failed=120,
                window_timed_out=120,
                gpu_queue_depth=0,
                gpu_backlog_threshold=48,
                consecutive_pressure_windows=1,
            )
            limit = decision["next_limit"]
            consecutive = decision["next_consecutive_pressure_windows"]
            self.assertEqual(limit, expected_limit)

        floor_decision = comparison._compute_stage1_downshift(
            current_limit=24,
            floor_limit=24,
            step=8,
            processed_total=1800,
            window_processed=300,
            window_failed=120,
            window_timed_out=120,
            gpu_queue_depth=0,
            gpu_backlog_threshold=48,
            consecutive_pressure_windows=1,
        )

        self.assertFalse(floor_decision["should_downshift"])
        self.assertEqual(floor_decision["next_limit"], 24)

    def test_skips_downshift_when_gpu_queue_is_backlogged(self):
        decision = comparison._compute_stage1_downshift(
            current_limit=48,
            floor_limit=24,
            step=8,
            processed_total=900,
            window_processed=250,
            window_failed=90,
            window_timed_out=100,
            gpu_queue_depth=80,
            gpu_backlog_threshold=48,
            consecutive_pressure_windows=1,
        )

        self.assertFalse(decision["should_downshift"])
        self.assertEqual(decision["next_limit"], 48)
        self.assertEqual(decision["next_consecutive_pressure_windows"], 0)
