#!/usr/bin/env python3
"""Unit tests for the dependency-free new-flow rate detector."""
import unittest

from flow_detection import FlowRateDetector


def flow(source_port):
    return ("10.0.3.99", "10.0.3.40", source_port, 5001, 6)


class FlowRateDetectorTests(unittest.TestCase):
    def test_counts_distinct_five_tuples_only(self):
        detector = FlowRateDetector(window_seconds=5, threshold=4)
        first = detector.observe(flow(40000), now=1)
        duplicate = detector.observe(flow(40000), now=2)
        second = detector.observe(flow(40001), now=2)

        self.assertEqual(first.flow_count, 1)
        self.assertIsNone(duplicate)
        self.assertEqual(second.flow_count, 2)
        self.assertFalse(second.suspicious)

    def test_threshold_is_strictly_exceeded(self):
        detector = FlowRateDetector(window_seconds=5, threshold=4)
        observations = [detector.observe(flow(41000 + n), now=1 + n / 10)
                        for n in range(20)]

        self.assertEqual(observations[-1].measured_rate, 4)
        self.assertFalse(observations[-1].suspicious)
        over_threshold = detector.observe(flow(42000), now=3.1)
        self.assertEqual(over_threshold.flow_count, 21)
        self.assertTrue(over_threshold.suspicious)

    def test_old_flows_expire_from_rolling_window(self):
        detector = FlowRateDetector(window_seconds=5, threshold=0.2)
        detector.observe(flow(43000), now=1)
        recent = detector.observe(flow(43001), now=7)

        self.assertEqual(recent.flow_count, 1)
        self.assertEqual(recent.measured_rate, 0.2)
        self.assertFalse(recent.suspicious)

    def test_window_and_threshold_are_validated(self):
        with self.assertRaises(ValueError):
            FlowRateDetector(window_seconds=0)
        with self.assertRaises(ValueError):
            FlowRateDetector(threshold=-1)
        with self.assertRaises(ValueError):
            FlowRateDetector(window_seconds=float("nan"))
        with self.assertRaises(ValueError):
            FlowRateDetector(threshold=float("inf"))


if __name__ == "__main__":
    unittest.main()
