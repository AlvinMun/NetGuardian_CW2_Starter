#!/usr/bin/env python3
"""Tests for the dependency-free monitoring graph writer."""
import tempfile
import unittest
from pathlib import Path

from monitoring import write_svg_graph


class MonitoringGraphTests(unittest.TestCase):
    def test_writes_labeled_svg_with_each_switch_series(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "flows.svg"
            write_svg_graph(output, "Active flows", "Flows", [
                ("s1", [1, 3, 2]),
                ("s2", [0, 2, 4]),
                ("s3", [1, 1, 1]),
            ])
            svg = output.read_text(encoding="utf-8")

        self.assertIn("<svg", svg)
        self.assertIn("Active flows", svg)
        self.assertIn("Monitoring sample", svg)
        self.assertIn("Flows", svg)
        self.assertIn("s1", svg)
        self.assertIn("s2", svg)
        self.assertIn("s3", svg)

    def test_handles_empty_series(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "empty.svg"
            write_svg_graph(output, "Traffic", "Bytes", [])
            svg = output.read_text(encoding="utf-8")

        self.assertIn("Traffic", svg)
        self.assertIn("Bytes", svg)


if __name__ == "__main__":
    unittest.main()
