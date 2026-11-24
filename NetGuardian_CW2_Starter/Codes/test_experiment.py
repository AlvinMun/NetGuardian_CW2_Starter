#!/usr/bin/env python3
"""Unit tests for experiment metric parsing and CSV handling."""
import argparse
import csv
import tempfile
import unittest
from pathlib import Path

from experiment import (FIELDS, add_manual_run, parse_run_values,
                        ping_average_rtt, ping_ok, read_new_csv_rows)


class ExperimentHelperTests(unittest.TestCase):
    def test_parses_ping_results(self):
        output = ("3 packets transmitted, 3 packets received, 0% packet loss\n"
                  "rtt min/avg/max/mdev = 0.041/0.058/0.093/0.021 ms\n")
        self.assertTrue(ping_ok(output))
        self.assertEqual(ping_average_rtt(output), 0.058)
        self.assertFalse(ping_ok("3 packets transmitted, 0 received, 100% loss"))

    def test_rejects_non_integer_flow_counts(self):
        with self.assertRaises(SystemExit):
            parse_run_values(["2.1", "4.5", "1", "0.1"], argparse.ArgumentParser())

    def test_records_measured_rows_and_reads_new_security_events(self):
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / "runs.csv"
            number = add_manual_run(result_path, [2.1, 4, 1.0, 0.1])
            with result_path.open(newline="", encoding="utf-8") as result_file:
                rows = list(csv.DictReader(result_file))
            self.assertEqual(number, 1)
            self.assertEqual(rows[0]["run"], "1")
            self.assertEqual(rows[0]["active_flows"], "4")
            self.assertEqual(len(FIELDS), 5)

            event_path = Path(directory) / "security.csv"
            event_path.write_text("".join(
                "a,b,c,d,e,f,g,h,i,j,k,3,true,DROP_REQUESTED\r\n"),
                encoding="utf-8")
            offset, events = read_new_csv_rows(event_path, 0)
            self.assertEqual(offset, event_path.stat().st_size)
            self.assertEqual(events[0][12], "true")


if __name__ == "__main__":
    unittest.main()
