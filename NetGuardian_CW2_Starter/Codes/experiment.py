#!/usr/bin/env python3
"""NetGuardian Task 5 guided integration and five-run evaluation helper.

This script records metrics only when supplied with measured values. It does not
fabricate RTT, detection, mitigation, or flow-count results.
"""
import argparse, csv, statistics
from pathlib import Path

FIELDS = ["run","average_rtt_ms","active_flows",
          "intrusion_detection_time_s","mitigation_response_time_s"]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="../data/performance_runs.csv")
    p.add_argument("--add-run", nargs=4, metavar=("RTT_MS","ACTIVE_FLOWS","DETECTION_S","MITIGATION_S"))
    a = p.parse_args()
    path = Path(a.results); path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(path.open())) if path.exists() else []
    if a.add_run:
        if len(rows) >= 5:
            raise SystemExit("Five runs already recorded. Use a new results file to repeat.")
        vals = [float(x) for x in a.add_run]
        rows.append(dict(zip(FIELDS, [len(rows)+1] + vals)))
        with path.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
        print(f"Recorded run {len(rows)} in {path}")
    if rows:
        print(f"Recorded independent runs: {len(rows)}/5")
        if len(rows) == 5:
            for field in FIELDS[1:]:
                values = [float(r[field]) for r in rows]
                print(f"{field}: mean={statistics.mean(values):.4f}, "
                      f"stdev={statistics.stdev(values):.4f}")
        else:
            print("Do not report final averages until five valid independent runs are recorded.")
    else:
        print("Guided integration checklist:")
        for item in [
            "Start Ryu with controller.py and verify c0 listens on 127.0.0.1:6633.",
            "Run sudo python3 topology.py; verify nodes, net, dump and pingall.",
            "Verify s1-s3 use OpenFlow13 and inspect ovs-ofctl dump-flows.",
            "Test authorized host -> h7; h6 -> h7 blocked; h6 -> non-h7 reachable.",
            "Run monitoring.py while generating ICMP, normal TCP and h8 high-rate TCP.",
            "Verify low-rate no-alert, high-rate alert, mitigation rule and timeout recovery.",
            "Perform five separate runs and record measured values with --add-run."
        ]: print(" - " + item)

if __name__ == "__main__":
    main()
