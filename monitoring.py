#!/usr/bin/env python3
"""NetGuardian Task 3: poll Open vSwitch flow/port counters and export CSV.

Run on the Ubuntu VM while Mininet is running. Uses ovs-ofctl and Python stdlib.
PNG graph creation is optional and requires matplotlib already present in the VM.
"""
import argparse, csv, re, subprocess, time
from datetime import datetime
from pathlib import Path

def run_cmd(args):
    return subprocess.run(args, capture_output=True, text=True, check=False).stdout

def collect_switch(sw):
    flows = run_cmd(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw])
    ports = run_cmd(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports", sw])
    flow_lines = [x for x in flows.splitlines() if "table=" in x and "priority=0" not in x]
    packets = sum(int(x) for x in re.findall(r"n_packets=(\d+)", flows))
    bytes_ = sum(int(x) for x in re.findall(r"n_bytes=(\d+)", flows))
    durations = [float(x) for x in re.findall(r"duration=([0-9.]+)s", flows)]
    port_rx = sum(int(x) for x in re.findall(r"rx pkts=(\d+)", ports))
    port_tx = sum(int(x) for x in re.findall(r"tx pkts=(\d+)", ports))
    return {
        "active_flows": len(flow_lines), "packet_count": packets,
        "byte_count": bytes_, "max_flow_duration_s": max(durations, default=0),
        "port_rx_packets": port_rx, "port_tx_packets": port_tx,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--out", default="../data")
    a = p.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    flow_path, port_path = out / "flow_stats.csv", out / "port_stats.csv"
    flow_fields = ["timestamp","switch","packet_count","byte_count",
                   "max_flow_duration_s","active_flows"]
    port_fields = ["timestamp","switch","rx_packets","tx_packets"]
    start = time.monotonic()
    with flow_path.open("w", newline="") as ff, port_path.open("w", newline="") as pf:
        fw, pw = csv.DictWriter(ff, fieldnames=flow_fields), csv.DictWriter(pf, fieldnames=port_fields)
        fw.writeheader(); pw.writeheader()
        while time.monotonic() - start < a.duration:
            stamp = datetime.now().isoformat(timespec="milliseconds")
            for sw in ("s1","s2","s3"):
                stats = collect_switch(sw)
                fw.writerow({"timestamp":stamp,"switch":sw, **{k:stats[k] for k in
                    ("packet_count","byte_count","max_flow_duration_s","active_flows")}})
                pw.writerow({"timestamp":stamp,"switch":sw,
                             "rx_packets":stats["port_rx_packets"],
                             "tx_packets":stats["port_tx_packets"]})
            ff.flush(); pf.flush()
            time.sleep(a.interval)
    print(f"Wrote {flow_path} and {port_path}")
    try:
        import matplotlib.pyplot as plt
        rows = list(csv.DictReader(flow_path.open()))
        for sw in ("s1","s2","s3"):
            subset = [r for r in rows if r["switch"] == sw]
            if not subset: continue
            x = list(range(len(subset)))
            plt.plot(x, [int(r["active_flows"]) for r in subset], label=sw)
        plt.xlabel("Monitoring sample"); plt.ylabel("Active non-table-miss flows")
        plt.title("Active OpenFlow flows over time"); plt.legend(); plt.tight_layout()
        plt.savefig(out / "active_flows.png"); plt.close()
        rows = list(csv.DictReader(flow_path.open()))
        for sw in ("s1","s2","s3"):
            subset = [r for r in rows if r["switch"] == sw]
            if not subset: continue
            plt.plot(range(len(subset)), [int(r["byte_count"]) for r in subset], label=sw)
        plt.xlabel("Monitoring sample"); plt.ylabel("Cumulative flow bytes")
        plt.title("Traffic volume over time"); plt.legend(); plt.tight_layout()
        plt.savefig(out / "traffic_volume.png"); plt.close()
        print("Generated active_flows.png and traffic_volume.png")
    except ImportError:
        print("matplotlib is not installed; CSVs are saved. Ask the teaching team before installing packages.")
if __name__ == "__main__":
    main()
