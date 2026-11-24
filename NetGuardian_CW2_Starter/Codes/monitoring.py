#!/usr/bin/env python3
"""NetGuardian Task 3: poll Open vSwitch flow/port counters and export CSV.

Run on the Ubuntu VM while Mininet is running. Uses ovs-ofctl and Python stdlib.
PNG graph creation is optional and requires matplotlib already present in the VM.
"""
import argparse, csv, html, math, re, subprocess, time
from datetime import datetime
from pathlib import Path

def run_cmd(args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("Command failed: {}: {}".format(
            " ".join(args), result.stderr.strip()))
    return result.stdout

def collect_switch(sw):
    flows = run_cmd(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", sw])
    ports = run_cmd(["ovs-ofctl", "-O", "OpenFlow13", "dump-ports", sw])
    flow_lines = [x for x in flows.splitlines()
                  if "table=" in x and not re.search(r"\bpriority=0(?:,|\s)", x)]
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

def write_svg_graph(path, title, y_label, series):
    """Write a simple labeled line graph using only the Python standard library."""
    width, height = 900, 520
    left, right, top, bottom = 100, 40, 60, 90
    plot_width, plot_height = width - left - right, height - top - bottom
    samples = max((len(values) for _, values in series), default=0)
    maximum = max((max(values, default=0) for _, values in series), default=0)
    scale_max = max(1, int(math.ceil(maximum / 5.0) * 5))
    colors = ("#1769aa", "#d1495b", "#2a9d8f")
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">'.format(width, height, width, height),
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="{}" y="32" text-anchor="middle" font-family="sans-serif" font-size="22" font-weight="bold">{}</text>'.format(width / 2, html.escape(title)),
    ]
    for tick in range(6):
        value = scale_max * tick / 5
        y = top + plot_height - plot_height * tick / 5
        lines.append('<line x1="{}" y1="{:.1f}" x2="{}" y2="{:.1f}" stroke="#d9d9d9"/>'.format(left, y, width-right, y))
        lines.append('<text x="{}" y="{:.1f}" text-anchor="end" font-family="sans-serif" font-size="12">{:.0f}</text>'.format(left-12, y+4, value))
    lines.extend([
        '<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#222"/>'.format(left, top, left, height-bottom),
        '<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#222"/>'.format(left, height-bottom, width-right, height-bottom),
        '<text x="{}" y="{}" text-anchor="middle" font-family="sans-serif" font-size="15">Monitoring sample</text>'.format(left + plot_width/2, height-25),
        '<text transform="translate(24 {}) rotate(-90)" text-anchor="middle" font-family="sans-serif" font-size="15">{}</text>'.format(top + plot_height/2, html.escape(y_label)),
    ])
    if samples:
        for index, (label, values) in enumerate(series):
            if not values:
                continue
            coords = []
            for sample, value in enumerate(values):
                x = left if samples == 1 else left + plot_width * sample / (samples - 1)
                y = top + plot_height - plot_height * value / scale_max
                coords.append('{:.1f},{:.1f}'.format(x, y))
            color = colors[index % len(colors)]
            lines.append('<polyline fill="none" stroke="{}" stroke-width="2.5" points="{}"/>'.format(color, ' '.join(coords)))
            legend_x = left + 150 * index
            lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{}" stroke-width="3"/>'.format(legend_x, height-60, legend_x+24, height-60, color))
            lines.append('<text x="{}" y="{}" font-family="sans-serif" font-size="13">{}</text>'.format(legend_x+31, height-55, html.escape(label)))
    lines.append('</svg>')
    path.write_text('\n'.join(lines), encoding='utf-8')

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--duration", type=float, default=60.0)
    p.add_argument("--out", default="data")
    a = p.parse_args()
    if (not math.isfinite(a.interval) or not math.isfinite(a.duration) or
            a.interval <= 0 or a.duration <= 0):
        p.error("--interval and --duration must be positive")
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
    with flow_path.open(newline="") as flow_file:
        rows = list(csv.DictReader(flow_file))
    for field, title, y_label, output in (
        ("active_flows", "Active OpenFlow flows over time", "Active non-table-miss flows", "active_flows.svg"),
        ("byte_count", "Traffic volume over time", "Cumulative flow bytes", "traffic_volume.svg"),
    ):
        series = []
        for sw in ("s1", "s2", "s3"):
            subset = [r for r in rows if r["switch"] == sw]
            series.append((sw, [int(r[field]) for r in subset]))
        write_svg_graph(out / output, title, y_label, series)
    print(f"Generated {out / 'active_flows.svg'} and {out / 'traffic_volume.svg'}")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        for sw in ("s1","s2","s3"):
            subset = [r for r in rows if r["switch"] == sw]
            if not subset: continue
            x = list(range(len(subset)))
            plt.plot(x, [int(r["active_flows"]) for r in subset], label=sw)
        plt.xlabel("Monitoring sample"); plt.ylabel("Active non-table-miss flows")
        plt.title("Active OpenFlow flows over time"); plt.legend(); plt.tight_layout()
        plt.savefig(out / "active_flows.png"); plt.close()
        with flow_path.open(newline="") as flow_file:
            rows = list(csv.DictReader(flow_file))
        for sw in ("s1","s2","s3"):
            subset = [r for r in rows if r["switch"] == sw]
            if not subset: continue
            plt.plot(range(len(subset)), [int(r["byte_count"]) for r in subset], label=sw)
        plt.xlabel("Monitoring sample"); plt.ylabel("Cumulative flow bytes")
        plt.title("Traffic volume over time"); plt.legend(); plt.tight_layout()
        plt.savefig(out / "traffic_volume.png"); plt.close()
        print("Generated active_flows.png and traffic_volume.png")
    except ImportError:
        print("matplotlib is not installed; standard-library SVG graphs were saved without adding packages.")
if __name__ == "__main__":
    main()
