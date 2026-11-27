"""Collect OpenFlow statistics and plot the measured CSV data using Python 3."""

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
from pathlib import Path
import time
from xml.sax.saxutils import escape

from settings import HOST_PORTS, SWITCH_IDS


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class CsvLog:
    def __init__(self, path, fields):
        self.path = Path(path)
        self.fields = fields.split()
        with self.path.open("x", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerow(self.fields)

    def write(self, rows):
        with self.path.open("a", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerows(rows)


class Monitor:
    def __init__(self, output):
        fields = "timestamp elapsed_s sample switch_id"
        self.summary = CsvLog(output / "monitoring.csv",
                              fields + " active_flows packet_count byte_count mean_duration_s")
        self.flows = CsvLog(output / "flow_stats.csv", fields +
                           " table_id priority cookie packet_count byte_count flow_duration_s match")
        self.ports = CsvLog(output / "port_stats.csv", fields +
                           " port rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped")
        self.started = time.monotonic()
        self.sample = 0
        self.pending = {}

    def poll(self, datapaths):
        self.sample += 1
        self.pending = {key: entry for key, entry in self.pending.items()
                        if entry[0] >= self.sample - 3}
        stamp = utc_timestamp()
        elapsed = round(time.monotonic() - self.started, 6)
        for dp in datapaths:
            parser = dp.ofproto_parser
            for request in (parser.OFPFlowStatsRequest(dp),
                            parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)):
                dp.set_xid(request)
                self.pending[dp.id, request.xid] = (self.sample, stamp, elapsed, [])
                dp.send_msg(request)

    def receive(self, msg, kind):
        """Return the full reply after the final multipart fragment arrives."""
        dp = msg.datapath
        key = dp.id, msg.xid
        entry = self.pending.get(key)
        if entry is None:
            return None
        sample, stamp, elapsed, stats = entry
        stats.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return None
        del self.pending[key]
        prefix = (stamp, elapsed, sample, dp.id)
        if kind == "port":
            self.ports.write(
                (*prefix, p.port_no, p.rx_packets, p.tx_packets, p.rx_bytes,
                 p.tx_bytes, p.rx_dropped, p.tx_dropped) for p in stats
            )
        else:
            active = [f for f in stats if f.priority != 0]
            durations = [f.duration_sec + f.duration_nsec / 1e9 for f in active]
            self.flows.write(
                (*prefix, f.table_id, f.priority, hex(f.cookie), f.packet_count,
                 f.byte_count, f.duration_sec + f.duration_nsec / 1e9,
                 repr(dict(f.match.items()))) for f in stats
            )
            self.summary.write([(*prefix, len(active), sum(f.packet_count for f in active),
                                 sum(f.byte_count for f in active),
                                 sum(durations) / len(durations) if durations else 0)])
        return stats


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def line_chart(path, title, ylabel, points):
    if not points:
        raise ValueError(f"No samples available for {title}")
    width, height = 800, 390
    left, top, chart_w, chart_h = 112, 50, 645, 270
    xmax = max(1.0, points[-1][0])
    ymax = max(1.0, max(y for _, y in points))
    drawing = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'role="img" aria-label="{escape(title)}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<g font-family="sans-serif" font-size="13" fill="#17202b">',
        f'<text x="400" y="28" text-anchor="middle" font-size="19">{escape(title)}</text>',
    ]
    for tick in range(6):
        x = left + chart_w * tick / 5
        y = top + chart_h - chart_h * tick / 5
        drawing.extend([
            f'<path d="M {left} {y} H {left + chart_w}" stroke="#dce1e6"/>',
            f'<text x="{left - 9}" y="{y + 4}" text-anchor="end">{ymax * tick / 5:.3g}</text>',
            f'<text x="{x}" y="{top + chart_h + 21}" text-anchor="middle">'
            f'{xmax * tick / 5:.3g}</text>',
        ])
    coordinates = " ".join(f"{left + chart_w * x / xmax:.2f},"
                           f"{top + chart_h * (1 - y / ymax):.2f}" for x, y in points)
    drawing.extend([
        f'<path d="M {left} {top} V {top + chart_h} H {left + chart_w}" '
        'fill="none" stroke="#17202b"/>',
        f'<polyline points="{coordinates}" fill="none" stroke="#006b75" stroke-width="2.5"/>',
        f'<text x="{left + chart_w / 2}" y="372" text-anchor="middle">Elapsed time (s)</text>',
        f'<text transform="translate(25 185) rotate(-90)" text-anchor="middle">'
        f'{escape(ylabel)}</text></g></svg>',
    ])
    path.write_text("\n".join(drawing), encoding="utf-8")


def plot(output):
    output = Path(output)
    by_sample = defaultdict(dict)
    times = {}
    for row in read_csv(output / "monitoring.csv"):
        sample = int(row["sample"])
        by_sample[sample][int(row["switch_id"])] = int(row["active_flows"])
        times[sample] = float(row["elapsed_s"])
    flows = [(times[sample], sum(by_sample[sample].values()))
             for sample in sorted(by_sample) if len(by_sample[sample]) == len(SWITCH_IDS)]
    port_rows = sorted(
        (float(row["elapsed_s"]), int(row["tx_bytes"]))
        for row in read_csv(output / "port_stats.csv")
        if int(row["switch_id"]) == SWITCH_IDS["s3"] and int(row["port"]) == HOST_PORTS["h7"]
    )
    volume = [(new_t, new_bytes - old_bytes)
              for (_, old_bytes), (new_t, new_bytes) in zip(port_rows, port_rows[1:])
              if 0 <= old_bytes <= new_bytes < 2**64 - 1]
    line_chart(output / "active_flows.svg", "Active OpenFlow rules over time",
               "Non-table-miss rules (count)", flows)
    line_chart(output / "traffic_volume.svg", "Traffic delivered toward h7 over time",
               "s3 host-port TX (bytes per sample)", volume)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="directory containing the monitoring CSVs")
    plot(parser.parse_args().output)
