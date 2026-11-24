#!/usr/bin/env python3
"""Integrated NetGuardian demonstration and five-run VM evaluation helper.

Run ``sudo python3 experiment.py --live`` in the module Ubuntu VM to launch
Ryu, Mininet, traffic, monitoring and the five measured performance runs.
Use ``--add-run`` only when values have been measured independently by hand.
"""
import argparse
import csv
import math
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


FIELDS = ["run", "average_rtt_ms", "active_flows",
          "intrusion_detection_time_s", "mitigation_response_time_s"]
CODE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CODE_DIR.parent
DATA_DIR = CODE_DIR / "data"
EVIDENCE_DIR = CODE_DIR / "Evidence" / "Task5"
H8_IP = "10.0.3.99"
H7_IP = "10.0.3.40"
HTTP_PORT = 5001
FLOW_WINDOW = 5
FLOW_THRESHOLD = 4
MITIGATION_TIMEOUT = 15
HIGH_RATE = 8
HIGH_DURATION = 12


def parse_run_values(values, parser):
    try:
        rtt, active, detection, mitigation = map(float, values)
    except ValueError:
        parser.error("--add-run values must be numeric")
    if not all(math.isfinite(value) and value >= 0
               for value in (rtt, active, detection, mitigation)):
        parser.error("--add-run values must be finite and non-negative")
    if not active.is_integer():
        parser.error("ACTIVE_FLOWS must be a whole number")
    return [rtt, int(active), detection, mitigation]


def load_rows(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as result_file:
        return list(csv.DictReader(result_file))


def add_manual_run(path, values):
    rows = load_rows(path)
    if len(rows) >= 5:
        raise ValueError("Five runs are already recorded; choose a new results file")
    row = dict(zip(FIELDS, [len(rows) + 1] + values))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as result_file:
        writer = csv.DictWriter(result_file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows + [row])
    return len(rows) + 1


def print_summary(rows):
    print("Recorded runs: {}/5".format(len(rows)))
    for row in rows:
        print("Run {run}: RTT={average_rtt_ms} ms, flows={active_flows}, "
              "detection={intrusion_detection_time_s} s, "
              "mitigation={mitigation_response_time_s} s".format(**row))
    if len(rows) != 5:
        print("Final averages are available after five runs.")
        return
    for field in FIELDS[1:]:
        values = [float(row[field]) for row in rows]
        print("{}: mean={:.4f}, stdev={:.4f}".format(
            field, statistics.mean(values), statistics.stdev(values)))


def ping_ok(output):
    match = re.search(r"(\d+) packets transmitted,\s*(\d+) (?:packets )?received", output)
    return bool(match and int(match.group(2)) > 0)


def ping_average_rtt(output):
    match = re.search(r"(?:rtt|round-trip) min/avg/max(?:/mdev|/stddev)?\s*=\s*"
                      r"[\d.]+/([\d.]+)/", output)
    if not match:
        raise RuntimeError("Could not read average RTT from ping output:\n" + output)
    return float(match.group(1))


def read_new_csv_rows(path, offset):
    if not path.exists():
        return offset, []
    with path.open("rb") as event_file:
        event_file.seek(offset)
        content = event_file.read()
        new_offset = event_file.tell()
    rows = list(csv.reader(content.decode("utf-8").splitlines())) if content else []
    return new_offset, [row for row in rows if len(row) >= 13]


def ovs_flows(switch):
    result = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch],
        check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("ovs-ofctl failed for {}: {}".format(switch, result.stderr.strip()))
    return result.stdout


def active_flow_count():
    count = 0
    for switch in ("s1", "s2", "s3"):
        lines = [line for line in ovs_flows(switch).splitlines()
                 if "table=" in line and not re.search(r"\bpriority=0(?:,|\s)", line)]
        count += len(lines)
    return count


def mitigation_present():
    output = ovs_flows("s3")
    return any("priority=500" in line and "ipv4_src=10.0.3.99" in line
               and "ipv4_dst=10.0.3.40" in line for line in output.splitlines())


def run_live_suite():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run --live with sudo in the module Ubuntu VM")
    for command in ("ryu-manager", "ovs-ofctl", "ovs-vsctl", "ping"):
        if shutil.which(command) is None:
            raise RuntimeError("Required VM command not found: {}".format(command))
    try:
        from mininet.log import setLogLevel
        from topology import build
    except ImportError as exc:
        raise RuntimeError("Mininet is not available; use the module Ubuntu VM") from exc

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    result_path = DATA_DIR / ("performance_runs_{}.csv".format(run_id))
    security_path = DATA_DIR / ("security_events_{}.csv".format(run_id))
    monitor_dir = DATA_DIR / ("monitoring_{}".format(run_id))
    log_path = EVIDENCE_DIR / ("integration_{}.log".format(run_id))
    ryu_log_path = EVIDENCE_DIR / ("ryu_{}.log".format(run_id))
    monitor_log_path = EVIDENCE_DIR / ("monitoring_{}.log".format(run_id))

    def log(message):
        print(message, flush=True)
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(str(message) + "\n")

    env = os.environ.copy()
    env.update({
        "NG_FLOW_WINDOW": str(FLOW_WINDOW),
        "NG_FLOW_THRESHOLD": str(FLOW_THRESHOLD),
        "NG_MITIGATION_TIMEOUT": str(MITIGATION_TIMEOUT),
        "NG_SECURITY_LOG": str(security_path),
    })
    ryu_output = ryu_log_path.open("w", encoding="utf-8")
    monitor_output = None
    controller = subprocess.Popen(
        [shutil.which("ryu-manager"), "controller.py"], cwd=str(CODE_DIR),
        env=env, stdout=ryu_output, stderr=subprocess.STDOUT, text=True)
    monitor = None
    net = None
    server = None
    results = []
    setLogLevel("warning")

    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if controller.poll() is not None:
                raise RuntimeError("Ryu exited; see {}".format(ryu_log_path))
            try:
                with socket.create_connection(("127.0.0.1", 6633), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError("Ryu did not listen on 127.0.0.1:6633")

        net = build()
        time.sleep(2)
        log("Integrated NetGuardian run started: {}".format(run_id))
        log("Nodes: c0, s1, s2, s3, h1, h2, h3, h4, h5, h6, h7, h8")
        for host in net.hosts:
            log("{} IP={} MAC={}".format(host.name, host.IP(), host.MAC()))
        for switch in ("s1", "s2", "s3"):
            protocol = subprocess.run(
                ["ovs-vsctl", "get", "Bridge", switch, "protocols"],
                capture_output=True, text=True, check=False).stdout.strip()
            log("{} OpenFlow protocols={}".format(switch, protocol))
            log("{} initial flows:\n{}".format(switch, ovs_flows(switch).strip()))

        h1, h6, h7, h8 = (net.get(name) for name in ("h1", "h6", "h7", "h8"))
        authorized = h1.cmd("ping -c 3 -W 1 {}".format(H7_IP))
        guest_server = h6.cmd("ping -c 2 -W 1 {}".format(H7_IP))
        guest_staff = h6.cmd("ping -c 2 -W 1 10.0.1.11")
        if not ping_ok(authorized):
            raise RuntimeError("Authorized h1 -> h7 connectivity failed:\n" + authorized)
        if ping_ok(guest_server):
            raise RuntimeError("The h6 -> h7 guest policy did not block traffic")
        if not ping_ok(guest_staff):
            raise RuntimeError("Guest h6 should still reach h1:\n" + guest_staff)
        log("Policy checks passed: h1 -> h7 allowed; h6 -> h7 denied; h6 -> h1 allowed")

        server = h7.popen([sys.executable, "-m", "http.server", str(HTTP_PORT)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        traffic_script = CODE_DIR / "traffic_generator.py"
        monitor_output = monitor_log_path.open("w", encoding="utf-8")
        monitor = subprocess.Popen(
            [sys.executable, str(CODE_DIR / "monitoring.py"), "--interval", "1",
             "--duration", "55", "--out", str(monitor_dir)],
            cwd=str(CODE_DIR), stdout=monitor_output, stderr=subprocess.STDOUT)

        def generate(host, mode, rate, duration):
            command = "{} {} --mode {} --destination {} --port {} --rate {} --duration {}".format(
                shlex_quote(sys.executable), shlex_quote(str(traffic_script)), mode,
                H7_IP, HTTP_PORT, rate, duration)
            return host.cmd(command)

        log("Normal ICMP experiment:\n" + generate(h1, "icmp", 1, 3).strip())
        log("Normal TCP experiment:\n" + generate(h1, "tcp", 2, 5).strip())
        log("Low-rate h8 experiment:\n" + generate(h8, "tcp", 1, 6).strip())
        time.sleep(FLOW_WINDOW + 0.2)

        def measured_trial(run_number):
            baseline = h1.cmd("ping -c 3 -W 1 {}".format(H7_IP))
            rtt = ping_average_rtt(baseline)
            offset = security_path.stat().st_size if security_path.exists() else 0
            started_wall = datetime.now(timezone.utc)
            started_mono = time.monotonic()
            high_process = h8.popen(
                [sys.executable, str(traffic_script), "--mode", "tcp",
                 "--destination", H7_IP, "--port", str(HTTP_PORT),
                 "--rate", str(HIGH_RATE), "--duration", str(HIGH_DURATION)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            event_offset = offset
            alert_time = None
            alert_seen = None
            while time.monotonic() - started_mono < HIGH_DURATION:
                event_offset, rows = read_new_csv_rows(security_path, event_offset)
                for row in rows:
                    if row[12].lower() == "true":
                        alert_time = datetime.fromisoformat(row[0]).timestamp()
                        alert_seen = time.monotonic()
                        break
                if alert_time is not None:
                    break
                if high_process.poll() is not None:
                    break
                time.sleep(0.05)
            if alert_time is None:
                high_process.wait(timeout=2)
                raise RuntimeError("Run {} did not detect h8 high-rate traffic".format(run_number))

            alert_wall = started_wall.timestamp()
            detection_seconds = max(0.0, alert_time - alert_wall)
            response_seconds = None
            response_deadline = time.monotonic() + 5
            while time.monotonic() < response_deadline:
                if mitigation_present():
                    response_seconds = time.monotonic() - alert_seen
                    break
                time.sleep(0.05)
            if response_seconds is None:
                raise RuntimeError("Run {} alert had no installed DROP rule".format(run_number))

            flows = active_flow_count()
            legitimate = h1.cmd("ping -c 1 -W 1 {}".format(H7_IP))
            blocked = h8.cmd("ping -c 1 -W 1 {}".format(H7_IP))
            if not ping_ok(legitimate):
                raise RuntimeError("Legitimate h1 traffic failed during mitigation")
            if ping_ok(blocked):
                raise RuntimeError("h8 traffic reached h7 during mitigation")
            log("Run {}: mitigation present; h1 remains connected; h8 blocked".format(run_number))

            high_process.wait(timeout=HIGH_DURATION + 2)
            expiry_deadline = time.monotonic() + MITIGATION_TIMEOUT + 3
            while time.monotonic() < expiry_deadline and mitigation_present():
                time.sleep(0.1)
            if mitigation_present():
                raise RuntimeError("Run {} mitigation rule did not expire".format(run_number))
            restored = h8.cmd("ping -c 2 -W 1 {}".format(H7_IP))
            if not ping_ok(restored):
                raise RuntimeError("Run {} h8 traffic was not restored".format(run_number))

            row = dict(zip(FIELDS, [run_number, "{:.4f}".format(rtt), flows,
                                    "{:.4f}".format(detection_seconds),
                                    "{:.4f}".format(response_seconds)]))
            results.append(row)
            log("Run {} measured: {}".format(run_number, row))
            with result_path.open("w", newline="", encoding="utf-8") as result_file:
                writer = csv.DictWriter(result_file, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(results)
            time.sleep(FLOW_WINDOW + 0.2)

        for run_number in range(1, 6):
            measured_trial(run_number)

        print_summary(results)
        log("Performance data: {}".format(result_path))
        log("Security event data: {}".format(security_path))
        log("Monitoring CSVs and graphs: {}".format(monitor_dir))
        log("Monitoring process log: {}".format(monitor_log_path))
        log("Ryu controller log: {}".format(ryu_log_path))
        if monitor is not None:
            try:
                monitor.wait(timeout=8)
            except subprocess.TimeoutExpired:
                monitor.terminate()
                monitor.wait(timeout=5)
            if monitor.returncode:
                raise RuntimeError("Monitoring failed; see {}".format(monitor_log_path))
    finally:
        if monitor is not None and monitor.poll() is None:
            monitor.terminate()
            monitor.wait(timeout=5)
        if server is not None and server.poll() is None:
            server.terminate()
            server.wait(timeout=5)
        if net is not None:
            net.stop()
        controller.terminate()
        try:
            controller.wait(timeout=5)
        except subprocess.TimeoutExpired:
            controller.kill()
            controller.wait(timeout=5)
        ryu_output.close()
        if monitor_output is not None:
            monitor_output.close()


def shlex_quote(value):
    """Quote one argument for Mininet Host.cmd's shell."""
    import shlex
    return shlex.quote(str(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true",
                        help="run the integrated demonstration and five trials in the Ubuntu VM")
    parser.add_argument("--results", default="data/performance_runs.csv",
                        help="CSV path for hand-entered measured runs")
    parser.add_argument("--add-run", nargs=4,
                        metavar=("RTT_MS", "ACTIVE_FLOWS", "DETECTION_S", "MITIGATION_S"),
                        help="append one independently measured run")
    args = parser.parse_args()

    if args.live:
        run_live_suite()
        return

    path = Path(args.results)
    rows = load_rows(path)
    if args.add_run:
        values = parse_run_values(args.add_run, parser)
        try:
            number = add_manual_run(path, values)
        except ValueError as exc:
            parser.error(str(exc))
        print("Recorded run {} in {}".format(number, path))
        rows = load_rows(path)
    if rows:
        print_summary(rows)
    else:
        print("For a full real-VM integration run: sudo python3 experiment.py --live")
        print("For manually measured values, use --add-run RTT_MS ACTIVE_FLOWS "
              "DETECTION_S MITIGATION_S. Do not enter example or estimated values.")


if __name__ == "__main__":
    main()
