"""Run individual NetGuardian checks, the integrated demo and five independent trials."""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import os
import re
import shutil
import socket
from statistics import mean
import subprocess
import sys
import time

from mininet.log import setLogLevel

from monitoring import CsvLog, plot, read_csv
from settings import (
    CONTROLLER_IP, CONTROLLER_PORT, HOST_IP, MITIGATION_PRIORITY, SERVICE_PORT, SWITCH_IDS,
)
from topology import enterprise_network
from traffic_generator import MAX_DURATION, MAX_RATE

HERE = Path(__file__).resolve().parent
METRICS = ("average_rtt_ms", "active_openflow_flows", "detection_ms", "mitigation_ms")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(check, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.04)
    raise RuntimeError(f"Timed out waiting for {description}")


@contextmanager
def logged_process(launcher, command, log, **kwargs):
    with log.open("w", encoding="utf-8") as stream:
        child = launcher(command, stdout=stream, stderr=subprocess.STDOUT, **kwargs)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


@contextmanager
def controller(args, directory, basic=False, mitigate=True):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((CONTROLLER_IP, args.controller_port))
        except OSError as exc:
            raise RuntimeError(f"Controller port {args.controller_port} is unavailable") from exc
    app = "ryu.app.simple_switch_13" if basic else str(HERE / "controller.py")
    env = dict(os.environ, NG_OUTPUT=str(directory), NG_WINDOW=str(args.window),
               NG_POLL=str(args.poll), NG_THRESHOLD=str(args.threshold),
               NG_BLOCK_SECONDS=str(args.block_seconds), NG_MITIGATE="1" if mitigate else "0",
               PYTHONPATH=str(HERE) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    command = [args.ryu_manager, "--ofp-listen-host", CONTROLLER_IP,
               "--ofp-tcp-listen-port", str(args.controller_port), app]
    with logged_process(subprocess.Popen, command, directory / "controller.log",
                        cwd=HERE, env=env) as child:
        def ready():
            require(child.poll() is None, f"Ryu stopped. See {directory / 'controller.log'}")
            try:
                with socket.create_connection((CONTROLLER_IP, args.controller_port), timeout=0.1):
                    return True
            except OSError:
                return False

        wait_for(ready, 12, "Ryu to listen")
        yield


def ping(net, source, destination, count=1):
    host = net[source]
    result = host.popen(["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "1",
                         HOST_IP[destination]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, _ = result.communicate(timeout=count + 4)
    if result.returncode not in (0, 1):
        raise RuntimeError(stdout.decode(errors="replace"))
    return result.returncode == 0, stdout.decode(errors="replace")


def ovs(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=5)


def dump_flows(directory, name):
    sections = {switch: ovs("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch)
                for switch in SWITCH_IDS}
    (directory / f"{name}.txt").write_text(
        "\n".join(f"--- {sw} ---\n{table}" for sw, table in sections.items()), encoding="utf-8"
    )
    return sections


def traffic_command(args, protocol, source, rate, duration, start_file=None):
    command = [
        sys.executable, str(HERE / "traffic_generator.py"), "generate", protocol,
        "--source", source, "--destination", "h7", "--rate", str(rate),
        "--duration", str(duration), "--port", str(args.service_port),
    ]
    if start_file:
        command += ["--start-file", str(start_file)]
    return command


def completed_traffic(child, log, timeout):
    require(child.wait(timeout=timeout) == 0, f"Traffic command failed. See {log}")
    return log.read_text(encoding="utf-8")


def event_for(directory, event):
    return next((row for row in read_csv(directory / "security_events.csv")
                 if row["source_host"] == "h8" and row["event"] == event), None)


def topology_check(args, directory):
    directory.mkdir()
    with controller(args, directory, basic=True):
        with enterprise_network(controller_port=args.controller_port) as net:
            report = directory / "topology.txt"
            with report.open("w", encoding="utf-8") as stream:
                print("nodes:", " ".join(sorted(net.keys())), file=stream)
                print("net:", file=stream)
                for link in net.links:
                    print(link, file=stream)
                print("dump:", file=stream)
                for node in net.values():
                    print(repr(node), file=stream)
                print(ovs("ovs-vsctl", "show"), file=stream)
                for switch in SWITCH_IDS:
                    print(switch, ovs("ovs-vsctl", "get", "bridge", switch, "protocols").strip(),
                          file=stream)
                loss = net.pingAll()
                print(f"pingall: {loss:.1f}% loss", file=stream)
            require(loss == 0, "Task 1 pingall failed")
            dump_flows(directory, "topology_flows")


def policy_demo(net, directory):
    with (directory / "policy_checks.txt").open("w", encoding="utf-8") as report:
        for source, target, expected in (("h1", "h7", True), ("h6", "h7", False),
                                         ("h6", "h5", True)):
            success, output = ping(net, source, target)
            print(f"{source} -> {target} expected={expected} observed={success}\n{output}",
                  file=report)
            require(success == expected, f"Unexpected policy for {source} -> {target}")
    active = dump_flows(directory, "policy_active")
    for switch, table in active.items():
        require(any("idle_timeout=5" in line and ",icmp," in line
                    for line in table.splitlines()), f"No 5-second ICMP rule on {switch}")
    require("actions=drop" in active["s3"] and HOST_IP["h6"] in active["s3"],
            "Guest DROP missing")
    time.sleep(5.4)
    expired = dump_flows(directory, "policy_expired")
    # The kernel can issue fresh ARP probes while the tested ICMP rules are idle.
    for table in expired.values():
        require("priority=0" in table and ",icmp," not in table,
                "Expected permanent table-miss and expired ICMP forwarding rules")


def normal_rtt(net, directory):
    good, output = ping(net, "h1", "h7", count=6)
    (directory / "normal_ping.txt").write_text(output, encoding="utf-8")
    match = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s+ms", output)
    require(good and match is not None, "Unable to measure normal RTT")
    return float(match.group(1))


def traffic_check(args, net, directory, name, protocol, source, rate, duration):
    path = directory / f"{name}.log"
    command = traffic_command(args, protocol, source, rate, duration)
    with logged_process(net[source].popen, command, path) as child:
        output = completed_traffic(child, path, duration + 4)
    if protocol == "tcp":
        result = json.loads(output)
        require(result["successful"] > 0, f"No successful health checks in {path}")
        return result
    return None


def normal_traffic(args, net, directory):
    traffic_check(args, net, directory, "icmp", "icmp", "h1", 1, 3)
    traffic_check(args, net, directory, "normal_tcp", "tcp", "h1", 1, 3)


def low_rate_check(args, net, directory):
    traffic_check(args, net, directory, "low_rate_tcp", "tcp", "h8", 1, args.window + 1)
    time.sleep(args.window)
    require(not event_for(directory, "alert"), "The low-rate condition triggered an alert")


def security_trial(args, net, directory, checks):
    start_file = directory / "high_rate_start.txt"
    duration = 2 * args.window + 0.5
    command = traffic_command(args, "tcp", "h8", MAX_RATE, duration, start_file)
    traffic_log = directory / "high_rate_tcp.log"
    with logged_process(net["h8"].popen, command, traffic_log) as traffic:
        wait_for(lambda: start_file.exists() and start_file.stat().st_size, 3, "TCP start")
        start = float(start_file.read_text(encoding="utf-8"))
        confirmed = wait_for(lambda: event_for(directory, "drop_confirmed"),
                             duration + 2, "h8 DROP confirmation")
        alert = event_for(directory, "alert")
        tables = dump_flows(directory, "mitigating_flows")
        require(any(f"priority={MITIGATION_PRIORITY}" in line and "actions=drop" in line
                    for line in tables["s3"].splitlines()), "Mitigation rule missing from s3")
        active = sum("actions=" in line and "priority=0" not in line
                     for table in tables.values() for line in table.splitlines())
        if checks:
            legit, legit_output = ping(net, "h1", "h7")
            blocked, blocked_output = ping(net, "h8", "h7")
            (directory / "during_mitigation.txt").write_text(
                f"h1 -> h7\n{legit_output}\nh8 -> h7\n{blocked_output}", encoding="utf-8")
            require(legit and not blocked, "Mitigation did not isolate the intended host")
        if traffic.poll() is None:
            # Leave enough time to demonstrate timed recovery without starting a second burst.
            traffic.terminate()
        summary = json.loads(completed_traffic(traffic, traffic_log, 3))
        require(summary["attempts"] > 1, "Expected distinct TCP connection attempts from h8")
    wait_for(lambda: event_for(directory, "drop_removed"), args.block_seconds + 2,
             "mitigation timeout")
    if checks:
        restored, output = ping(net, "h8", "h7")
        (directory / "after_mitigation.txt").write_text(output, encoding="utf-8")
        require(restored, "h8 could not reach h7 after mitigation expired")
    return (active, (float(alert["monotonic_s"]) - start) * 1000,
            (float(confirmed["monotonic_s"]) - float(alert["monotonic_s"])) * 1000)


@contextmanager
def tcp_service(args, net, directory):
    command = [sys.executable, str(HERE / "traffic_generator.py"), "serve",
               "--port", str(args.service_port)]
    log = directory / "tcp_service.log"
    with logged_process(net["h7"].popen, command, log) as child:
        def ready():
            require(child.poll() is None, f"TCP service failed. See {log}")
            return "READY" in log.read_text(encoding="utf-8")

        wait_for(ready, 5, "TCP service")
        yield


def run(args, directory, mode):
    directory.mkdir()
    with controller(args, directory, mitigate=mode != "monitoring"):
        with enterprise_network(controller_port=args.controller_port) as net:
            if mode in ("policy", "demo"):
                policy_demo(net, directory)
            if mode == "policy":
                return
            rtt = normal_rtt(net, directory) if mode in ("demo", "benchmark") else None
            with tcp_service(args, net, directory):
                if mode in ("monitoring", "demo"):
                    normal_traffic(args, net, directory)
                if mode == "monitoring":
                    high = traffic_check(args, net, directory, "high_rate_tcp",
                                         "tcp", "h8", MAX_RATE, 2 * args.window + 0.5)
                    require(high["attempts"] > 1, "Expected multiple h8 health checks")
                    time.sleep(args.poll)
                else:
                    if mode in ("security", "demo"):
                        low_rate_check(args, net, directory)
                    active, detection, mitigation = security_trial(
                        args, net, directory, checks=mode != "benchmark"
                    )
    if mode in ("monitoring", "demo"):
        plot(directory)
    if mode == "benchmark":
        return rtt, active, detection, mitigation


def benchmark(args, output):
    table = CsvLog(output / "performance.csv", "run " + " ".join(METRICS))
    rows = []
    for index in range(1, 6):
        print(f"Starting independent trial {index}/5", flush=True)
        result = run(args, output / f"run_{index}", "benchmark")
        rows.append(result)
        table.write([(index, *(round(value, 3) for value in result))])
    table.write([("mean", *(round(mean(values), 3) for values in zip(*rows)))])


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="all",
                        choices=("topology", "policy", "monitoring", "security",
                                 "demo", "benchmark", "evaluation", "all"),
                        help="Tasks 1–5: topology, policy, monitoring, security, evaluation")
    parser.add_argument("--output", type=Path, required=True, help="new results directory")
    parser.add_argument("--ryu-manager", default=shutil.which("ryu-manager"))
    parser.add_argument("--controller-port", type=int, default=CONTROLLER_PORT)
    parser.add_argument("--service-port", type=int, default=SERVICE_PORT)
    parser.add_argument("--window", type=float, default=2)
    parser.add_argument("--poll", type=float, default=0.5)
    parser.add_argument("--threshold", type=float, default=3)
    parser.add_argument("--block-seconds", type=int, choices=range(3, 6), default=5)
    args = parser.parse_args()
    if not args.ryu_manager:
        parser.error("ryu-manager is not on PATH. Supply --ryu-manager with its absolute path")
    if not (0.2 <= args.poll < args.window and 1 <= args.window <= (MAX_DURATION - 0.5) / 2):
        parser.error("Use a window of 1–14.75 s and a poll interval of at least 0.2 s below it")
    if not 2 <= args.threshold <= MAX_RATE - 1:
        parser.error(f"Use a threshold in [2, {MAX_RATE - 1}] new flows/s")
    if not all(1 <= port <= 65535 for port in (args.controller_port, args.service_port)):
        parser.error("Ports must be between 1 and 65535")
    return args


def main():
    args = parse_args()
    require(os.geteuid() == 0, "Run the experiment with sudo in the course Ubuntu VM")
    os.environ["LC_ALL"] = "C"
    setLogLevel("info")
    output = args.output.resolve()
    output.mkdir(parents=True)
    if args.mode in ("topology", "all"):
        topology_check(args, output / "topology")
    if args.mode in ("policy", "monitoring", "security"):
        run(args, output / args.mode, args.mode)
    if args.mode in ("demo", "evaluation", "all"):
        run(args, output / "demo", "demo")
    if args.mode in ("benchmark", "evaluation", "all"):
        benchmark(args, output)
    print(f"Results: {output}", flush=True)


if __name__ == "__main__":
    main()
