"""Bounded ICMP and TCP health-check traffic for the Mininet hosts."""

import argparse
import json
import math
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import time

from settings import HOST_IP, SERVICE_PORT

MAX_RATE = 5
MAX_DURATION = 30
PAYLOAD = b"netguardian-check\n"


class HealthCheck(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(0.5)
        if self.rfile.readline(len(PAYLOAD) + 1) == PAYLOAD:
            self.wfile.write(PAYLOAD)


class HealthServer(socketserver.TCPServer):
    allow_reuse_address = True


def tcp_probe(source, destination, port, timeout=0.12):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.bind((HOST_IP[source], 0))
        try:
            client.connect((HOST_IP[destination], port))
            client.sendall(PAYLOAD)
            with client.makefile("rb") as response:
                return response.readline(len(PAYLOAD) + 1) == PAYLOAD
        except OSError:
            return False


def generate(args):
    if not (0 < args.rate <= MAX_RATE and 0 < args.duration <= MAX_DURATION):
        raise SystemExit(f"Use a rate in (0, {MAX_RATE}] and duration in (0, {MAX_DURATION}]")
    attempts = math.ceil(args.rate * args.duration)
    if args.protocol == "icmp":
        result = subprocess.run(
            ["ping", "-n", "-I", HOST_IP[args.source], "-c", str(attempts),
             "-i", str(max(0.2, 1 / args.rate)), "-W", "1", HOST_IP[args.destination]],
            check=False,
        )
        return result.returncode
    if args.rate > 2 and (args.source, args.destination) != ("h8", "h7"):
        raise SystemExit("Rates above 2 checks/s are reserved for the h8/h7 lab scenario")
    # Validate the source address before publishing the experiment start.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.bind((HOST_IP[args.source], 0))
    started = time.monotonic()
    if args.start_file:
        with args.start_file.open("x", encoding="utf-8") as stream:
            stream.write(f"{started:.9f}\n")
    sent = succeeded = 0
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    next_probe = started
    while not stopping and sent < attempts and next_probe < started + args.duration:
        time.sleep(max(0, next_probe - time.monotonic()))
        now = time.monotonic()
        if stopping or now >= started + args.duration:
            break
        succeeded += tcp_probe(args.source, args.destination, args.port)
        sent += 1
        next_probe = now + 1 / args.rate
    print(json.dumps({"source": args.source, "destination": args.destination,
                      "attempts": sent, "successful": succeeded,
                      "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the TCP health-check service on h7")
    serve.add_argument("--port", type=int, default=SERVICE_PORT)
    traffic = commands.add_parser("generate", help="run a finite traffic experiment")
    traffic.add_argument("protocol", choices=("icmp", "tcp"))
    traffic.add_argument("--source", choices=HOST_IP, required=True)
    traffic.add_argument("--destination", choices=HOST_IP, default="h7")
    traffic.add_argument("--rate", type=float, default=1)
    traffic.add_argument("--duration", type=float, default=3)
    traffic.add_argument("--port", type=int, default=SERVICE_PORT)
    traffic.add_argument("--start-file", type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.command == "serve":
        with HealthServer((HOST_IP["h7"], args.port), HealthCheck) as server:
            print("READY", flush=True)
            server.serve_forever()
    return generate(args)


if __name__ == "__main__":
    raise SystemExit(main())
