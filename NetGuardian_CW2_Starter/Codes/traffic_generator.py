#!/usr/bin/env python3
"""NetGuardian Task 3 traffic generator; run inside a Mininet host namespace."""
import argparse
import socket
import subprocess
import time

def tcp_client(destination, port, rate, duration):
    end = time.monotonic() + duration
    interval = 1.0 / max(rate, 0.1)
    sent = 0
    while time.monotonic() < end:
        start = time.monotonic()
        try:
            with socket.create_connection((destination, port), timeout=0.5):
                sent += 1
        except OSError:
            pass
        remaining = interval - (time.monotonic() - start)
        if remaining > 0:
            time.sleep(remaining)
    print(f"TCP connection attempts completed: {sent}")

def icmp(destination, duration, rate):
    end = time.monotonic() + duration
    interval = 1.0 / max(rate, 0.1)
    sent = 0
    while time.monotonic() < end:
        subprocess.run(["ping", "-c", "1", "-W", "1", destination],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sent += 1
        time.sleep(max(0, interval))
    print(f"ICMP echo attempts completed: {sent}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=("icmp", "tcp"), required=True)
    p.add_argument("--destination", required=True)
    p.add_argument("--port", type=int, default=5001)
    p.add_argument("--rate", type=float, default=1.0, help="attempts per second")
    p.add_argument("--duration", type=float, default=10.0)
    a = p.parse_args()
    if a.mode == "icmp":
        icmp(a.destination, a.duration, a.rate)
    else:
        tcp_client(a.destination, a.port, a.rate, a.duration)

if __name__ == "__main__":
    main()
