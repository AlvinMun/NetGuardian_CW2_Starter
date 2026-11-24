#!/usr/bin/env python3
"""Small, dependency-free rolling-window detector for TCP five-tuples."""
from collections import deque, namedtuple
import math


FlowRateObservation = namedtuple(
    "FlowRateObservation",
    "flow_count measured_rate threshold window_seconds suspicious",
)


class FlowRateDetector:
    """Count distinct flow keys seen in the most recent fixed-length window."""

    def __init__(self, window_seconds=5.0, threshold=4.0):
        if not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be finite and positive")
        if not math.isfinite(threshold) or threshold < 0:
            raise ValueError("threshold must be finite and non-negative")
        self.window_seconds = float(window_seconds)
        self.threshold = float(threshold)
        self._events = deque()
        self._active_flows = set()

    def observe(self, flow, now):
        """Return an observation for a new five-tuple, or None for a duplicate.

        ``flow`` is (source IP, destination IP, source port, destination port,
        IP protocol). ``now`` is a monotonic timestamp supplied by the caller.
        """
        cutoff = float(now) - self.window_seconds
        while self._events and self._events[0][0] <= cutoff:
            _, expired_flow = self._events.popleft()
            self._active_flows.discard(expired_flow)

        flow = tuple(flow)
        if flow in self._active_flows:
            return None

        self._active_flows.add(flow)
        self._events.append((float(now), flow))
        count = len(self._active_flows)
        rate = count / self.window_seconds
        return FlowRateObservation(
            flow_count=count,
            measured_rate=rate,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
            suspicious=rate > self.threshold,
        )
