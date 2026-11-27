"""Merge TCP SYN observations and sampled ingress flow entries by five-tuple."""

from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowRate:
    source: str
    count: int
    seconds: float
    packet_in_count: int
    stats_count: int

    @property
    def rate(self):
        return self.count / self.seconds


class FlowWindow:
    def __init__(self, started, interval):
        self.started = started
        self.interval = interval
        self.seen = {}
        self.packet_in = set()
        self.stats = set()

    def observe_packet(self, key, now):
        self._observe(key, now, self.packet_in)

    def observe_stats(self, key, installed_at):
        if installed_at >= self.started:
            self._observe(key, installed_at, self.stats)

    def _observe(self, key, timestamp, observations):
        if key not in self.seen:
            self.seen[key] = timestamp
        if self.seen[key] >= self.started:
            observations.add(key)

    def close(self, now):
        seconds = now - self.started
        if seconds < self.interval:
            return None
        counts = defaultdict(lambda: [0, 0, 0])
        for key in self.packet_in | self.stats:
            source = key[0]
            counts[source][0] += 1
            counts[source][1] += key in self.packet_in
            counts[source][2] += key in self.stats
        result = [FlowRate(source, count, seconds, packets, stats)
                  for source, (count, packets, stats) in sorted(counts.items())]
        # Keep recent five-tuples across windows so a retry cannot look like a new flow.
        self.seen = {key: timestamp for key, timestamp in self.seen.items()
                     if now - timestamp < max(15, 2 * self.interval)}
        self.packet_in.clear()
        self.stats.clear()
        self.started = now
        return result
