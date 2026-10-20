"""Bidirectional flow assembler for live capture.

Packets are grouped by the canonical 5-tuple (src, dst, sport, dport, proto).
A flow is flushed once it has been idle for LIVE_FLOW_TIMEOUT seconds; the
accumulated statistics are then converted into the NetHawk feature vector by
LiveTrafficFeatureAdapter.  The statistics collected here mirror the
CIC-IDS2017 definitions closely enough to be fed to the same model, but they
are NOT computed by CICFlowMeter - see docs/architecture.md for the caveat.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    start: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    fwd_lengths: list[int] = field(default_factory=list)
    bwd_lengths: list[int] = field(default_factory=list)
    fwd_times: list[float] = field(default_factory=list)
    bwd_times: list[float] = field(default_factory=list)
    all_times: list[float] = field(default_factory=list)
    flags: dict[str, int] = field(default_factory=lambda: {
        "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0})
    init_win_fwd: int = 0

    # Set by FlowTable; the direction-independent key this flow is stored under.
    table_key: tuple | None = None
    # >0 when this Flow is the merge of N micro-flows (see aggregate_micro_flows).
    aggregated: int = 0

    @property
    def key(self) -> tuple:
        return self.table_key or (self.src, self.dst, self.sport, self.dport, self.protocol)

    @property
    def packet_count(self) -> int:
        return len(self.fwd_lengths) + len(self.bwd_lengths)

    def add(self, length: int, forward: bool, timestamp: float,
            flags: dict[str, int] | None = None, window: int | None = None) -> None:
        self.last_seen = timestamp
        self.all_times.append(timestamp)
        if forward:
            self.fwd_lengths.append(length)
            self.fwd_times.append(timestamp)
            if window is not None and self.init_win_fwd == 0:
                self.init_win_fwd = int(window)
        else:
            self.bwd_lengths.append(length)
            self.bwd_times.append(timestamp)
        if flags:
            for name, value in flags.items():
                if value:
                    self.flags[name] = self.flags.get(name, 0) + 1

    def is_expired(self, timeout: float, now: float | None = None) -> bool:
        return (now or time.time()) - self.last_seen >= timeout

    # ------------------------------------------------------------- stats ----
    @staticmethod
    def _mean(values: list[float]) -> float:
        return float(statistics.fmean(values)) if values else 0.0

    @staticmethod
    def _iats(times: list[float]) -> list[float]:
        return [(b - a) * 1e6 for a, b in zip(times, times[1:])]  # microseconds

    def statistics_dict(self) -> dict[str, float]:
        duration_us = max(1.0, (self.last_seen - self.start) * 1e6)
        all_lengths = self.fwd_lengths + self.bwd_lengths
        iats = self._iats(sorted(self.all_times))
        return {
            "duration_us": duration_us,
            "fwd_pkts": len(self.fwd_lengths),
            "bwd_pkts": len(self.bwd_lengths),
            "fwd_bytes": float(sum(self.fwd_lengths)),
            "bwd_bytes": float(sum(self.bwd_lengths)),
            "fwd_mean": self._mean(self.fwd_lengths),
            "bwd_mean": self._mean(self.bwd_lengths),
            "pkt_min": float(min(all_lengths)) if all_lengths else 0.0,
            "pkt_max": float(max(all_lengths)) if all_lengths else 0.0,
            "pkt_mean": self._mean(all_lengths),
            "pkt_std": float(statistics.pstdev(all_lengths)) if len(all_lengths) > 1 else 0.0,
            "iat_mean": self._mean(iats),
            "iat_std": float(statistics.pstdev(iats)) if len(iats) > 1 else 0.0,
            "fwd_iat_mean": self._mean(self._iats(self.fwd_times)),
            "bwd_iat_mean": self._mean(self._iats(self.bwd_times)),
            "flags": dict(self.flags),
            "port": float(self.dport),
            "win": float(self.init_win_fwd),
        }


class FlowTable:
    """Keeps live flows and hands back the ones that are ready for analysis."""

    def __init__(self, timeout: float = 5.0, max_flows: int = 4096) -> None:
        self.timeout = timeout
        self.max_flows = max_flows
        self.flows: dict[tuple, Flow] = {}

    @staticmethod
    def _unordered_key(src, dst, sport, dport, proto) -> tuple:
        """Direction-independent key: both directions of a conversation match."""
        endpoints = tuple(sorted([(src, sport), (dst, dport)]))
        return (endpoints[0], endpoints[1], proto)

    def add_packet(self, src: str, dst: str, sport: int, dport: int, proto: str,
                   length: int, timestamp: float | None = None,
                   flags: dict[str, int] | None = None,
                   window: int | None = None) -> None:
        timestamp = timestamp or time.time()
        key = self._unordered_key(src, dst, sport, dport, proto)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.max_flows:
                self.flows.pop(next(iter(self.flows)))
            # The first packet observed defines the forward (client->server)
            # direction, which is how CICFlowMeter labels a flow too.
            flow = Flow(src=src, dst=dst, sport=sport, dport=dport, protocol=proto,
                        start=timestamp, last_seen=timestamp)
            flow.table_key = key
            self.flows[key] = flow
        forward = (src, sport) == (flow.src, flow.sport)
        flow.add(length, forward, timestamp, flags, window)

    def collect_expired(self, now: float | None = None, force: bool = False) -> list[Flow]:
        now = now or time.time()
        ready = [f for f in self.flows.values() if force or f.is_expired(self.timeout, now)]
        for flow in ready:
            self.flows.pop(flow.key, None)
        return ready


def aggregate_micro_flows(flows: list[Flow], min_group: int = 5,
                          max_packets: int = 2) -> list[Flow]:
    """Merge storms of tiny flows into one record per (src, dst, proto, dport).

    Why this is needed: a SYN flood uses a fresh source port for every packet,
    so strict 5-tuple accounting turns 900 flood packets into 900 one-packet
    flows.  Analysed individually each one looks like a single stray probe, and
    the *aggregate* behaviour that actually defines a flood - the packet rate -
    is lost entirely (plus it means 900 model calls and 900 database rows).

    Grouping by destination **port** is what keeps the two reconnaissance
    patterns apart:

      * flood     -> hundreds of micro-flows to ONE port  -> merged, high rate
      * port scan -> one or two micro-flows per port across MANY ports
                     -> each group stays below min_group, so scans are left
                        alone and still look like scans

    Only groups of at least `min_group` flows of at most `max_packets` packets
    each are merged, so ordinary conversations are never touched.
    """
    groups: dict[tuple, list[Flow]] = {}
    passthrough: list[Flow] = []
    for flow in flows:
        if flow.packet_count <= max_packets:
            groups.setdefault((flow.src, flow.dst, flow.protocol, flow.dport),
                              []).append(flow)
        else:
            passthrough.append(flow)

    merged: list[Flow] = []
    for (src, dst, protocol, dport), members in groups.items():
        if len(members) < min_group:
            passthrough.extend(members)
            continue
        combined = Flow(src=src, dst=dst, sport=members[0].sport, dport=dport,
                        protocol=protocol,
                        start=min(f.start for f in members),
                        last_seen=max(f.last_seen for f in members))
        for member in members:
            combined.fwd_lengths.extend(member.fwd_lengths)
            combined.bwd_lengths.extend(member.bwd_lengths)
            combined.fwd_times.extend(member.fwd_times)
            combined.bwd_times.extend(member.bwd_times)
            combined.all_times.extend(member.all_times)
            for name, value in member.flags.items():
                combined.flags[name] = combined.flags.get(name, 0) + value
            combined.init_win_fwd = combined.init_win_fwd or member.init_win_fwd
        combined.fwd_times.sort()
        combined.bwd_times.sort()
        combined.all_times.sort()
        combined.aggregated = len(members)
        merged.append(combined)

    return passthrough + merged
