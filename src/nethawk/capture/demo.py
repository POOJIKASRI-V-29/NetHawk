"""Controlled demo traffic source (Mode 1).

Two jobs:
  * `next_background_record()` - a steady stream of mostly-benign traffic so the
    dashboard has something to show while monitoring.
  * `simulation_sequence()`    - the "Run Security Simulation" button: a scripted,
    locally generated sequence of attack-like traffic records.

NOTHING here touches a network.  No packets are transmitted.  Each record is a
synthetic feature vector plus plausible metadata (source IP/MAC, port, protocol)
so the dashboard has realistic-looking context.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterator

from ..datasets.synthetic import ATTACK_LABELS, generate_flow

LOCAL_SUBNET = "192.168.1."
GATEWAY_IP = "192.168.1.1"


@dataclass
class TrafficRecord:
    """One unit of traffic handed to the detection pipeline."""
    features: dict[str, float]
    source: str
    destination: str
    protocol: str
    packets: int
    origin_label: str                      # the demo label used to synthesise it
    metadata: dict = field(default_factory=dict)


def _mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


class DemoTrafficGenerator:
    """Deterministic-by-seed generator of controlled demo traffic."""

    def __init__(self, seed: int | None = None, device_count: int = 6) -> None:
        self.rng = random.Random(seed)
        self.devices = [
            {"ip": f"{LOCAL_SUBNET}{self.rng.randint(20, 99)}", "mac": _mac(self.rng)}
            for _ in range(device_count)
        ]
        # A dedicated "attacker" host used by the security simulation.
        self.attacker = {"ip": f"{LOCAL_SUBNET}{self.rng.randint(100, 199)}",
                         "mac": _mac(self.rng)}

    # ------------------------------------------------------- background ----
    def next_background_record(self, attack_probability: float = 0.12) -> TrafficRecord:
        """Mostly benign traffic, with occasional low-level suspicious activity."""
        if self.rng.random() < attack_probability:
            label = self.rng.choice(["PortScan", "Bot", "FTP-Patator"])
            device = self.attacker
        else:
            label = "BENIGN"
            device = self.rng.choice(self.devices)
        return self._build(label, device)

    # ------------------------------------------------------- simulation ----
    def simulation_sequence(self, intensity: str = "standard") -> Iterator[TrafficRecord]:
        """The scripted attack demonstration: recon -> brute force -> flood."""
        script = [
            ("PortScan", 3),
            ("FTP-Patator", 2),
            ("DoS Hulk", 2),
            ("DDoS", 2),
        ]
        if intensity == "short":
            script = [("PortScan", 1), ("DoS Hulk", 1), ("DDoS", 1)]
        for label, repeat in script:
            for _ in range(repeat):
                yield self._build(label, self.attacker)

    def random_attack_record(self) -> TrafficRecord:
        return self._build(self.rng.choice(ATTACK_LABELS), self.attacker)

    # ------------------------------------------------------------ helper ----
    def _build(self, label: str, device: dict) -> TrafficRecord:
        features = generate_flow(label, self.rng)
        packets = int(features["Total Fwd Packets"] + features["Total Backward Packets"])
        protocol = "UDP" if features["Destination Port"] in (53, 123) else "TCP"
        return TrafficRecord(
            features=features,
            source=device["ip"],
            destination=GATEWAY_IP if label == "BENIGN" else f"{LOCAL_SUBNET}{self.rng.randint(2, 19)}",
            protocol=protocol,
            packets=max(1, packets),
            origin_label=label,
            metadata={"mac": device["mac"],
                      "dst_port": int(features["Destination Port"]),
                      "synthetic": True},
        )
