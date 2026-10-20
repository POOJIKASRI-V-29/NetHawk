"""Bundled DEMO traffic generator.

IMPORTANT / HONESTY NOTE
------------------------
Everything produced here is SYNTHETIC DEMO DATA.  It is *not* CIC-IDS2017 and
it is *not* captured Wi-Fi traffic.  It exists for exactly two reasons:

  1. so the whole NetHawk pipeline can be trained, tested and demonstrated on a
     laptop that does not have the 50k-flow CIC-IDS2017 CSVs, and
  2. so the "Run Security Simulation" button has controlled, non-destructive
     traffic to feed into the detector.

Any accuracy measured on this data describes the demo generator, not real-world
intrusion-detection performance.  Drop the real CIC-IDS2017 CSVs into
data/cicids2017/ and re-run scripts/train_model.py to train on real data.

Flows are generated from base quantities (duration, packet counts, byte counts,
TCP flags) and the rate/size features are then *derived* from them, exactly the
same way LiveTrafficFeatureAdapter derives them from captured packets.  That is
what keeps demo flows and live flows in the same feature space.
"""
from __future__ import annotations

import random
from typing import Any

import pandas as pd

from ..schema import FEATURE_NAMES, LABEL_COLUMN

# Raw labels deliberately use CIC-IDS2017 spellings so the label-normalisation
# layer is exercised by the demo data too.
DEMO_LABELS = [
    "BENIGN",
    "DoS Hulk",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "Bot",
    "Web Attack - Brute Force",
]

ATTACK_LABELS = [lbl for lbl in DEMO_LABELS if lbl != "BENIGN"]

_BENIGN_PORTS = [80, 443, 443, 443, 53, 22, 123, 8080, 3000, 5228]


def _jitter(rng: random.Random, value: float, pct: float = 0.25) -> float:
    """Multiplicative noise so classes overlap instead of being separable toys."""
    return max(0.0, value * (1.0 + rng.uniform(-pct, pct)))


def _base_flow(label: str, rng: random.Random) -> dict[str, Any]:
    """Sample the primitive quantities of one flow for the given label."""
    if label == "BENIGN":
        duration = _jitter(rng, rng.uniform(2e5, 9e6))
        fwd_pkts = rng.randint(4, 60)
        bwd_pkts = max(1, int(fwd_pkts * rng.uniform(0.5, 1.8)))
        fwd_mean = _jitter(rng, rng.uniform(80, 700))
        bwd_mean = _jitter(rng, rng.uniform(100, 1200))
        flags = {"FIN": rng.choice([0, 1, 1]), "SYN": 1, "RST": 0,
                 "PSH": rng.randint(0, 4), "ACK": max(1, fwd_pkts // 2),
                 "URG": 0}
        port = rng.choice(_BENIGN_PORTS)
        win = rng.choice([8192, 29200, 64240, 65535])

    elif label == "DoS Hulk":
        duration = _jitter(rng, rng.uniform(5e4, 1.2e6))
        fwd_pkts = rng.randint(120, 1200)
        bwd_pkts = rng.randint(0, max(1, fwd_pkts // 12))
        fwd_mean = _jitter(rng, rng.uniform(60, 320))
        bwd_mean = _jitter(rng, rng.uniform(0, 120))
        flags = {"FIN": 0, "SYN": rng.randint(1, 3), "RST": rng.randint(0, 2),
                 "PSH": rng.randint(20, 200), "ACK": rng.randint(50, 400),
                 "URG": 0}
        port = 80
        win = rng.choice([229, 237, 8192])

    elif label == "DDoS":
        duration = _jitter(rng, rng.uniform(3e4, 8e5))
        fwd_pkts = rng.randint(600, 6000)
        bwd_pkts = rng.randint(0, 40)
        fwd_mean = _jitter(rng, rng.uniform(40, 200))
        bwd_mean = _jitter(rng, rng.uniform(0, 60))
        flags = {"FIN": 0, "SYN": rng.randint(2, 20), "RST": rng.randint(0, 10),
                 "PSH": rng.randint(50, 600), "ACK": rng.randint(100, 1500),
                 "URG": 0}
        port = rng.choice([80, 80, 443])
        win = rng.choice([0, 229, 1024])

    elif label == "PortScan":
        duration = _jitter(rng, rng.uniform(20, 4000))     # microseconds
        fwd_pkts = rng.randint(1, 2)
        bwd_pkts = rng.randint(0, 1)
        fwd_mean = _jitter(rng, rng.uniform(0, 40))
        bwd_mean = _jitter(rng, rng.uniform(0, 30))
        flags = {"FIN": 0, "SYN": 1, "RST": rng.choice([0, 1, 1]),
                 "PSH": 0, "ACK": rng.choice([0, 0, 1]), "URG": 0}
        port = rng.choice([21, 22, 23, 25, 53, 110, 135, 139, 445, 1433,
                           3306, 3389, 5900, 8080, rng.randint(1, 65535)])
        win = rng.choice([0, 1024, 8192])

    elif label == "FTP-Patator":
        duration = _jitter(rng, rng.uniform(1e6, 6e6))
        fwd_pkts = rng.randint(8, 30)
        bwd_pkts = rng.randint(8, 30)
        fwd_mean = _jitter(rng, rng.uniform(20, 90))
        bwd_mean = _jitter(rng, rng.uniform(30, 120))
        flags = {"FIN": rng.choice([0, 1]), "SYN": 1, "RST": 0,
                 "PSH": rng.randint(4, 18), "ACK": rng.randint(8, 28),
                 "URG": 0}
        port = rng.choice([21, 21, 22])
        win = rng.choice([8192, 29200])

    elif label == "Bot":
        duration = _jitter(rng, rng.uniform(4e6, 3e7))     # long, idle-ish
        fwd_pkts = rng.randint(3, 12)
        bwd_pkts = rng.randint(2, 10)
        fwd_mean = _jitter(rng, rng.uniform(40, 260))
        bwd_mean = _jitter(rng, rng.uniform(40, 300))
        flags = {"FIN": rng.choice([0, 1]), "SYN": 1, "RST": 0,
                 "PSH": rng.randint(1, 6), "ACK": rng.randint(3, 12),
                 "URG": 0}
        port = rng.choice([8080, 443, 6667, 50000])
        win = rng.choice([8192, 64240])

    elif label == "Web Attack - Brute Force":
        duration = _jitter(rng, rng.uniform(8e5, 7e6))
        fwd_pkts = rng.randint(12, 60)
        bwd_pkts = rng.randint(8, 50)
        fwd_mean = _jitter(rng, rng.uniform(250, 900))     # POST bodies
        bwd_mean = _jitter(rng, rng.uniform(150, 700))
        flags = {"FIN": rng.choice([0, 1]), "SYN": 1, "RST": 0,
                 "PSH": rng.randint(6, 30), "ACK": rng.randint(10, 50),
                 "URG": rng.choice([0, 0, 1])}
        port = rng.choice([80, 80, 8080])
        win = rng.choice([8192, 29200, 64240])
    else:
        raise ValueError(f"Unknown demo label: {label}")

    return {
        "duration_us": max(1.0, duration),
        "fwd_pkts": fwd_pkts,
        "bwd_pkts": bwd_pkts,
        "fwd_mean": fwd_mean,
        "bwd_mean": bwd_mean,
        "flags": flags,
        "port": port,
        "win": win,
    }


def _derive(base: dict[str, Any], rng: random.Random) -> dict[str, float]:
    """Turn primitive flow quantities into the NetHawk feature vector."""
    duration_us = base["duration_us"]
    duration_s = duration_us / 1e6
    fwd_pkts, bwd_pkts = base["fwd_pkts"], base["bwd_pkts"]
    total_pkts = max(1, fwd_pkts + bwd_pkts)
    fwd_bytes = base["fwd_mean"] * fwd_pkts
    bwd_bytes = base["bwd_mean"] * bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes

    pkt_mean = total_bytes / total_pkts
    pkt_min = max(0.0, min(base["fwd_mean"], base["bwd_mean"]) * rng.uniform(0.0, 0.6))
    pkt_max = max(base["fwd_mean"], base["bwd_mean"]) * rng.uniform(1.1, 2.2)
    pkt_std = max(0.0, (pkt_max - pkt_min) / rng.uniform(2.5, 5.0))

    iat_mean = duration_us / total_pkts
    fwd_iat = duration_us / max(1, fwd_pkts)
    bwd_iat = duration_us / max(1, bwd_pkts)
    flags = base["flags"]

    return {
        "Destination Port": float(base["port"]),
        "Flow Duration": float(duration_us),
        "Total Fwd Packets": float(fwd_pkts),
        "Total Backward Packets": float(bwd_pkts),
        "Total Length of Fwd Packets": float(fwd_bytes),
        "Total Length of Bwd Packets": float(bwd_bytes),
        "Fwd Packet Length Mean": float(base["fwd_mean"]),
        "Bwd Packet Length Mean": float(base["bwd_mean"]),
        "Flow Bytes/s": float(total_bytes / duration_s) if duration_s > 0 else 0.0,
        "Flow Packets/s": float(total_pkts / duration_s) if duration_s > 0 else 0.0,
        "Flow IAT Mean": float(iat_mean),
        "Flow IAT Std": float(iat_mean * rng.uniform(0.1, 1.4)),
        "Fwd IAT Mean": float(fwd_iat),
        "Bwd IAT Mean": float(bwd_iat),
        "Min Packet Length": float(pkt_min),
        "Max Packet Length": float(pkt_max),
        "Packet Length Mean": float(pkt_mean),
        "Packet Length Std": float(pkt_std),
        "FIN Flag Count": float(flags["FIN"]),
        "SYN Flag Count": float(flags["SYN"]),
        "RST Flag Count": float(flags["RST"]),
        "PSH Flag Count": float(flags["PSH"]),
        "ACK Flag Count": float(flags["ACK"]),
        "URG Flag Count": float(flags["URG"]),
        "Down/Up Ratio": float(bwd_pkts / fwd_pkts) if fwd_pkts else 0.0,
        "Average Packet Size": float(pkt_mean),
        "Init_Win_bytes_forward": float(base["win"]),
    }


def generate_flow(label: str, rng: random.Random | None = None) -> dict[str, float]:
    """Generate one synthetic demo flow (feature dict) for the given raw label."""
    rng = rng or random.Random()
    return _derive(_base_flow(label, rng), rng)


def generate_dataset(rows_per_class: int = 1200, seed: int = 42) -> pd.DataFrame:
    """Build a balanced labelled demo dataset in the NetHawk feature schema."""
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    for label in DEMO_LABELS:
        # Benign is over-represented, as in real traffic.
        count = rows_per_class * 3 if label == "BENIGN" else rows_per_class
        for _ in range(count):
            row = generate_flow(label, rng)
            row[LABEL_COLUMN] = label
            records.append(row)
    rng.shuffle(records)
    return pd.DataFrame(records, columns=FEATURE_NAMES + [LABEL_COLUMN])
