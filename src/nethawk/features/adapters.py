"""Feature adapters: one feature contract, three sources.

    DatasetFeatureAdapter      CSV row (CIC-IDS2017 or demo CSV)
    DemoTrafficFeatureAdapter  synthetic demo flow generated at runtime
    LiveTrafficFeatureAdapter  Flow assembled from Scapy-captured packets

All three implement extract_features(record) and return a dict keyed by
schema.FEATURE_NAMES, which is what the model consumes.

Honesty note: live features are computed by NetHawk's own flow assembler.
They follow the CIC-IDS2017 *definitions* but are not produced by
CICFlowMeter, so a model trained on CIC-IDS2017 and applied to live traffic
is doing cross-domain inference.  This is stated in the docs and the UI.
"""
from __future__ import annotations

import random
from typing import Any

from ..capture.flows import Flow
from ..datasets.synthetic import generate_flow
from ..preprocessing.clean import normalize_columns, vector_from_dict
from ..schema import FEATURE_NAMES


class FeatureAdapter:
    """Common interface for all feature sources."""

    name = "base"

    def extract_features(self, record: Any) -> dict[str, float]:
        raise NotImplementedError

    @staticmethod
    def as_vector(features: dict[str, float]) -> list[float]:
        return vector_from_dict(features)


class DatasetFeatureAdapter(FeatureAdapter):
    """Adapts a dataset row (dict or pandas Series) to the feature schema."""

    name = "dataset"

    def extract_features(self, record: Any) -> dict[str, float]:
        if hasattr(record, "to_dict"):
            record = record.to_dict()
        # Normalise key spelling the same way the CSV loader does.
        cleaned: dict[str, Any] = {}
        import pandas as pd
        mapped = normalize_columns(pd.DataFrame([record])).iloc[0].to_dict()
        cleaned.update(mapped)
        return {name: float(cleaned.get(name, 0.0) or 0.0) for name in FEATURE_NAMES}


class DemoTrafficFeatureAdapter(FeatureAdapter):
    """Generates / adapts controlled demo traffic."""

    name = "demo"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def extract_features(self, record: Any) -> dict[str, float]:
        """`record` may be a raw label (str) or an already-built feature dict."""
        if isinstance(record, str):
            return generate_flow(record, self.rng)
        if isinstance(record, dict) and "label" in record:
            return generate_flow(record["label"], self.rng)
        if isinstance(record, dict):
            return {name: float(record.get(name, 0.0) or 0.0) for name in FEATURE_NAMES}
        raise TypeError(f"DemoTrafficFeatureAdapter cannot handle {type(record)!r}")


class LiveTrafficFeatureAdapter(FeatureAdapter):
    """Converts an assembled live Flow into the model's feature vector."""

    name = "live"

    def extract_features(self, record: Any) -> dict[str, float]:
        if not isinstance(record, Flow):
            raise TypeError("LiveTrafficFeatureAdapter expects a Flow instance")
        s = record.statistics_dict()
        duration_s = s["duration_us"] / 1e6
        total_pkts = max(1, int(s["fwd_pkts"] + s["bwd_pkts"]))
        total_bytes = s["fwd_bytes"] + s["bwd_bytes"]
        flags = s["flags"]
        return {
            "Destination Port": s["port"],
            "Flow Duration": s["duration_us"],
            "Total Fwd Packets": float(s["fwd_pkts"]),
            "Total Backward Packets": float(s["bwd_pkts"]),
            "Total Length of Fwd Packets": s["fwd_bytes"],
            "Total Length of Bwd Packets": s["bwd_bytes"],
            "Fwd Packet Length Mean": s["fwd_mean"],
            "Bwd Packet Length Mean": s["bwd_mean"],
            "Flow Bytes/s": total_bytes / duration_s if duration_s > 0 else 0.0,
            "Flow Packets/s": total_pkts / duration_s if duration_s > 0 else 0.0,
            "Flow IAT Mean": s["iat_mean"],
            "Flow IAT Std": s["iat_std"],
            "Fwd IAT Mean": s["fwd_iat_mean"],
            "Bwd IAT Mean": s["bwd_iat_mean"],
            "Min Packet Length": s["pkt_min"],
            "Max Packet Length": s["pkt_max"],
            "Packet Length Mean": s["pkt_mean"],
            "Packet Length Std": s["pkt_std"],
            "FIN Flag Count": float(flags.get("FIN", 0)),
            "SYN Flag Count": float(flags.get("SYN", 0)),
            "RST Flag Count": float(flags.get("RST", 0)),
            "PSH Flag Count": float(flags.get("PSH", 0)),
            "ACK Flag Count": float(flags.get("ACK", 0)),
            "URG Flag Count": float(flags.get("URG", 0)),
            "Down/Up Ratio": (s["bwd_pkts"] / s["fwd_pkts"]) if s["fwd_pkts"] else 0.0,
            "Average Packet Size": total_bytes / total_pkts,
            "Init_Win_bytes_forward": s["win"],
        }


def extract_features(packet_or_record: Any) -> dict[str, float]:
    """Convenience dispatcher used by tests and scripts."""
    if isinstance(packet_or_record, Flow):
        return LiveTrafficFeatureAdapter().extract_features(packet_or_record)
    if isinstance(packet_or_record, str):
        return DemoTrafficFeatureAdapter().extract_features(packet_or_record)
    return DatasetFeatureAdapter().extract_features(packet_or_record)
