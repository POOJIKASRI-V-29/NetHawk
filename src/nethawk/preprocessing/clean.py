"""Traffic preprocessing: column normalisation, numeric coercion, missing values.

The same cleaning code runs for CIC-IDS2017 CSVs and for the bundled demo CSV,
so the model only ever sees one consistent representation.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

from ..schema import FEATURE_NAMES, LABEL_COLUMN

# Alias map for dataset variants (CSE-CIC-IDS2018 / CICFlowMeter short names)
# pointing at NetHawk's canonical (CIC-IDS2017) feature names.
COLUMN_ALIASES: dict[str, str] = {
    "dst port": "Destination Port",
    "destination port": "Destination Port",
    "flow duration": "Flow Duration",
    "tot fwd pkts": "Total Fwd Packets",
    "total fwd packets": "Total Fwd Packets",
    "tot bwd pkts": "Total Backward Packets",
    "total backward packets": "Total Backward Packets",
    "totlen fwd pkts": "Total Length of Fwd Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "totlen bwd pkts": "Total Length of Bwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "fwd pkt len mean": "Fwd Packet Length Mean",
    "bwd pkt len mean": "Bwd Packet Length Mean",
    "flow byts/s": "Flow Bytes/s",
    "flow pkts/s": "Flow Packets/s",
    "pkt len min": "Min Packet Length",
    "pkt len max": "Max Packet Length",
    "pkt len mean": "Packet Length Mean",
    "pkt len std": "Packet Length Std",
    "fin flag cnt": "FIN Flag Count",
    "syn flag cnt": "SYN Flag Count",
    "rst flag cnt": "RST Flag Count",
    "psh flag cnt": "PSH Flag Count",
    "ack flag cnt": "ACK Flag Count",
    "urg flag cnt": "URG Flag Count",
    "pkt size avg": "Average Packet Size",
    "init fwd win byts": "Init_Win_bytes_forward",
    "init_win_bytes_forward": "Init_Win_bytes_forward",
    "label": LABEL_COLUMN,
}


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip padding/casing differences and apply the alias map."""
    renamed = {}
    for col in df.columns:
        clean = re.sub(r"\s+", " ", str(col)).strip()
        key = clean.lower()
        renamed[col] = COLUMN_ALIASES.get(key, clean)
    out = df.rename(columns=renamed)
    # Drop duplicate columns that can appear after aliasing (e.g. "Fwd Header Length.1")
    return out.loc[:, ~out.columns.duplicated()]


def coerce_numeric(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    df = df.copy()
    for col in columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def handle_invalid(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """CIC-IDS2017 contains Infinity and NaN in the rate columns; fix both."""
    df = df.copy()
    df[columns] = df[columns].replace([np.inf, -np.inf], np.nan)
    df[columns] = df[columns].fillna(0.0)
    df[columns] = df[columns].clip(lower=0.0)
    return df


def prepare_dataframe(df: pd.DataFrame, require_label: bool = True) -> pd.DataFrame:
    """Full cleaning pass -> exactly FEATURE_NAMES (+ Label) as float columns."""
    df = normalize_columns(df)

    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(
            "Dataset is missing required feature columns: "
            + ", ".join(missing[:8])
            + (" ..." if len(missing) > 8 else "")
        )
    if require_label and LABEL_COLUMN not in df.columns:
        raise ValueError(f"Dataset is missing the '{LABEL_COLUMN}' column.")

    keep = FEATURE_NAMES + ([LABEL_COLUMN] if require_label and LABEL_COLUMN in df.columns else [])
    df = df[keep]
    df = coerce_numeric(df, FEATURE_NAMES)
    df = handle_invalid(df, FEATURE_NAMES)
    if LABEL_COLUMN in df.columns:
        df = df[df[LABEL_COLUMN].notna()]
        df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(str).str.strip()
    return df.drop_duplicates().reset_index(drop=True)


def vector_from_dict(features: dict) -> list[float]:
    """Order a feature dict into the model's expected vector, filling gaps with 0."""
    vector = []
    for name in FEATURE_NAMES:
        value = features.get(name, 0.0)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.0
        if not np.isfinite(value):
            value = 0.0
        vector.append(max(0.0, value))
    return vector
