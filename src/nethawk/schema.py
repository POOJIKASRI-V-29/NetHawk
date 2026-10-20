"""The single source of truth for NetHawk's feature schema and attack taxonomy.

FEATURE_NAMES uses CIC-IDS2017 ("MachineLearningCVE" CSV) column names, so a
model trained on the real dataset and a model trained on the bundled demo data
share exactly one feature contract.  Every feature in this list is also
computable from a live TCP/UDP flow captured with Scapy, which is what makes
the DatasetFeatureAdapter / LiveTrafficFeatureAdapter / DemoTrafficFeatureAdapter
trio able to feed the same model.
"""
from __future__ import annotations

FEATURE_NAMES: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Init_Win_bytes_forward",
]

LABEL_COLUMN = "Label"
BINARY_NORMAL = "NORMAL"
BINARY_ATTACK = "ATTACK"

# ------------------------------------------------------------- categories ---
# Canonical categories NetHawk reports.  Raw dataset labels are normalised into
# these by src/nethawk/detection/classifier.py.
CATEGORY_NORMAL = "Normal"
CATEGORY_DOS = "DoS"
CATEGORY_DDOS = "DDoS"
CATEGORY_PORT_SCAN = "Port Scan"
CATEGORY_BRUTE_FORCE = "Brute Force"
CATEGORY_BOTNET = "Botnet"
CATEGORY_WEB_ATTACK = "Web Attack"
CATEGORY_OTHER = "Other Suspicious"

ATTACK_CATEGORIES: list[str] = [
    CATEGORY_NORMAL,
    CATEGORY_DOS,
    CATEGORY_DDOS,
    CATEGORY_PORT_SCAN,
    CATEGORY_BRUTE_FORCE,
    CATEGORY_BOTNET,
    CATEGORY_WEB_ATTACK,
    CATEGORY_OTHER,
]

# Severity weight per category (0-100).  Used by the risk scorer; documented in
# docs/VIVA.md so the number can be explained, not hand-waved.
CATEGORY_SEVERITY: dict[str, int] = {
    CATEGORY_NORMAL: 0,
    CATEGORY_OTHER: 45,
    CATEGORY_PORT_SCAN: 55,
    CATEGORY_WEB_ATTACK: 70,
    CATEGORY_BRUTE_FORCE: 70,
    CATEGORY_BOTNET: 80,
    CATEGORY_DOS: 85,
    CATEGORY_DDOS: 95,
}

# Short human explanation per category, shown in the dashboard detail panel.
CATEGORY_DESCRIPTION: dict[str, str] = {
    CATEGORY_NORMAL: "Traffic matches ordinary client behaviour.",
    CATEGORY_DOS: "High-rate one-to-one traffic consistent with a denial-of-service flood.",
    CATEGORY_DDOS: "Very high-rate flood behaviour consistent with a distributed denial-of-service.",
    CATEGORY_PORT_SCAN: "Many short, tiny SYN flows to different ports - reconnaissance pattern.",
    CATEGORY_BRUTE_FORCE: "Repeated short authentication-sized flows to a login service.",
    CATEGORY_BOTNET: "Low-volume periodic flows resembling command-and-control beaconing.",
    CATEGORY_WEB_ATTACK: "Abnormal HTTP request pattern (injection / brute force against a web app).",
    CATEGORY_OTHER: "Anomalous traffic that does not match a known category cleanly.",
}

MODE_DEMO = "DEMO"
MODE_LIVE = "LIVE"
# Replay reads frames from a .pcap file through the LIVE packet path.
MODE_REPLAY = "REPLAY"

RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
