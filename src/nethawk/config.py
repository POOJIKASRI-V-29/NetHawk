"""Central configuration for NetHawk.

All paths are derived from the project root so the project can be moved or
cloned anywhere.  Every path can be overridden with an environment variable,
which keeps the app portable (macOS / Linux / Windows).
"""
from __future__ import annotations

import os
from pathlib import Path

# src/nethawk/config.py -> src/nethawk -> src -> <project root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _path_from_env(var: str, default: Path) -> Path:
    value = os.environ.get(var)
    return Path(value).expanduser().resolve() if value else default


DATA_DIR = _path_from_env("NETHAWK_DATA_DIR", PROJECT_ROOT / "data")
CICIDS_DIR = _path_from_env("NETHAWK_CICIDS_DIR", DATA_DIR / "cicids2017")
DEMO_DATA_DIR = DATA_DIR / "demo"
DEMO_DATASET_PATH = DEMO_DATA_DIR / "nethawk_demo_traffic.csv"
SAMPLE_PCAP_PATH = DEMO_DATA_DIR / "sample_traffic.pcap"

MODELS_DIR = _path_from_env("NETHAWK_MODELS_DIR", PROJECT_ROOT / "models")
MODEL_PATH = MODELS_DIR / "nethawk_rf.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

DB_DIR = _path_from_env("NETHAWK_DB_DIR", PROJECT_ROOT / "database")
DB_PATH = _path_from_env("NETHAWK_DB_PATH", DB_DIR / "nethawk.db")

LOG_DIR = PROJECT_ROOT / "logs"
LOG_PATH = LOG_DIR / "nethawk.log"

# ---------------------------------------------------------------- runtime ---
# Seconds between synthetic traffic events in demo monitoring.
DEMO_EVENT_INTERVAL = float(os.environ.get("NETHAWK_DEMO_INTERVAL", "1.5"))
# Seconds a live flow is accumulated before it is flushed to the ML pipeline.
LIVE_FLOW_TIMEOUT = float(os.environ.get("NETHAWK_FLOW_TIMEOUT", "5.0"))
# Only events at/above this risk are shown in the "Recent alerts" panel.
ALERT_MIN_RISK = int(os.environ.get("NETHAWK_ALERT_MIN_RISK", "40"))

APP_NAME = "NetHawk"
APP_TAGLINE = "AI-Powered Wi-Fi Intrusion Detection & Automated Response"
VERSION = "1.0.0-mvp"


def ensure_directories() -> None:
    """Create every directory the application writes to."""
    for directory in (DATA_DIR, CICIDS_DIR, DEMO_DATA_DIR, MODELS_DIR, DB_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)
