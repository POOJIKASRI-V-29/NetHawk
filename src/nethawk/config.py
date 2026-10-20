"""Central configuration for NetHawk.

Paths are derived from the project root, so the project can be moved or cloned
anywhere, and every path can be overridden with an environment variable.

Two layouts are supported:

* **running from source** (the normal case) - everything lives under the
  project directory.
* **running from a PyInstaller bundle** - the bundle is read-only, so
  generated files (database, trained model, logs, demo data) go to a
  per-user application-support directory instead, and read-only resources
  shipped inside the bundle are copied there on first run.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

APP_NAME = "NetHawk"
APP_TAGLINE = "AI-Powered Wi-Fi Intrusion Detection & Automated Response"
VERSION = "1.0.0-mvp"

# True when running inside a PyInstaller bundle.
FROZEN = bool(getattr(sys, "frozen", False))

if FROZEN:
    # Read-only resources unpacked by PyInstaller.
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    PROJECT_ROOT = BUNDLE_DIR
else:
    # src/nethawk/config.py -> src/nethawk -> src -> <project root>
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    BUNDLE_DIR = PROJECT_ROOT


def _user_data_root() -> Path:
    """Per-user writable location, used only when running from a bundle."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME


# Everything NetHawk writes goes under this root.
WRITABLE_ROOT = _user_data_root() if FROZEN else PROJECT_ROOT


def _path_from_env(var: str, default: Path) -> Path:
    value = os.environ.get(var)
    return Path(value).expanduser().resolve() if value else default


DATA_DIR = _path_from_env("NETHAWK_DATA_DIR", WRITABLE_ROOT / "data")
CICIDS_DIR = _path_from_env("NETHAWK_CICIDS_DIR", DATA_DIR / "cicids2017")
DEMO_DATA_DIR = DATA_DIR / "demo"
DEMO_DATASET_PATH = DEMO_DATA_DIR / "nethawk_demo_traffic.csv"
SAMPLE_PCAP_PATH = DEMO_DATA_DIR / "sample_traffic.pcap"

MODELS_DIR = _path_from_env("NETHAWK_MODELS_DIR", WRITABLE_ROOT / "models")
MODEL_PATH = MODELS_DIR / "nethawk_rf.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

DB_DIR = _path_from_env("NETHAWK_DB_DIR", WRITABLE_ROOT / "database")
DB_PATH = _path_from_env("NETHAWK_DB_PATH", DB_DIR / "nethawk.db")

LOG_DIR = WRITABLE_ROOT / "logs"
LOG_PATH = LOG_DIR / "nethawk.log"

REPORTS_DIR = WRITABLE_ROOT / "reports"

# ---------------------------------------------------------------- runtime ---
# Seconds between synthetic traffic events in demo monitoring.
DEMO_EVENT_INTERVAL = float(os.environ.get("NETHAWK_DEMO_INTERVAL", "1.5"))
# Seconds a live flow is accumulated before it is flushed to the ML pipeline.
LIVE_FLOW_TIMEOUT = float(os.environ.get("NETHAWK_FLOW_TIMEOUT", "5.0"))
# Only events at/above this risk are shown in the "Recent alerts" panel.
ALERT_MIN_RISK = int(os.environ.get("NETHAWK_ALERT_MIN_RISK", "40"))

# Resources a bundle may ship read-only, copied to the writable tree on first
# run: (path inside the bundle, destination).
_SEEDED_RESOURCES = (
    ("models/nethawk_rf.joblib", MODEL_PATH),
    ("models/metrics.json", METRICS_PATH),
    ("data/demo/nethawk_demo_traffic.csv", DEMO_DATASET_PATH),
    ("data/demo/sample_traffic.pcap", SAMPLE_PCAP_PATH),
)


def seed_from_bundle() -> list[str]:
    """Copy read-only bundled resources into the writable tree on first run."""
    if not FROZEN:
        return []
    copied = []
    for relative, destination in _SEEDED_RESOURCES:
        source = BUNDLE_DIR / relative
        if source.exists() and not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied.append(destination.name)
    return copied


def ensure_directories() -> None:
    """Create every directory the application writes to."""
    for directory in (DATA_DIR, CICIDS_DIR, DEMO_DATA_DIR, MODELS_DIR,
                      DB_DIR, LOG_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
    seed_from_bundle()


def describe_paths() -> str:
    """Human-readable path summary, used by --paths and the diagnostics."""
    mode = "PyInstaller bundle" if FROZEN else "source checkout"
    return "\n".join([
        f"run mode     : {mode}",
        f"resources    : {BUNDLE_DIR}",
        f"writable root: {WRITABLE_ROOT}",
        f"database     : {DB_PATH}",
        f"model        : {MODEL_PATH}",
        f"demo data    : {DEMO_DATA_DIR}",
        f"logs         : {LOG_PATH}",
        f"reports      : {REPORTS_DIR}",
    ])
