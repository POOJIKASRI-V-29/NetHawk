"""Text report generation from the stored event history."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .. import config


def build_report(db, predictor=None) -> str:
    counts = db.event_counts()
    types = db.attack_type_counts()
    devices = db.devices()
    blocked = db.blocklist()
    events = db.recent_events(limit=25, attacks_only=True)

    metrics_note = "no metrics file found"
    if config.METRICS_PATH.exists():
        metrics = json.loads(config.METRICS_PATH.read_text())
        metrics_note = (f"{metrics['data_source']} | multiclass accuracy "
                        f"{metrics['multiclass']['accuracy']:.4f} | {metrics['caveat']}")

    lines = [
        "NETHAWK SECURITY REPORT",
        "=" * 70,
        f"Generated       : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Model           : {predictor.describe() if predictor else 'n/a'}",
        f"Training metrics: {metrics_note}",
        "",
        "SUMMARY",
        "-" * 70,
        f"Events analysed : {counts['total']}",
        f"Attacks detected: {counts['attacks']}  (HIGH {counts['high']}, MEDIUM {counts['medium']})",
        f"Avg attack risk : {counts['avg_attack_risk']}/100",
        f"Devices seen    : {len(devices)}",
        f"Blocklist (sim) : {len(blocked)} entr(y/ies)",
        "",
        "ATTACK TYPES",
        "-" * 70,
    ]
    lines += [f"  {name:<20} {count}" for name, count in types] or ["  none"]
    lines += ["", "DEVICES", "-" * 70]
    lines += [f"  {d['identifier']:<18} {d['status']:<14} packets={d['packets']:<8} "
              f"threats={d['threat_count']}" for d in devices] or ["  none"]
    lines += ["", "RECENT ATTACK EVENTS", "-" * 70]
    for e in events:
        lines.append(f"  [{e['timestamp']}] {e['source']:<15} {e['attack_type']:<14} "
                     f"conf={e['confidence']:.2f} risk={e['risk_score']:>3}/{e['risk_level']:<6} "
                     f"-> {e['response']}")
    if not events:
        lines.append("  none")
    lines += ["", "NOTE", "-" * 70,
              "All responses recorded by NetHawk are SIMULATED. The system does not",
              "block, deauthenticate or otherwise modify any real network.",
              ""]
    return "\n".join(lines)


def write_report(db, predictor=None, path: Path | None = None) -> Path:
    reports_dir = config.REPORTS_DIR
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = path or reports_dir / f"nethawk_report_{datetime.now():%Y%m%d_%H%M%S}.txt"
    path.write_text(build_report(db, predictor))
    return path
