#!/usr/bin/env python3
"""NetHawk entry point.

    python app.py                  # dashboard, DEMO mode (works everywhere)
    sudo python app.py --mode live # dashboard, LIVE capture (falls back to DEMO)
    python app.py --headless       # terminal demo of the full pipeline, no GUI
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make src/ importable without installing the package.
SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from nethawk import config                                    # noqa: E402
from nethawk.schema import MODE_DEMO, MODE_LIVE               # noqa: E402
from nethawk.utils.logging import get_logger                  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nethawk",
        description="NetHawk - AI-powered Wi-Fi intrusion detection & automated response (MVP)")
    parser.add_argument("--mode", choices=[MODE_DEMO.lower(), MODE_LIVE.lower()],
                        default=MODE_DEMO.lower(),
                        help="start in demo (generated traffic) or live (packet capture) mode")
    parser.add_argument("--headless", action="store_true",
                        help="run the pipeline in the terminal instead of opening the GUI")
    parser.add_argument("--no-autostart", action="store_true",
                        help="open the dashboard without starting monitoring automatically")
    parser.add_argument("--simulate", action="store_true",
                        help="headless: run the security simulation immediately")
    parser.add_argument("--duration", type=float, default=12.0,
                        help="headless: seconds of monitoring before exiting")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def run_headless(mode: str, duration: float, simulate: bool) -> int:
    import time

    from nethawk.engine import NetHawkEngine

    log = get_logger(verbose=True)
    engine = NetHawkEngine(mode=mode)
    log.info("Model: %s", engine.predictor.describe())

    def on_message(message) -> None:
        if message.kind == "event":
            e = message.payload["event"]
            marker = "!!" if e["prediction"] == "ATTACK" else "  "
            log.info("%s %-15s %-14s conf=%.2f risk=%3d %-6s -> %s",
                     marker, e["source"], e["attack_type"], e["confidence"],
                     e["risk_score"], e["risk_level"], e["response"])
        elif message.kind == "notice":
            log.info("[%s] %s", message.payload["level"].upper(), message.payload["text"])

    engine.on_message = on_message
    engine.start_monitoring(mode)
    if simulate:
        time.sleep(2)
        engine.run_simulation(step_delay=0.6)
    time.sleep(duration)
    engine.stop_monitoring()

    snap = engine.snapshot()
    log.info("SUMMARY: %s events, %s threats, %s devices, avg attack risk %s/100",
             snap["events"], snap["threats"], snap["devices"], snap["avg_attack_risk"])
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config.ensure_directories()
    mode = MODE_LIVE if args.mode == MODE_LIVE.lower() else MODE_DEMO

    if args.headless:
        return run_headless(mode, args.duration, args.simulate)

    try:
        from nethawk.dashboard.app import launch
    except Exception as exc:                       # pragma: no cover - GUI env issue
        print(f"[NetHawk] Could not load the desktop dashboard: {exc}")
        print("[NetHawk] Falling back to the headless pipeline demo.")
        return run_headless(mode, args.duration, True)

    launch(mode=mode, autostart=not args.no_autostart)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
