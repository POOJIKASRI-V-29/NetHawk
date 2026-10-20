#!/usr/bin/env python3
"""Run the full NetHawk pipeline in the terminal - no GUI required.

    python scripts/run_demo.py             # background traffic + attack simulation
    python scripts/run_demo.py --duration 20
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nethawk.engine import NetHawkEngine                          # noqa: E402
from nethawk.schema import MODE_DEMO                              # noqa: E402
from nethawk.utils.report import build_report                     # noqa: E402

BAR = "=" * 96


def main() -> int:
    parser = argparse.ArgumentParser(description="NetHawk end-to-end demo (terminal)")
    parser.add_argument("--duration", type=float, default=14.0)
    parser.add_argument("--step-delay", type=float, default=0.7)
    parser.add_argument("--fresh", action="store_true", help="clear stored data first")
    args = parser.parse_args()

    engine = NetHawkEngine(mode=MODE_DEMO)
    if args.fresh:
        engine.clear_data()

    print(BAR)
    print("NETHAWK - end-to-end pipeline demonstration (DEMO MODE, no real traffic)")
    print(f"Model: {engine.predictor.describe()}")
    print(BAR)
    header = (f"{'TIME':<9}{'SOURCE':<16}{'PREDICTION':<11}{'ATTACK TYPE':<14}"
              f"{'CONF':<7}{'RISK':<6}{'LEVEL':<8}RESPONSE")
    print(header)
    print("-" * 96)

    def on_message(message) -> None:
        if message.kind != "event":
            return
        e = message.payload["event"]
        print(f"{e['timestamp'][-8:]:<9}{str(e['source']):<16}{e['prediction']:<11}"
              f"{e['attack_type']:<14}{e['confidence']:<7.2f}{e['risk_score']:<6}"
              f"{e['risk_level']:<8}{e['response']}")

    engine.on_message = on_message
    engine.start_monitoring(MODE_DEMO)
    time.sleep(3)
    print("-" * 96)
    print(">>> RUN SECURITY SIMULATION (controlled local traffic - nothing is transmitted)")
    print("-" * 96)
    engine.run_simulation(step_delay=args.step_delay)
    time.sleep(args.duration)
    engine.stop_monitoring()

    print("\n" + BAR)
    print(build_report(engine.db, engine.predictor))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
