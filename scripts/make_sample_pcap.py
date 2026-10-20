#!/usr/bin/env python3
"""Build the bundled sample capture file used by NetHawk's replay mode.

    python3 scripts/make_sample_pcap.py

Packets are crafted in memory and written straight to disk - nothing is
transmitted and no privileges are needed.  The builder itself lives in
src/nethawk/capture/sample.py so the app can regenerate the file on demand.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nethawk import config                                  # noqa: E402
from nethawk.capture.sample import write_sample_pcap        # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Create NetHawk's sample .pcap (offline)")
    parser.add_argument("--out", default=None)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    config.ensure_directories()
    path, count = write_sample_pcap(args.out, args.seed)
    print(f"[NetHawk] Wrote {count} crafted packets to {path}")
    print("[NetHawk] Nothing was transmitted - the packets were written straight to disk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
