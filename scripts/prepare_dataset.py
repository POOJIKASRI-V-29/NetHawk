#!/usr/bin/env python3
"""Inspect / prepare datasets for NetHawk.

    python scripts/prepare_dataset.py            # report what is available
    python scripts/prepare_dataset.py --make-demo --rows 1500
    python scripts/prepare_dataset.py --export-clean data/clean.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nethawk import config                                              # noqa: E402
from nethawk.datasets.loader import find_cicids_csvs, load_cicids, load_demo  # noqa: E402
from nethawk.datasets.synthetic import generate_dataset                 # noqa: E402
from nethawk.detection.classifier import normalize_label                # noqa: E402
from nethawk.schema import FEATURE_NAMES, LABEL_COLUMN                  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare NetHawk training data")
    parser.add_argument("--make-demo", action="store_true",
                        help="(re)generate the bundled synthetic demo dataset")
    parser.add_argument("--rows", type=int, default=1200, help="demo rows per attack class")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--export-clean", type=str, default=None,
                        help="write the cleaned dataset to this CSV path")
    args = parser.parse_args()

    config.ensure_directories()
    print(f"[NetHawk] Feature schema : {len(FEATURE_NAMES)} features (CIC-IDS2017 names)")
    print(f"[NetHawk] Dataset dir    : {config.CICIDS_DIR}")

    if args.make_demo:
        frame = generate_dataset(rows_per_class=args.rows, seed=args.seed)
        config.DEMO_DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        frame.to_csv(config.DEMO_DATASET_PATH, index=False)
        print(f"[NetHawk] Demo dataset regenerated: {config.DEMO_DATASET_PATH} ({len(frame)} rows)")

    csvs = find_cicids_csvs()
    if csvs:
        print(f"[NetHawk] Found {len(csvs)} CIC-IDS2017 CSV file(s):")
        for path in csvs:
            print(f"    - {path.name}  ({path.stat().st_size / 1e6:.1f} MB)")
        try:
            dataset = load_cicids()
        except ValueError as exc:
            print(f"[NetHawk] ERROR: those CSVs are not usable: {exc}")
            return 1
        print(f"[NetHawk] Cleaned real dataset: {len(dataset.frame)} rows")
    else:
        print("[NetHawk] No CIC-IDS2017 CSVs found - see data/README.md for the download steps.")
        dataset = load_demo(rows_per_class=args.rows, seed=args.seed)
        print(f"[NetHawk] Using DEMO dataset: {len(dataset.frame)} rows (SYNTHETIC)")

    counts = dataset.frame[LABEL_COLUMN].value_counts()
    print("\n[NetHawk] Raw label -> NetHawk category")
    for raw, count in counts.items():
        print(f"    {str(raw)[:34]:<36} -> {normalize_label(raw):<18} {count}")

    if args.export_clean:
        out = Path(args.export_clean)
        out.parent.mkdir(parents=True, exist_ok=True)
        dataset.frame.to_csv(out, index=False)
        print(f"\n[NetHawk] Cleaned dataset written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
