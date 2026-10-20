#!/usr/bin/env python3
"""Train the NetHawk Random Forest and persist it to models/.

    python scripts/train_model.py            # real CIC-IDS2017 if present, else demo data
    python scripts/train_model.py --demo     # force the bundled demo dataset
    python scripts/train_model.py --data-dir /path/to/MachineLearningCVE
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nethawk import config                                             # noqa: E402
from nethawk.datasets.loader import (                                  # noqa: E402
    SOURCE_DEMO, find_cicids_csvs, load_cicids, load_demo, load_training_data,
)
from nethawk.ml import model as ml_model                               # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the NetHawk intrusion-detection model")
    parser.add_argument("--demo", action="store_true", help="force the synthetic demo dataset")
    parser.add_argument("--data-dir", type=str, default=None,
                        help="directory holding CIC-IDS2017 CSV files")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    config.ensure_directories()

    if args.demo:
        dataset = load_demo()
    elif args.data_dir:
        dataset = load_cicids(Path(args.data_dir))
    else:
        found = find_cicids_csvs()
        print(f"[NetHawk] CIC-IDS2017 CSVs found in {config.CICIDS_DIR}: {len(found)}")
        dataset = load_training_data()

    print(f"[NetHawk] Dataset : {dataset.summary()}")
    if dataset.source == SOURCE_DEMO:
        print("[NetHawk] WARNING: training on SYNTHETIC DEMO DATA. Metrics below describe")
        print("[NetHawk]          the demo generator, NOT real intrusion detection accuracy.")
        print(f"[NetHawk]          Put the real CSVs in {config.CICIDS_DIR} and re-run to change this.")

    result = ml_model.train(dataset, test_size=args.test_size, seed=args.seed)
    model_path, metrics_path = ml_model.save(result)

    m = result.metrics
    print("\n[NetHawk] ---------------- EVALUATION ----------------")
    print(f"  data source        : {m['data_source']} ({'DEMO' if m['is_demo_data'] else 'REAL'})")
    print(f"  train / test rows  : {m['rows_train']} / {m['rows_test']}")
    print(f"  classes            : {', '.join(m['classes'])}")
    print(f"  multiclass accuracy: {m['multiclass']['accuracy']:.4f}")
    print(f"  multiclass macro-F1: {m['multiclass']['macro_f1']:.4f}")
    b = m["binary"]
    print(f"  binary  accuracy   : {b['accuracy']:.4f}")
    print(f"  attack precision   : {b['precision_attack']:.4f}")
    print(f"  attack recall      : {b['recall_attack']:.4f}")
    print("  top features       :")
    for item in m["top_features"][:6]:
        print(f"      {item['feature']:<28} {item['importance']:.4f}")
    print(f"\n  CAVEAT: {m['caveat']}")
    print(f"\n[NetHawk] Model   -> {model_path}")
    print(f"[NetHawk] Metrics -> {metrics_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
