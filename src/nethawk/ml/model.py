"""Random Forest training, evaluation and persistence.

Design decisions
----------------
* One multiclass Random Forest is trained on the *canonical* attack categories
  (raw dataset labels are normalised first by detection/classifier.py).  The
  binary NORMAL/ATTACK answer is derived from the category, so the two outputs
  can never disagree.
* The saved artifact carries metadata recording whether it was trained on real
  CIC-IDS2017 data or on the bundled synthetic demo data.  The dashboard shows
  that flag, so a demo model can never be mistaken for a real-data model.
"""
from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from .. import config
from ..datasets.loader import SOURCE_DEMO, LoadedDataset
from ..detection.classifier import normalize_label, to_binary
from ..schema import BINARY_ATTACK, FEATURE_NAMES, LABEL_COLUMN

MODEL_FORMAT_VERSION = 2


@dataclass
class TrainingResult:
    model: RandomForestClassifier
    metrics: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


def build_model(seed: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=seed,
        class_weight="balanced_subsample",
    )


def train(dataset: LoadedDataset, test_size: float = 0.25,
          seed: int = 42) -> TrainingResult:
    frame = dataset.frame
    X = frame[FEATURE_NAMES].astype(float)
    y_raw = frame[LABEL_COLUMN]
    y = y_raw.map(normalize_label)

    # Classes with too few samples cannot be stratified or learned reliably.
    counts = y.value_counts()
    keep = counts[counts >= 10].index
    dropped = sorted(set(counts.index) - set(keep))
    mask = y.isin(keep)
    X, y = X[mask], y[mask]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y)

    model = build_model(seed)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    bin_true = np.array([to_binary(v) for v in y_test])
    bin_pred = np.array([to_binary(v) for v in y_pred])

    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda kv: kv[1], reverse=True)

    metrics: dict[str, Any] = {
        "data_source": dataset.source,
        "is_demo_data": dataset.source == SOURCE_DEMO,
        "files": dataset.files,
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "rows_total": int(len(frame)),
        "rows_train": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "classes": sorted(model.classes_.tolist()),
        "dropped_rare_classes": dropped,
        "multiclass": {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
            "report": classification_report(y_test, y_pred, zero_division=0, output_dict=True),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "confusion_labels": sorted(set(y_test) | set(y_pred)),
        },
        "binary": {
            "accuracy": float(accuracy_score(bin_true, bin_pred)),
            "precision_attack": float(precision_score(
                bin_true, bin_pred, pos_label=BINARY_ATTACK, zero_division=0)),
            "recall_attack": float(recall_score(
                bin_true, bin_pred, pos_label=BINARY_ATTACK, zero_division=0)),
            "f1_attack": float(f1_score(
                bin_true, bin_pred, pos_label=BINARY_ATTACK, zero_division=0)),
        },
        "top_features": [{"feature": f, "importance": float(i)} for f, i in importances[:12]],
        "caveat": (
            "Metrics measured on synthetic DEMO data - they describe the demo "
            "generator, not real-world intrusion detection performance."
            if dataset.source == SOURCE_DEMO else
            "Metrics measured on a held-out split of the loaded CIC-IDS2017 CSV files."
        ),
    }

    metadata = {
        "format_version": MODEL_FORMAT_VERSION,
        "data_source": dataset.source,
        "is_demo_data": dataset.source == SOURCE_DEMO,
        "trained_at": metrics["trained_at"],
        "sklearn_python": platform.python_version(),
        "rows_total": metrics["rows_total"],
        "accuracy": metrics["multiclass"]["accuracy"],
    }
    return TrainingResult(model=model, metrics=metrics, metadata=metadata)


def save(result: TrainingResult, model_path: Path | None = None,
         metrics_path: Path | None = None) -> tuple[Path, Path]:
    model_path = Path(model_path) if model_path else config.MODEL_PATH
    metrics_path = Path(metrics_path) if metrics_path else config.METRICS_PATH
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": result.model,
            "feature_names": FEATURE_NAMES,
            "classes": result.model.classes_.tolist(),
            "metadata": result.metadata,
        },
        model_path,
    )
    metrics_path.write_text(json.dumps(result.metrics, indent=2))
    return model_path, metrics_path


def train_and_save(prefer_real: bool = True, seed: int = 42) -> TrainingResult:
    from ..datasets.loader import load_training_data

    dataset = load_training_data(prefer_real=prefer_real)
    result = train(dataset, seed=seed)
    save(result)
    return result
