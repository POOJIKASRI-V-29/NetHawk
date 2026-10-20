"""Model loading and inference.

Predictor.predict() takes a feature dict (from any of the three adapters) and
returns the structured detection result the rest of NetHawk consumes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from .. import config
from ..detection.classifier import normalize_label, to_binary
from ..preprocessing.clean import vector_from_dict
from ..schema import FEATURE_NAMES


class ModelNotTrainedError(RuntimeError):
    pass


class Predictor:
    """Wraps the persisted Random Forest."""

    def __init__(self, model_path: Path | None = None, auto_train: bool = True) -> None:
        self.model_path = Path(model_path) if model_path else config.MODEL_PATH
        self.model = None
        self.classes: list[str] = []
        self.metadata: dict[str, Any] = {}
        self.feature_names: list[str] = FEATURE_NAMES
        self.load(auto_train=auto_train)

    # ------------------------------------------------------------ loading ---
    def load(self, auto_train: bool = True) -> None:
        if not self.model_path.exists():
            if not auto_train:
                raise ModelNotTrainedError(
                    f"No model at {self.model_path}. Run: python scripts/train_model.py")
            from .model import train_and_save  # local import avoids a cycle
            train_and_save()
        bundle = joblib.load(self.model_path)
        self.model = bundle["model"]
        self.classes = list(bundle.get("classes", getattr(self.model, "classes_", [])))
        self.feature_names = bundle.get("feature_names", FEATURE_NAMES)
        self.metadata = bundle.get("metadata", {})

    # --------------------------------------------------------- properties ---
    @property
    def is_demo_model(self) -> bool:
        return bool(self.metadata.get("is_demo_data", True))

    @property
    def data_source(self) -> str:
        return str(self.metadata.get("data_source", "UNKNOWN"))

    def describe(self) -> str:
        tag = "DEMO DATA" if self.is_demo_model else "REAL DATASET"
        return f"RandomForest | trained on {self.data_source} ({tag})"

    # ---------------------------------------------------------- inference ---
    def predict(self, features: dict) -> dict[str, Any]:
        """Classify one feature record."""
        if self.model is None:
            raise ModelNotTrainedError("Model is not loaded.")
        vector = pd.DataFrame([vector_from_dict(features)], columns=self.feature_names)
        category = normalize_label(self.model.predict(vector)[0])

        probabilities: dict[str, float] = {}
        confidence = 1.0
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(vector)[0]
            probabilities = {normalize_label(c): float(p)
                             for c, p in zip(self.model.classes_, proba)}
            confidence = float(max(proba))

        return {
            "prediction": to_binary(category),
            "attack_type": category,
            "confidence": round(confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in
                              sorted(probabilities.items(), key=lambda kv: -kv[1])},
        }

    def predict_batch(self, records: list[dict]) -> list[dict[str, Any]]:
        return [self.predict(r) for r in records]
