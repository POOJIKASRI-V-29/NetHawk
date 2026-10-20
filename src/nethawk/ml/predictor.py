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
    """No model file exists yet."""


class ModelLoadError(RuntimeError):
    """The model file exists but cannot be used."""


class FeatureSchemaError(ValueError):
    """The feature record does not match the model's expected schema."""


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
        try:
            bundle = joblib.load(self.model_path)
        except Exception as exc:
            raise ModelLoadError(
                f"{self.model_path.name} is not a readable NetHawk model "
                f"({type(exc).__name__}: {exc}). Retrain it with: "
                f"python3 scripts/train_model.py"
            ) from exc

        if not isinstance(bundle, dict) or "model" not in bundle:
            raise ModelLoadError(
                f"{self.model_path.name} does not contain a NetHawk model bundle. "
                f"Retrain it with: python3 scripts/train_model.py")

        self.model = bundle["model"]
        if not hasattr(self.model, "predict"):
            raise ModelLoadError(
                f"{self.model_path.name} contains "
                f"{type(self.model).__name__}, which is not a trained classifier. "
                f"Retrain it with: python3 scripts/train_model.py")

        # Training benefits from all cores, inference does not: NetHawk
        # predicts one flow at a time, where a parallel backend is pure
        # overhead - and in a frozen build it spawns helper processes that
        # re-execute the application.  Force single-threaded inference.
        try:
            self.model.n_jobs = 1
        except Exception:
            pass

        self.classes = list(bundle.get("classes", getattr(self.model, "classes_", [])))
        self.feature_names = list(bundle.get("feature_names", FEATURE_NAMES))
        self.metadata = bundle.get("metadata", {})

        # Guard against schema drift: if the saved model was trained on a
        # different feature list than the code now uses, every prediction would
        # be made on silently mis-ordered values.  Fail loudly instead.
        if self.feature_names != FEATURE_NAMES:
            saved, expected = set(self.feature_names), set(FEATURE_NAMES)
            if saved == expected:
                reason = ("the same features in a different order - predictions "
                          "would be made on mis-ordered values")
            else:
                reason = (f"a different feature set "
                          f"(missing: {sorted(expected - saved)[:3]}, "
                          f"unexpected: {sorted(saved - expected)[:3]})")
            raise ModelLoadError(
                f"{self.model_path.name} was trained on {reason}. "
                f"Retrain it with: python3 scripts/train_model.py")

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
    def validate(self, features: dict) -> None:
        """Reject a record that is not in the model's feature schema.

        Without this, a record missing most of its features would quietly be
        padded with zeros and still produce a confident-looking label - the
        kind of failure that hides a schema change instead of surfacing it.
        """
        if not isinstance(features, dict):
            raise FeatureSchemaError(
                f"Features must be a dict keyed by feature name, got "
                f"{type(features).__name__}.")
        missing = [name for name in self.feature_names if name not in features]
        if missing:
            raise FeatureSchemaError(
                f"{len(missing)} of {len(self.feature_names)} required features are "
                f"missing (first few: {', '.join(missing[:4])}). Use one of the "
                f"adapters in nethawk.features.adapters to build the record.")

    def predict(self, features: dict) -> dict[str, Any]:
        """Classify one feature record."""
        if self.model is None:
            raise ModelNotTrainedError("Model is not loaded.")
        self.validate(features)
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
