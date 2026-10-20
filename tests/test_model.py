"""Model training, persistence and metadata honesty."""
import joblib

from nethawk.datasets.loader import load_demo
from nethawk.ml import model as ml_model
from nethawk.ml.predictor import ModelNotTrainedError, Predictor
from nethawk.schema import FEATURE_NAMES


def test_training_produces_usable_metrics():
    result = ml_model.train(load_demo(rows_per_class=120, seed=3), seed=3)
    metrics = result.metrics
    assert 0.0 <= metrics["multiclass"]["accuracy"] <= 1.0
    assert 0.0 <= metrics["binary"]["recall_attack"] <= 1.0
    assert metrics["rows_train"] > metrics["rows_test"] > 0
    assert len(metrics["top_features"]) > 0


def test_demo_training_is_flagged_as_demo():
    result = ml_model.train(load_demo(rows_per_class=60, seed=3), seed=3)
    assert result.metrics["is_demo_data"] is True
    assert result.metadata["is_demo_data"] is True
    assert "DEMO" in result.metrics["caveat"] or "demo" in result.metrics["caveat"]


def test_save_and_reload_roundtrip(tmp_path):
    result = ml_model.train(load_demo(rows_per_class=60, seed=3), seed=3)
    model_path, metrics_path = ml_model.save(
        result, tmp_path / "m.joblib", tmp_path / "m.json")
    assert model_path.exists() and metrics_path.exists()

    bundle = joblib.load(model_path)
    assert bundle["feature_names"] == FEATURE_NAMES

    predictor = Predictor(model_path, auto_train=False)
    assert predictor.is_demo_model is True
    assert "RandomForest" in predictor.describe()


def test_missing_model_raises_when_autotrain_disabled(tmp_path):
    try:
        Predictor(tmp_path / "nope.joblib", auto_train=False)
    except ModelNotTrainedError as exc:
        assert "train_model.py" in str(exc)
    else:
        raise AssertionError("expected ModelNotTrainedError")
