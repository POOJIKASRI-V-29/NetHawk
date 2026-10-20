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


# ------------------------------------------------ reproducibility record ---
def test_training_is_reproducible_for_a_fixed_seed():
    dataset = load_demo(rows_per_class=100, seed=3)
    first = ml_model.train(dataset, seed=42)
    second = ml_model.train(dataset, seed=42)
    assert (first.metrics["multiclass"]["accuracy"]
            == second.metrics["multiclass"]["accuracy"])
    assert (first.metrics["multiclass"]["confusion_matrix"]
            == second.metrics["multiclass"]["confusion_matrix"])


def test_metrics_record_everything_needed_to_repeat_the_run():
    result = ml_model.train(load_demo(rows_per_class=60, seed=3), seed=11)
    rep = result.metrics["reproducibility"]
    assert rep["random_seed"] == 11
    assert rep["test_size"] == 0.25
    assert "stratified" in rep["split"]
    assert len(rep["dataset_fingerprint_sha256"]) == 32
    assert "scripts/train_model.py" in rep["command"]
    assert rep["feature_count"] == len(FEATURE_NAMES)
    for key in ("python", "scikit-learn", "pandas", "numpy"):
        assert rep["library_versions"][key]
    assert rep["model_params"]["n_estimators"] == 200
    assert result.metadata["random_seed"] == 11
    assert result.metadata["dataset_fingerprint_sha256"] == rep["dataset_fingerprint_sha256"]


def test_predictions_survive_a_save_reload_cycle(tmp_path):
    from nethawk.features.adapters import DatasetFeatureAdapter
    from nethawk.detection.classifier import normalize_label

    dataset = load_demo(rows_per_class=80, seed=3)
    result = ml_model.train(dataset, seed=5)
    model_path, _ = ml_model.save(result, tmp_path / "m.joblib", tmp_path / "m.json")
    reloaded = Predictor(model_path, auto_train=False)

    adapter = DatasetFeatureAdapter()
    rows = dataset.frame.head(120)
    direct = [normalize_label(v) for v in
              result.model.predict(rows[FEATURE_NAMES].astype(float))]
    through_predictor = [reloaded.predict(adapter.extract_features(row))["attack_type"]
                         for _, row in rows.iterrows()]
    assert direct == through_predictor
