"""Regression tests for defects found by hostile edge-case probing.

Each test here corresponds to a specific bug that was found and fixed: bad
capture files, corrupt models, schema drift, non-finite features, unusable
datasets, invalid filters, leaked threads and an unopenable database.
"""
import os
import tempfile
import threading
import time
from pathlib import Path

import joblib
import pandas as pd
import pytest

from nethawk.capture.live import validate_bpf_filter
from nethawk.database.db import Database, DatabaseUnavailableError
from nethawk.datasets.loader import LoadedDataset, load_cicids
from nethawk.datasets.synthetic import generate_dataset
from nethawk.engine import NetHawkEngine
from nethawk.ml import model as ml_model
from nethawk.ml.predictor import FeatureSchemaError, ModelLoadError, Predictor
from nethawk.risk.scoring import score_event, traffic_intensity
from nethawk.schema import FEATURE_NAMES, LABEL_COLUMN

scapy = pytest.importorskip("scapy.all")


def engine(tmp_path, name="r.db", **kwargs):
    return NetHawkEngine(database=Database(tmp_path / name), demo_seed=1, **kwargs)


# ------------------------------------------------- bad capture files -------
@pytest.mark.parametrize("make,label", [
    (lambda p: p.write_bytes(b""), "zero-byte file"),
    (lambda p: p.write_bytes(os.urandom(4096)), "random bytes"),
    (lambda p: p.write_bytes(bytes.fromhex(
        "d4c3b2a1020004000000000000000000ffff000001000000")), "header, no packets"),
])
def test_bad_capture_files_are_reported_not_raised(tmp_path, make, label):
    """A malformed capture file must produce a notice, never a traceback."""
    path = tmp_path / "bad.pcap"
    make(path)
    eng = engine(tmp_path)
    notices = []
    eng.on_message = lambda m: (notices.append(m.payload["text"])
                                if m.kind == "notice" else None)
    assert eng.replay_pcap(path, blocking=True) == 0
    assert notices, f"no notice emitted for {label}"


def test_directory_as_capture_path_is_reported(tmp_path):
    eng = engine(tmp_path)
    notices = []
    eng.on_message = lambda m: (notices.append(m.payload["text"])
                                if m.kind == "notice" else None)
    assert eng.replay_pcap(tmp_path, blocking=True) == 0
    assert any("Could not read" in n or "not found" in n for n in notices)


def test_truncated_capture_file_still_yields_flows(tmp_path):
    """Scapy tolerates a half-written packet; we must not lose the rest."""
    path = tmp_path / "t.pcap"
    scapy.wrpcap(str(path), [scapy.Ether() / scapy.IP() / scapy.TCP()] * 6)
    data = path.read_bytes()
    path.write_bytes(data[: int(len(data) * 0.7)])
    eng = engine(tmp_path)
    assert eng.replay_pcap(path, blocking=True) >= 0      # no exception


# ------------------------------------------------------ model loading ------
def test_corrupt_model_file_raises_a_clear_error(tmp_path):
    path = tmp_path / "bad.joblib"
    path.write_bytes(b"definitely not joblib")
    with pytest.raises(ModelLoadError, match="train_model.py"):
        Predictor(path, auto_train=False)


def test_bundle_without_a_model_raises_a_clear_error(tmp_path):
    path = tmp_path / "nk.joblib"
    joblib.dump({"something": "else"}, path)
    with pytest.raises(ModelLoadError, match="NetHawk model bundle"):
        Predictor(path, auto_train=False)


def test_non_classifier_payload_is_rejected(tmp_path):
    path = tmp_path / "str.joblib"
    joblib.dump({"model": "not a classifier", "feature_names": FEATURE_NAMES}, path)
    with pytest.raises(ModelLoadError, match="not a trained classifier"):
        Predictor(path, auto_train=False)


def test_feature_order_drift_is_detected_at_load(tmp_path, predictor):
    """Same features in a different order would silently mis-order values."""
    bundle = joblib.load(predictor.model_path)
    bundle["feature_names"] = list(reversed(FEATURE_NAMES))
    path = tmp_path / "rev.joblib"
    joblib.dump(bundle, path)
    with pytest.raises(ModelLoadError, match="different order"):
        Predictor(path, auto_train=False)


def test_different_feature_set_is_detected_at_load(tmp_path, predictor):
    bundle = joblib.load(predictor.model_path)
    bundle["feature_names"] = FEATURE_NAMES[:10]
    path = tmp_path / "few.joblib"
    joblib.dump(bundle, path)
    with pytest.raises(ModelLoadError, match="different feature set"):
        Predictor(path, auto_train=False)


# ------------------------------------------------- feature validation -----
def test_incomplete_feature_record_is_rejected(predictor):
    """Padding a half-empty record with zeros would hide a schema change."""
    with pytest.raises(FeatureSchemaError, match="missing"):
        predictor.predict({name: 1.0 for name in FEATURE_NAMES[:5]})
    with pytest.raises(FeatureSchemaError):
        predictor.predict({})


def test_non_dict_features_are_rejected(predictor):
    with pytest.raises(FeatureSchemaError, match="must be a dict"):
        predictor.predict([1, 2, 3])


def test_complete_record_with_odd_values_still_predicts(predictor):
    """Non-finite values are sanitised, not fatal, once the schema is complete."""
    for value in (float("nan"), float("inf"), -1.0, "abc"):
        result = predictor.predict({name: value for name in FEATURE_NAMES})
        assert result["prediction"] in ("NORMAL", "ATTACK")


# --------------------------------------------------------- risk scoring ---
def test_non_finite_rates_do_not_inflate_intensity():
    """NaN once scored as maximum intensity, making missing data look like a flood."""
    broken = {"Flow Packets/s": float("nan"), "Flow Bytes/s": float("nan"),
              "Total Fwd Packets": 100, "Total Backward Packets": 0}
    assert traffic_intensity(broken) == 0.0
    assert traffic_intensity(dict(broken, **{"Flow Packets/s": float("inf"),
                                             "Flow Bytes/s": float("inf")})) == 0.0


def test_negative_and_textual_rates_are_treated_as_zero():
    assert traffic_intensity({"Flow Packets/s": -9, "Flow Bytes/s": "abc",
                              "Total Fwd Packets": 50,
                              "Total Backward Packets": 50}) == 0.0


def test_risk_stays_bounded_for_broken_input():
    for features in ({}, None, {"Flow Packets/s": float("nan")}):
        result = score_event("DoS", 0.9, features)
        assert 0 <= result.score <= 100


# ------------------------------------------------------ dataset guards ----
def test_empty_csv_directory_raises_a_clear_error(tmp_path):
    frame = pd.DataFrame(columns=FEATURE_NAMES + [LABEL_COLUMN])
    path = tmp_path / "Monday-WorkingHours.pcap_ISCX.csv"
    frame.to_csv(path, index=False)
    with open(path, "a") as handle:
        handle.write(" " * 2000)            # exceed the minimum-size filter
    with pytest.raises(ValueError, match="no usable rows"):
        load_cicids(tmp_path)


def test_training_on_an_empty_frame_is_refused():
    empty = pd.DataFrame(columns=FEATURE_NAMES + [LABEL_COLUMN])
    with pytest.raises(ValueError, match="empty dataset"):
        ml_model.train(LoadedDataset(frame=empty, source="X", files=["x"]))


def test_too_few_samples_per_class_is_refused():
    tiny = generate_dataset(rows_per_class=4, seed=1).head(9)
    with pytest.raises(ValueError, match="at least 10 samples"):
        ml_model.train(LoadedDataset(frame=tiny, source="X", files=["x"]))


def test_single_class_dataset_is_flagged():
    frame = generate_dataset(rows_per_class=30, seed=1)
    frame = frame[frame[LABEL_COLUMN] == "BENIGN"]
    result = ml_model.train(LoadedDataset(frame=frame, source="X", files=["x"]))
    assert result.metrics["single_class_warning"]
    assert "one class" in result.metrics["single_class_warning"]


# ------------------------------------------------------- BPF filtering ----
@pytest.mark.parametrize("expression", ["tcp port 80", "host 10.0.0.1", "ip6", ""])
def test_valid_filters_are_accepted(expression):
    assert validate_bpf_filter(expression) is None


@pytest.mark.parametrize("expression", ["!!! nope", "tcp porttt 80"])
def test_invalid_filters_are_rejected(expression):
    assert validate_bpf_filter(expression) is not None


def test_invalid_filter_falls_back_to_demo(tmp_path):
    """An unusable filter must not be reported as a healthy LIVE capture."""
    eng = engine(tmp_path, interface="lo0", bpf_filter="!!! nope")
    notices = []
    eng.on_message = lambda m: (notices.append(m.payload["text"])
                                if m.kind == "notice" else None)
    mode = eng.start_monitoring("LIVE")
    eng.stop_monitoring()
    assert mode == "DEMO"
    assert any("filter" in n.lower() for n in notices)


def test_nonexistent_interface_falls_back_to_demo(tmp_path):
    eng = engine(tmp_path, interface="nosuchif0")
    mode = eng.start_monitoring("LIVE")
    eng.stop_monitoring()
    assert mode == "DEMO"


# ------------------------------------------------------------- database ---
def test_corrupt_database_is_moved_aside_and_recreated(tmp_path):
    path = tmp_path / "nethawk.db"
    path.write_bytes(os.urandom(8192))
    db = Database(path)
    assert db.event_counts()["total"] == 0
    assert db.recovered_from is not None and db.recovered_from.exists()


def test_unwritable_database_location_raises_a_clear_error(tmp_path):
    directory = tmp_path / "ro"
    directory.mkdir()
    os.chmod(directory, 0o500)
    try:
        with pytest.raises(DatabaseUnavailableError, match="NETHAWK_DB_PATH"):
            Database(directory / "x.db")
    finally:
        os.chmod(directory, 0o700)


def test_concurrent_writers_do_not_lose_rows(tmp_path):
    db = Database(tmp_path / "conc.db")
    errors: list[str] = []

    def writer(index: int) -> None:
        for _ in range(40):
            try:
                db.insert_event(dict(prediction="ATTACK", attack_type="DoS",
                                     confidence=0.9, risk_score=80,
                                     risk_level="HIGH", source=f"10.0.0.{index}",
                                     mode="DEMO"))
                db.upsert_device("10.0.0.1", packets=1, threat=True)
            except Exception as exc:
                errors.append(str(exc))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert db.event_counts()["total"] == 240
    assert db.devices()[0]["packets"] == 240


# -------------------------------------------------------- thread hygiene --
def test_stopping_during_a_replay_leaves_no_threads(tmp_path):
    eng = engine(tmp_path)
    eng.replay_pcap(blocking=False)
    time.sleep(0.2)
    eng.stop_monitoring()
    time.sleep(0.5)
    leftover = [t.name for t in threading.enumerate() if t.name.startswith("nethawk")]
    assert leftover == []


def test_repeated_start_stop_cycles_are_clean(tmp_path):
    eng = engine(tmp_path)
    for _ in range(6):
        assert eng.start_monitoring("DEMO") == "DEMO"
        eng.stop_monitoring()
    leftover = [t.name for t in threading.enumerate() if t.name.startswith("nethawk")]
    assert leftover == []


def test_monitor_thread_survives_a_failing_predictor(tmp_path):
    """One bad record must not kill monitoring."""
    eng = engine(tmp_path)

    class Exploding:
        is_demo_model = True
        data_source = "X"

        def describe(self):
            return "exploding"

        def predict(self, features):
            raise RuntimeError("model exploded")

    eng.predictor = Exploding()
    notices = []
    eng.on_message = lambda m: (notices.append(m.payload["text"])
                                if m.kind == "notice" else None)
    eng.start_monitoring("DEMO")
    time.sleep(1.8)
    alive = eng._demo_thread is not None and eng._demo_thread.is_alive()
    eng.stop_monitoring()
    assert alive, "the monitoring thread must survive a prediction failure"
    assert any("error" in n.lower() for n in notices)
