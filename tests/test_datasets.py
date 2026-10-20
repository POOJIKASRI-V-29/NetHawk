"""Dataset generation, cleaning and the CIC-IDS2017 loader contract."""
import numpy as np
import pandas as pd
import pytest

from nethawk.capture.demo import DemoTrafficGenerator
from nethawk.datasets.loader import SOURCE_CICIDS, load_cicids, load_demo
from nethawk.datasets.synthetic import DEMO_LABELS, generate_dataset, generate_flow
from nethawk.preprocessing.clean import prepare_dataframe, vector_from_dict
from nethawk.schema import FEATURE_NAMES, LABEL_COLUMN


def test_generated_dataset_shape_and_labels():
    frame = generate_dataset(rows_per_class=20, seed=1)
    assert list(frame.columns) == FEATURE_NAMES + [LABEL_COLUMN]
    assert set(frame[LABEL_COLUMN]) == set(DEMO_LABELS)
    assert frame.isna().sum().sum() == 0


def test_generated_flows_are_finite_and_non_negative():
    for label in DEMO_LABELS:
        features = generate_flow(label)
        values = np.array(list(features.values()), dtype=float)
        assert np.isfinite(values).all() and (values >= 0).all()


def test_attack_flows_differ_from_benign():
    benign = generate_flow("BENIGN")
    flood = generate_flow("DDoS")
    assert flood["Flow Packets/s"] > benign["Flow Packets/s"]


def test_demo_generator_emits_traffic_records():
    generator = DemoTrafficGenerator(seed=4)
    record = generator.next_background_record()
    assert record.source.startswith("192.168.1.")
    assert record.protocol in ("TCP", "UDP")
    assert set(record.features) == set(FEATURE_NAMES)
    assert record.metadata["synthetic"] is True


def test_simulation_sequence_is_scripted():
    labels = [r.origin_label for r in DemoTrafficGenerator(seed=4).simulation_sequence()]
    assert labels[0] == "PortScan" and labels[-1] == "DDoS"
    assert len(labels) >= 6
    # a single attacker host drives the whole scripted demonstration
    sources = {r.source for r in DemoTrafficGenerator(seed=4).simulation_sequence()}
    assert len(sources) == 1


def test_cleaning_handles_real_cicids_quirks(tmp_path):
    """Padded headers, extra columns, Infinity and NaN - all present in the real CSVs."""
    frame = generate_dataset(rows_per_class=12, seed=2)
    frame = frame.rename(columns={c: f" {c}" for c in frame.columns})
    frame[" Fwd Header Length"] = 20            # column NetHawk does not use
    frame.loc[frame.index[:5], " Flow Bytes/s"] = np.inf
    frame.loc[frame.index[5:10], " Flow Packets/s"] = np.nan
    path = tmp_path / "Friday-WorkingHours.pcap_ISCX.csv"
    frame.to_csv(path, index=False, encoding="latin-1")

    dataset = load_cicids(tmp_path)
    assert dataset.source == SOURCE_CICIDS and dataset.is_real
    assert list(dataset.frame.columns) == FEATURE_NAMES + [LABEL_COLUMN]
    assert np.isfinite(dataset.frame[FEATURE_NAMES].to_numpy()).all()


def test_missing_feature_columns_raise_a_clear_error():
    with pytest.raises(ValueError, match="missing required feature columns"):
        prepare_dataframe(pd.DataFrame({"Flow Duration": [1.0], "Label": ["BENIGN"]}))


def test_missing_dataset_directory_raises():
    with pytest.raises(FileNotFoundError):
        load_cicids("/nonexistent/nethawk/path")


def test_demo_dataset_is_written_and_reloadable(tmp_path):
    path = tmp_path / "demo.csv"
    first = load_demo(rows_per_class=15, path=path)
    assert path.exists()
    assert len(load_demo(path=path).frame) == len(first.frame)


def test_vector_from_dict_orders_and_sanitises():
    vector = vector_from_dict({"Flow Duration": float("inf"), "Destination Port": "80"})
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[FEATURE_NAMES.index("Destination Port")] == 80.0
    assert vector[FEATURE_NAMES.index("Flow Duration")] == 0.0   # inf sanitised


# ------------------------------------------- leakage + sampling regressions --
def test_cross_file_duplicates_are_dropped_before_splitting(tmp_path):
    """Two CSVs sharing rows must not leak the same flow into train AND test."""
    frame = generate_dataset(rows_per_class=20, seed=5)
    frame.iloc[:120].to_csv(tmp_path / "Monday-WorkingHours.pcap_ISCX.csv", index=False)
    frame.iloc[60:180].to_csv(tmp_path / "Tuesday-WorkingHours.pcap_ISCX.csv", index=False)

    dataset = load_cicids(tmp_path)
    assert dataset.duplicates_removed > 0
    assert not dataset.frame.duplicated().any()
    assert "duplicate rows dropped" in dataset.summary()


def test_large_files_are_sampled_randomly_not_truncated(tmp_path):
    """Head-truncation of a time/label-ordered CSV can drop whole classes."""
    frame = generate_dataset(rows_per_class=100, seed=1).sort_values(LABEL_COLUMN)
    path = tmp_path / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    frame.to_csv(path, index=False)

    truncated = pd.read_csv(path, nrows=150)[LABEL_COLUMN].nunique()
    sampled = load_cicids(tmp_path, max_rows_per_file=150).frame[LABEL_COLUMN].nunique()
    assert truncated == 1          # the bug this guards against
    assert sampled > truncated     # random sampling keeps the classes
