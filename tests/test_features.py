"""Feature extraction: all three adapters must produce the same schema."""
import time

import pytest

from nethawk.capture.flows import Flow, FlowTable
from nethawk.features.adapters import (
    DatasetFeatureAdapter,
    DemoTrafficFeatureAdapter,
    LiveTrafficFeatureAdapter,
    extract_features,
)
from nethawk.schema import FEATURE_NAMES


def build_flow(packets=40, forward_ratio=0.7):
    table = FlowTable(timeout=0.01)
    start = time.time()
    for i in range(packets):
        forward = (i % 10) < int(forward_ratio * 10)
        src, dst, sport, dport = (("10.0.0.5", "10.0.0.1", 51000, 80) if forward
                                  else ("10.0.0.1", "10.0.0.5", 80, 51000))
        table.add_packet(src, dst, sport, dport, "TCP", 200, start + i * 0.01,
                         {"SYN": 1 if i == 0 else 0, "ACK": 1, "PSH": 1}, window=64240)
    flows = table.collect_expired(force=True)
    assert len(flows) == 1
    return flows[0]


def test_live_adapter_produces_full_schema():
    features = LiveTrafficFeatureAdapter().extract_features(build_flow())
    assert set(features) == set(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in features.values())


def test_demo_adapter_produces_full_schema():
    features = DemoTrafficFeatureAdapter(seed=1).extract_features("DDoS")
    assert set(features) == set(FEATURE_NAMES)


def test_dataset_adapter_handles_padded_column_names():
    record = {f" {name}": 1.0 for name in FEATURE_NAMES}
    features = DatasetFeatureAdapter().extract_features(record)
    assert set(features) == set(FEATURE_NAMES)
    assert features["Flow Duration"] == 1.0


def test_flow_direction_is_set_by_first_packet():
    flow = build_flow(packets=20, forward_ratio=0.7)
    features = LiveTrafficFeatureAdapter().extract_features(flow)
    assert features["Total Fwd Packets"] > features["Total Backward Packets"]
    assert features["Destination Port"] == 80


def test_both_directions_land_in_one_flow():
    table = FlowTable(timeout=0.01)
    now = time.time()
    table.add_packet("10.0.0.5", "10.0.0.1", 5000, 80, "TCP", 100, now)
    table.add_packet("10.0.0.1", "10.0.0.5", 80, 5000, "TCP", 100, now + 0.01)
    assert len(table.collect_expired(force=True)) == 1


def test_derived_rates_are_consistent():
    features = LiveTrafficFeatureAdapter().extract_features(build_flow(packets=50))
    total = features["Total Fwd Packets"] + features["Total Backward Packets"]
    assert total == 50
    duration_s = features["Flow Duration"] / 1e6
    assert features["Flow Packets/s"] == pytest.approx(total / duration_s, rel=1e-6)


def test_dispatcher_picks_the_right_adapter():
    assert set(extract_features(build_flow())) == set(FEATURE_NAMES)
    assert set(extract_features("BENIGN")) == set(FEATURE_NAMES)


def test_empty_flow_does_not_crash():
    features = LiveTrafficFeatureAdapter().extract_features(
        Flow(src="a", dst="b", sport=1, dport=2, protocol="TCP"))
    assert features["Flow Packets/s"] >= 0
