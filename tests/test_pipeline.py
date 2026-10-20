"""End-to-end: prediction, decision policy, and the full engine pipeline."""
import pytest

from nethawk.capture.demo import DemoTrafficGenerator
from nethawk.database.db import Database
from nethawk.engine import NetHawkEngine
from nethawk.response.engine import ACTION_BLOCK, ACTION_MONITOR, ACTION_WARN, DecisionEngine
from nethawk.schema import ATTACK_CATEGORIES, MODE_DEMO


# --------------------------------------------------------------- prediction --
def test_predictor_returns_structured_result(predictor):
    features = DemoTrafficGenerator(seed=2).next_background_record().features
    result = predictor.predict(features)
    assert result["prediction"] in ("NORMAL", "ATTACK")
    assert result["attack_type"] in ATTACK_CATEGORIES
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["probabilities"]


def test_benign_traffic_is_classified_normal(predictor):
    from nethawk.datasets.synthetic import generate_flow
    import random
    rng = random.Random(11)
    normals = sum(predictor.predict(generate_flow("BENIGN", rng))["prediction"] == "NORMAL"
                  for _ in range(25))
    assert normals >= 22          # allow a little noise, this is a probabilistic model


@pytest.mark.parametrize("label", ["DDoS", "DoS Hulk", "PortScan", "FTP-Patator", "Bot"])
def test_attack_traffic_is_classified_attack(predictor, label):
    from nethawk.datasets.synthetic import generate_flow
    import random
    rng = random.Random(3)
    attacks = sum(predictor.predict(generate_flow(label, rng))["prediction"] == "ATTACK"
                  for _ in range(10))
    assert attacks >= 9


# ----------------------------------------------------------------- decisions --
def test_decision_policy_per_level():
    engine = DecisionEngine()
    assert engine.decide("LOW", "Port Scan", "1.1.1.1").action == ACTION_MONITOR
    assert engine.decide("MEDIUM", "Port Scan", "1.1.1.1").action == ACTION_WARN
    assert engine.decide("HIGH", "DDoS", "1.1.1.1").action == ACTION_BLOCK


def test_all_responses_are_simulated():
    engine = DecisionEngine()
    assert engine.enforcement_enabled is False
    for level in ("LOW", "MEDIUM", "HIGH"):
        decision = engine.decide(level, "DoS", "1.1.1.1")
        assert decision.simulated is True
        assert "SIMULATED" in decision.display


def test_high_risk_response_writes_blocklist(db):
    engine = DecisionEngine(db)
    decision = engine.decide("HIGH", "DDoS", "192.168.1.77")
    engine.execute(decision, "192.168.1.77", "DDoS", 95)
    assert db.blocklist()[0]["identifier"] == "192.168.1.77"
    assert db.devices()[0]["status"] == "BLOCKED (SIM)"


# -------------------------------------------------------------------- engine --
@pytest.fixture
def engine(tmp_path):
    return NetHawkEngine(database=Database(tmp_path / "engine.db"), demo_seed=5)


def test_process_record_runs_every_stage(engine):
    record = DemoTrafficGenerator(seed=9).random_attack_record()
    event = engine.process_record(record)
    for field in ("id", "prediction", "attack_type", "confidence", "risk_score",
                  "risk_level", "response", "explanation", "features", "probabilities"):
        assert field in event
    assert engine.db.get_event(event["id"]) is not None


def test_demo_simulation_produces_high_risk_attacks(engine):
    engine.run_simulation(step_delay=0, blocking=True)
    events = engine.db.recent_events(limit=50, attacks_only=True)
    assert len(events) >= 6
    assert any(e["risk_level"] == "HIGH" for e in events)
    assert {e["attack_type"] for e in events} & {"DoS", "DDoS", "Brute Force", "Port Scan"}
    assert all("SIMULATED" in e["response"] for e in events)


def test_simulation_escalates_from_recon_to_flood(engine):
    engine.run_simulation(step_delay=0, blocking=True)
    ordered = list(reversed(engine.db.recent_events(limit=50, attacks_only=True)))
    types = [e["attack_type"] for e in ordered]
    assert types[0] == "Port Scan"
    assert types[-1] == "DDoS"
    assert ordered[0]["risk_score"] < ordered[-1]["risk_score"]


def test_engine_counters_and_snapshot(engine):
    engine.run_simulation(step_delay=0, blocking=True)
    snapshot = engine.snapshot()
    assert snapshot["events"] >= 6
    assert snapshot["threats"] >= 6
    assert snapshot["packets"] > 0
    assert snapshot["mode"] == MODE_DEMO


def test_clear_data_resets_everything(engine):
    engine.run_simulation(step_delay=0, blocking=True)
    engine.clear_data()
    assert engine.snapshot()["events"] == 0


def test_live_mode_falls_back_to_demo_without_privileges(engine):
    """On an unprivileged machine start_monitoring('LIVE') must degrade, not crash."""
    mode = engine.start_monitoring("LIVE")
    engine.stop_monitoring()
    assert mode in ("DEMO", "LIVE")
    if mode == "DEMO":
        notices = []
        while not engine.messages.empty():
            message = engine.messages.get()
            if message.kind == "notice":
                notices.append(message.payload["text"])
        assert any("DEMO" in text for text in notices)
