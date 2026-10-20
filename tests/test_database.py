"""SQLite layer: schema, inserts, aggregates, devices, blocklist, clearing."""
from nethawk.database.db import Database

EVENT = dict(prediction="ATTACK", attack_type="DoS", confidence=0.93, risk_score=88,
             risk_level="HIGH", source="192.168.1.50", destination="192.168.1.1",
             protocol="TCP", response="ALERT + BLOCK [SIMULATED]", mode="DEMO",
             explanation="because", simulated=True)


def test_schema_tables_exist(db):
    with db.connect() as conn:
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"events", "devices", "system_status", "blocklist"} <= names


def test_insert_and_read_event(db):
    event_id = db.insert_event(EVENT)
    stored = db.get_event(event_id)
    assert stored["attack_type"] == "DoS"
    assert stored["risk_level"] == "HIGH"
    assert stored["simulated"] == 1
    assert stored["timestamp"]


def test_event_counts_and_types(db):
    db.insert_event(EVENT)
    db.insert_event(dict(EVENT, attack_type="Normal", prediction="NORMAL",
                         risk_score=0, risk_level="LOW"))
    counts = db.event_counts()
    assert counts["total"] == 2 and counts["attacks"] == 1 and counts["high"] == 1
    assert db.attack_type_counts() == [("DoS", 1)]


def test_recent_events_filters(db):
    db.insert_event(EVENT)
    db.insert_event(dict(EVENT, prediction="NORMAL", attack_type="Normal",
                         risk_score=0, risk_level="LOW"))
    assert len(db.recent_events(limit=10)) == 2
    assert len(db.recent_events(attacks_only=True)) == 1
    assert len(db.recent_events(min_risk=70)) == 1


def test_device_upsert_accumulates(db):
    db.upsert_device("10.0.0.9", packets=5, threat=True, status="SUSPICIOUS")
    db.upsert_device("10.0.0.9", packets=7)
    device = db.devices()[0]
    assert device["packets"] == 12
    assert device["threat_count"] == 1
    assert device["status"] == "SUSPICIOUS"   # status is preserved when not passed
    assert db.device_count() == 1


def test_blocklist_and_status(db):
    db.add_to_blocklist("10.0.0.9", "DoS (risk 88)")
    entry = db.blocklist()[0]
    assert entry["simulated"] == 1 and "DoS" in entry["reason"]
    db.record_status("DEMO", True, 10, 2, "started")
    assert db.latest_status()["mode"] == "DEMO"


def test_clear_all(db):
    db.insert_event(EVENT)
    db.upsert_device("10.0.0.9")
    db.add_to_blocklist("10.0.0.9", "x")
    db.clear_all()
    assert db.event_counts()["total"] == 0
    assert db.device_count() == 0 and db.blocklist() == []


def test_database_is_created_on_disk(tmp_path):
    path = tmp_path / "nested" / "nethawk.db"
    Database(path)
    assert path.exists()
