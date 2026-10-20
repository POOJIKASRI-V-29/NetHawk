"""SQLite persistence layer for NetHawk.

A fresh connection is opened per operation.  That is slightly less efficient
than a pooled connection but it is completely safe across the capture thread
and the Tk main thread, which is what matters for this application.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from .. import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    source        TEXT,
    destination   TEXT,
    protocol      TEXT,
    prediction    TEXT    NOT NULL,   -- NORMAL / ATTACK
    attack_type   TEXT    NOT NULL,   -- canonical category
    confidence    REAL    NOT NULL,
    risk_score    INTEGER NOT NULL,
    risk_level    TEXT    NOT NULL,   -- LOW / MEDIUM / HIGH
    response      TEXT,
    simulated     INTEGER NOT NULL DEFAULT 1,
    mode          TEXT    NOT NULL,   -- DEMO / LIVE
    explanation   TEXT,
    features_json TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier   TEXT UNIQUE NOT NULL,   -- IP or MAC
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    packets      INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'TRUSTED'   -- TRUSTED / SUSPICIOUS / BLOCKED(SIM)
);

CREATE TABLE IF NOT EXISTS system_status (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    mode          TEXT NOT NULL,
    monitoring    INTEGER NOT NULL,
    packets_seen  INTEGER NOT NULL DEFAULT 0,
    events_logged INTEGER NOT NULL DEFAULT 0,
    note          TEXT
);

CREATE TABLE IF NOT EXISTS blocklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    reason     TEXT,
    simulated  INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk_level);
"""


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else config.DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------- events ---
    def insert_event(self, event: dict[str, Any]) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """INSERT INTO events (timestamp, source, destination, protocol,
                        prediction, attack_type, confidence, risk_score, risk_level,
                        response, simulated, mode, explanation, features_json)
                   VALUES (:timestamp, :source, :destination, :protocol, :prediction,
                           :attack_type, :confidence, :risk_score, :risk_level,
                           :response, :simulated, :mode, :explanation, :features_json)""",
                {
                    "timestamp": event.get("timestamp") or now(),
                    "source": event.get("source"),
                    "destination": event.get("destination"),
                    "protocol": event.get("protocol"),
                    "prediction": event["prediction"],
                    "attack_type": event["attack_type"],
                    "confidence": float(event.get("confidence", 0.0)),
                    "risk_score": int(event.get("risk_score", 0)),
                    "risk_level": event.get("risk_level", "LOW"),
                    "response": event.get("response"),
                    "simulated": 1 if event.get("simulated", True) else 0,
                    "mode": event.get("mode", "DEMO"),
                    "explanation": event.get("explanation"),
                    "features_json": event.get("features_json"),
                },
            )
            return int(cur.lastrowid)

    def recent_events(self, limit: int = 100, attacks_only: bool = False,
                      min_risk: int = 0) -> list[dict]:
        query = "SELECT * FROM events WHERE risk_score >= ?"
        params: list[Any] = [min_risk]
        if attacks_only:
            query += " AND prediction = 'ATTACK'"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_event(self, event_id: int) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
            return dict(row) if row else None

    def event_counts(self) -> dict[str, int]:
        with self.connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            attacks = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE prediction='ATTACK'").fetchone()["c"]
            high = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE risk_level='HIGH'").fetchone()["c"]
            medium = conn.execute(
                "SELECT COUNT(*) c FROM events WHERE risk_level='MEDIUM'").fetchone()["c"]
            avg = conn.execute(
                "SELECT AVG(risk_score) a FROM events WHERE prediction='ATTACK'").fetchone()["a"]
        return {"total": total, "attacks": attacks, "high": high, "medium": medium,
                "avg_attack_risk": int(avg) if avg else 0}

    def attack_type_counts(self) -> list[tuple[str, int]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT attack_type, COUNT(*) c FROM events
                   WHERE prediction='ATTACK' GROUP BY attack_type ORDER BY c DESC"""
            ).fetchall()
        return [(r["attack_type"], r["c"]) for r in rows]

    # ------------------------------------------------------------ devices ---
    def upsert_device(self, identifier: str, packets: int = 1,
                      threat: bool = False, status: str | None = None) -> None:
        if not identifier:
            return
        stamp = now()
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO devices (identifier, first_seen, last_seen, packets, threat_count, status)
                   VALUES (?, ?, ?, ?, ?, COALESCE(?, 'TRUSTED'))
                   ON CONFLICT(identifier) DO UPDATE SET
                        last_seen    = excluded.last_seen,
                        packets      = devices.packets + excluded.packets,
                        threat_count = devices.threat_count + excluded.threat_count,
                        status       = COALESCE(?, devices.status)""",
                (identifier, stamp, stamp, packets, 1 if threat else 0, status, status),
            )

    def devices(self) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC").fetchall()]

    def device_count(self) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"])

    # ---------------------------------------------------------- blocklist ---
    def add_to_blocklist(self, identifier: str, reason: str, simulated: bool = True) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO blocklist (identifier, added_at, reason, simulated) VALUES (?,?,?,?)",
                (identifier, now(), reason, 1 if simulated else 0),
            )

    def blocklist(self) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM blocklist ORDER BY id DESC").fetchall()]

    # ------------------------------------------------------ system status ---
    def record_status(self, mode: str, monitoring: bool, packets_seen: int = 0,
                      events_logged: int = 0, note: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO system_status (timestamp, mode, monitoring, packets_seen, events_logged, note)
                   VALUES (?,?,?,?,?,?)""",
                (now(), mode, 1 if monitoring else 0, packets_seen, events_logged, note),
            )

    def latest_status(self) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM system_status ORDER BY id DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    # --------------------------------------------------------- housekeeping --
    def clear_all(self) -> None:
        """Wipe demo data so a fresh demonstration starts from an empty board."""
        with self.connect() as conn:
            for table in ("events", "devices", "system_status", "blocklist"):
                conn.execute(f"DELETE FROM {table}")
            conn.execute("DELETE FROM sqlite_sequence WHERE name IN "
                         "('events','devices','system_status','blocklist')")
