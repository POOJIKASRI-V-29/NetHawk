"""NetHawk monitoring engine - the orchestrator for the whole pipeline.

    traffic record / live flow
        -> feature extraction (adapters)
        -> ML prediction            (Random Forest)
        -> attack classification    (canonical category)
        -> risk scoring             (deterministic formula)
        -> decision engine          (controlled, simulated response)
        -> SQLite logging
        -> UI notification (queue consumed by the dashboard)

Everything runs on background threads; the dashboard only reads from a queue,
so the Tk main loop never blocks on capture or inference.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from . import config
from .capture.demo import DemoTrafficGenerator, TrafficRecord
from .capture.flows import Flow
from .capture.live import CaptureStatus, LiveCapture, capture_available, platform_hint
from .database.db import Database, now
from .detection.classifier import describe, is_attack
from .features.adapters import (
    DemoTrafficFeatureAdapter,
    LiveTrafficFeatureAdapter,
)
from .ml.predictor import Predictor
from .response.engine import DecisionEngine
from .risk.scoring import score_event
from .schema import MODE_DEMO, MODE_LIVE


@dataclass
class EngineStats:
    packets_seen: int = 0
    events_processed: int = 0
    attacks_detected: int = 0
    started_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"packets_seen": self.packets_seen,
                "events_processed": self.events_processed,
                "attacks_detected": self.attacks_detected,
                "uptime": int(time.time() - self.started_at) if self.started_at else 0}


@dataclass
class EngineMessage:
    """Anything the engine wants the dashboard to know about."""
    kind: str                              # 'event' | 'notice' | 'stats' | 'mode'
    payload: dict[str, Any] = field(default_factory=dict)


class NetHawkEngine:
    def __init__(self, database: Database | None = None,
                 predictor: Predictor | None = None,
                 mode: str = MODE_DEMO,
                 demo_seed: int | None = None) -> None:
        config.ensure_directories()
        self.db = database or Database()
        self.predictor = predictor or Predictor()
        self.decision_engine = DecisionEngine(self.db)
        self.demo_generator = DemoTrafficGenerator(seed=demo_seed)
        self.demo_adapter = DemoTrafficFeatureAdapter(seed=demo_seed)
        self.live_adapter = LiveTrafficFeatureAdapter()

        self.mode = mode
        self.monitoring = False
        self.stats = EngineStats()
        self.messages: "queue.Queue[EngineMessage]" = queue.Queue()
        self.capture_status: CaptureStatus | None = None

        self._stop = threading.Event()
        self._demo_thread: threading.Thread | None = None
        self._sim_thread: threading.Thread | None = None
        self._live: LiveCapture | None = None
        self._lock = threading.Lock()
        self.on_message: Callable[[EngineMessage], None] | None = None

    # ------------------------------------------------------------ plumbing --
    def _emit(self, kind: str, **payload: Any) -> None:
        message = EngineMessage(kind=kind, payload=payload)
        self.messages.put(message)
        if self.on_message:
            try:
                self.on_message(message)
            except Exception:
                pass

    def notice(self, text: str, level: str = "info") -> None:
        self._emit("notice", text=text, level=level, timestamp=now())

    # ---------------------------------------------------------- pipeline ----
    def process_record(self, record: TrafficRecord | Flow,
                       source_mode: str | None = None) -> dict[str, Any]:
        """Run one traffic record through the complete detection pipeline."""
        mode = source_mode or self.mode

        # 1. feature extraction (the adapter depends on where traffic came from)
        if isinstance(record, Flow):
            features = self.live_adapter.extract_features(record)
            source, destination = record.src, record.dst
            protocol = record.protocol
            packets = record.packet_count
            origin_label = None
        else:
            features = self.demo_adapter.extract_features(record.features)
            source, destination = record.source, record.destination
            protocol = record.protocol
            packets = record.packets
            origin_label = record.origin_label

        # 2. ML detection + 3. attack classification
        prediction = self.predictor.predict(features)
        category = prediction["attack_type"]

        # 4. risk scoring
        risk = score_event(category, prediction["confidence"], features)

        # 5. decision engine + controlled response
        decision = self.decision_engine.decide(risk.level, category, source)
        self.decision_engine.execute(decision, source, category, risk.score)

        # 6. persistence
        event = {
            "timestamp": now(),
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "prediction": prediction["prediction"],
            "attack_type": category,
            "confidence": prediction["confidence"],
            "risk_score": risk.score,
            "risk_level": risk.level,
            "response": decision.display,
            "simulated": decision.simulated,
            "mode": mode,
            "explanation": risk.explanation,
            "features_json": json.dumps({k: round(float(v), 3) for k, v in features.items()}),
        }
        event_id = self.db.insert_event(event)
        self.db.upsert_device(source, packets=packets, threat=is_attack(category))

        # 7. notify the UI
        with self._lock:
            self.stats.packets_seen += packets
            self.stats.events_processed += 1
            if is_attack(category):
                self.stats.attacks_detected += 1

        enriched = dict(event)
        enriched.update({
            "id": event_id,
            "probabilities": prediction["probabilities"],
            "category_description": describe(category),
            "risk_components": risk.components,
            "response_action": decision.action,
            "response_rationale": decision.rationale,
            "origin_label": origin_label,
            "alert": decision.alert,
            "features": features,
        })
        self._emit("event", event=enriched)
        self._emit("stats", stats=self.stats.as_dict())
        return enriched

    # ------------------------------------------------------- demo monitor ---
    def _demo_loop(self) -> None:
        while not self._stop.is_set():
            try:
                record = self.demo_generator.next_background_record()
                self.process_record(record, source_mode=MODE_DEMO)
            except Exception as exc:
                self.notice(f"Demo monitoring error: {exc}", "error")
            self._stop.wait(config.DEMO_EVENT_INTERVAL)

    # ------------------------------------------------------- live monitor ---
    def _on_live_flow(self, flow: Flow) -> None:
        try:
            self.process_record(flow, source_mode=MODE_LIVE)
        except Exception as exc:
            self.notice(f"Live analysis error: {exc}", "error")

    # ------------------------------------------------------------ control ---
    def start_monitoring(self, mode: str | None = None) -> str:
        """Start monitoring; returns the mode actually started (DEMO or LIVE)."""
        if self.monitoring:
            return self.mode
        requested = mode or self.mode
        self._stop.clear()

        if requested == MODE_LIVE:
            self.capture_status = capture_available()
            if self.capture_status.available:
                self._live = LiveCapture(on_flow=self._on_live_flow)
                if self._live.start():
                    self.mode = MODE_LIVE
                    self.monitoring = True
                    self.stats.started_at = time.time()
                    self.db.record_status(self.mode, True, note="live capture started")
                    self.notice(f"LIVE capture started on {self._live.interface or 'default interface'}.",
                                "success")
                    self._emit("mode", mode=self.mode)
                    return self.mode
                self.notice(f"Could not start sniffer: {self._live.last_error}", "error")
                self._live = None
            else:
                self.notice(f"LIVE mode unavailable - {self.capture_status.reason}", "warning")
            self.notice(f"Falling back to DEMO mode. {platform_hint()}", "warning")

        self.mode = MODE_DEMO
        self.monitoring = True
        self.stats.started_at = time.time()
        self._demo_thread = threading.Thread(target=self._demo_loop, daemon=True,
                                             name="nethawk-demo-monitor")
        self._demo_thread.start()
        self.db.record_status(self.mode, True, note="demo monitoring started")
        self.notice("DEMO monitoring started - traffic is locally generated, not captured.",
                    "success")
        self._emit("mode", mode=self.mode)
        return self.mode

    def stop_monitoring(self) -> None:
        if not self.monitoring:
            return
        self._stop.set()
        if self._live is not None:
            self._live.stop()
            self._live = None
        if self._demo_thread is not None:
            self._demo_thread.join(timeout=3.0)
            self._demo_thread = None
        self.monitoring = False
        self.db.record_status(self.mode, False,
                              packets_seen=self.stats.packets_seen,
                              events_logged=self.stats.events_processed,
                              note="monitoring stopped")
        self.notice("Monitoring stopped.", "info")

    def switch_mode(self, mode: str) -> str:
        was_running = self.monitoring
        self.stop_monitoring()
        self.mode = mode
        self._emit("mode", mode=self.mode)
        if was_running:
            return self.start_monitoring(mode)
        self.notice(f"Mode set to {mode}.", "info")
        return self.mode

    # --------------------------------------------------------- simulation ---
    def run_simulation(self, intensity: str = "standard",
                       step_delay: float = 0.9,
                       blocking: bool = False) -> None:
        """Run the controlled, local attack demonstration (no real traffic sent)."""
        if self._sim_thread and self._sim_thread.is_alive():
            self.notice("A security simulation is already running.", "warning")
            return

        def _run() -> None:
            self.notice("SECURITY SIMULATION started - controlled local traffic, "
                        "no packets are transmitted.", "warning")
            for record in self.demo_generator.simulation_sequence(intensity):
                if self._stop.is_set() and not blocking:
                    break
                try:
                    self.process_record(record, source_mode=self.mode)
                except Exception as exc:
                    self.notice(f"Simulation error: {exc}", "error")
                if step_delay:
                    time.sleep(step_delay)
            self.notice("SECURITY SIMULATION complete.", "success")

        if blocking:
            _run()
            return
        self._sim_thread = threading.Thread(target=_run, daemon=True,
                                            name="nethawk-simulation")
        self._sim_thread.start()

    # -------------------------------------------------------------- state ---
    def snapshot(self) -> dict[str, Any]:
        counts = self.db.event_counts()
        return {
            "mode": self.mode,
            "monitoring": self.monitoring,
            "model": self.predictor.describe(),
            "is_demo_model": self.predictor.is_demo_model,
            "devices": self.db.device_count(),
            "packets": self.stats.packets_seen,
            "threats": counts["attacks"],
            "high_risk": counts["high"],
            "avg_attack_risk": counts["avg_attack_risk"],
            "events": counts["total"],
        }

    def clear_data(self) -> None:
        self.db.clear_all()
        self.stats = EngineStats(started_at=self.stats.started_at)
        self.notice("All stored events, devices and blocklist entries cleared.", "info")
        self._emit("stats", stats=self.stats.as_dict())
