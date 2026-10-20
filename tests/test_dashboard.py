"""Dashboard smoke test - drives the real widgets without entering mainloop.

Skipped automatically when no display is available (e.g. CI).
"""
import time

import pytest

from nethawk.database.db import Database
from nethawk.engine import NetHawkEngine

ctk = pytest.importorskip("customtkinter")


@pytest.fixture
def app(tmp_path):
    from nethawk.dashboard.app import NetHawkDashboard
    engine = NetHawkEngine(database=Database(tmp_path / "gui.db"), demo_seed=8)
    try:
        dashboard = NetHawkDashboard(engine=engine, autostart=False)
    except Exception as exc:                      # no display / no Tk
        pytest.skip(f"GUI unavailable: {exc}")
    yield dashboard
    dashboard._on_close()


def pump(app, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.update_idletasks()
        app.update()
        time.sleep(0.02)


def test_dashboard_builds_all_sections(app):
    pump(app, 0.3)
    assert app.tree is not None and app.alerts_frame is not None
    assert app.card_devices and app.card_packets and app.card_threats and app.card_risk
    assert app.mode_switch.get() in ("DEMO", "LIVE")


def test_simulation_updates_table_alerts_and_cards(app):
    app.engine.run_simulation(step_delay=0, blocking=True)
    pump(app, 0.8)
    app._refresh_snapshot()
    pump(app, 0.2)
    assert len(app.tree.get_children()) >= 6
    assert len(app.alerts_frame.winfo_children()) >= 1
    assert int(app.card_threats.value_label.cget("text")) >= 6
    assert app.card_risk.value_label.cget("text") in ("LOW", "MEDIUM", "HIGH")


def test_detail_panel_shows_full_explanation(app):
    app.engine.run_simulation(step_delay=0, blocking=True)
    pump(app, 0.8)
    item = app.tree.get_children()[0]
    app.tree.selection_set(item)
    app._on_select_event()
    text = app.detail_text.get("1.0", "end")
    for section in ("DETECTION", "CLASSIFICATION", "RISK SCORE", "RESPONSE", "KEY FEATURES"):
        assert section in text


def test_clear_button_empties_the_table(app):
    app.engine.run_simulation(step_delay=0, blocking=True)
    pump(app, 0.5)
    app._clear_data()
    pump(app, 0.3)
    assert app.tree.get_children() == ()
    assert app.engine.snapshot()["events"] == 0
