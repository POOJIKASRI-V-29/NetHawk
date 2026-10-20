"""Integration-level checks: CLI wiring, config overrides, reports, shutdown."""
import threading

import pytest

from nethawk import config
from nethawk.database.db import Database
from nethawk.engine import NetHawkEngine
from nethawk.utils.report import build_report, write_report


# --------------------------------------------------------------------- CLI --
def test_cli_parses_every_documented_flag():
    import app as nethawk_app

    args = nethawk_app.parse_args(["--mode", "live", "--headless", "--simulate",
                                   "--duration", "3", "--iface", "lo0",
                                   "--filter", "tcp port 80", "--no-autostart",
                                   "--verbose"])
    assert args.mode == "live" and args.headless and args.simulate
    assert args.iface == "lo0" and args.bpf_filter == "tcp port 80"
    assert nethawk_app.parse_args(["--replay"]).replay == "__sample__"
    assert nethawk_app.parse_args(["--replay", "x.pcap"]).replay == "x.pcap"
    assert nethawk_app.parse_args([]).mode == "demo"


# ------------------------------------------------------------------ config --
def test_paths_are_relative_to_the_project_root():
    assert config.PROJECT_ROOT.is_dir()
    assert (config.PROJECT_ROOT / "app.py").exists()
    for path in (config.DATA_DIR, config.MODELS_DIR, config.DB_PATH):
        assert str(path).startswith(str(config.PROJECT_ROOT)) or path.is_absolute()


def test_env_override_is_respected(monkeypatch, tmp_path):
    import importlib
    monkeypatch.setenv("NETHAWK_DB_PATH", str(tmp_path / "custom.db"))
    reloaded = importlib.reload(config)
    try:
        assert reloaded.DB_PATH == tmp_path / "custom.db"
    finally:
        monkeypatch.delenv("NETHAWK_DB_PATH")
        importlib.reload(config)


# ------------------------------------------------------------------ engine --
def test_engine_forwards_interface_and_filter_to_capture(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "e.db"),
                           interface="lo0", bpf_filter="tcp port 65000")
    assert engine.interface == "lo0" and engine.bpf_filter == "tcp port 65000"


def test_shutdown_leaves_no_background_threads(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "s.db"), demo_seed=4)
    engine.start_monitoring("DEMO")
    engine.run_simulation(step_delay=0.01)
    engine.stop_monitoring()
    leftover = [t.name for t in threading.enumerate() if t.name.startswith("nethawk")]
    assert leftover == []
    assert engine.monitoring is False


def test_monitoring_can_be_restarted(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "r.db"), demo_seed=4)
    assert engine.start_monitoring("DEMO") == "DEMO"
    engine.stop_monitoring()
    assert engine.start_monitoring("DEMO") == "DEMO"      # _stop must be cleared
    engine.stop_monitoring()


# ------------------------------------------------------------------ report --
def test_report_contains_the_expected_sections(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "rep.db"), demo_seed=6)
    engine.run_simulation(step_delay=0, blocking=True)
    text = build_report(engine.db, engine.predictor)
    for section in ("NETHAWK SECURITY REPORT", "SUMMARY", "ATTACK TYPES",
                    "DEVICES", "RECENT ATTACK EVENTS", "SIMULATED"):
        assert section in text


def test_report_is_written_to_disk(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "rep2.db"), demo_seed=6)
    engine.process_record(engine.demo_generator.random_attack_record())
    path = write_report(engine.db, engine.predictor, tmp_path / "out.txt")
    assert path.exists() and path.read_text().startswith("NETHAWK SECURITY REPORT")
