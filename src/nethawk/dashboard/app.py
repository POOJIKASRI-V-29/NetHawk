"""NetHawk desktop dashboard (CustomTkinter).

The UI never runs detection itself.  NetHawkEngine does all work on background
threads and posts messages onto a queue; the dashboard drains that queue on the
Tk main loop every 200 ms, so the window stays responsive during capture and
inference.
"""
from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any

import customtkinter as ctk

from .. import config
from ..capture.live import capture_available, platform_hint
from ..detection.classifier import describe
from ..engine import EngineMessage, NetHawkEngine
from ..schema import MODE_DEMO, MODE_LIVE
from . import theme

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

HISTORY_COLUMNS = [
    ("time", "TIMESTAMP", 150),
    ("source", "SOURCE", 125),
    ("attack", "ATTACK TYPE", 120),
    ("conf", "CONF", 60),
    ("risk", "RISK", 55),
    ("level", "LEVEL", 80),
    ("action", "ACTION", 230),
    ("mode", "MODE", 60),
]
MAX_HISTORY_ROWS = 400
MAX_ALERTS = 7


class Card(ctk.CTkFrame):
    """One summary metric tile."""

    def __init__(self, master, title: str, value: str = "0", accent: str = theme.ACCENT):
        super().__init__(master, fg_color=theme.PANEL, corner_radius=12,
                         border_width=1, border_color=theme.BORDER)
        self.accent = accent
        ctk.CTkLabel(self, text=title.upper(), text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=16, pady=(12, 0))
        self.value_label = ctk.CTkLabel(self, text=value, text_color=accent,
                                        font=(theme.FONT_FAMILY, 30, "bold"))
        self.value_label.pack(anchor="w", padx=16, pady=(0, 2))
        self.sub_label = ctk.CTkLabel(self, text="", text_color=theme.TEXT_DIM,
                                      font=(theme.FONT_FAMILY, 11))
        self.sub_label.pack(anchor="w", padx=16, pady=(0, 12))

    def update_value(self, value: Any, subtitle: str = "", color: str | None = None) -> None:
        self.value_label.configure(text=str(value), text_color=color or self.accent)
        self.sub_label.configure(text=subtitle)


class NetHawkDashboard(ctk.CTk):
    def __init__(self, engine: NetHawkEngine | None = None,
                 start_mode: str = MODE_DEMO, autostart: bool = True) -> None:
        super().__init__()
        self.engine = engine or NetHawkEngine(mode=start_mode)
        self.events: dict[str, dict] = {}     # treeview item id -> event dict
        self.autostart = autostart

        self.title(f"{config.APP_NAME} - Monitoring Console")
        # Fit the window to the actual screen so it works on small laptops too.
        width = min(1420, max(1100, self.winfo_screenwidth() - 80))
        height = min(900, max(700, self.winfo_screenheight() - 120))
        self.geometry(f"{width}x{height}+40+40")
        self.minsize(1100, 700)
        self.configure(fg_color=theme.BG)

        style = ttk.Style(self)
        theme.style_treeview(style)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_cards()
        self._build_body()
        self._build_footer()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        # Tk `after` loops must stop rescheduling once the window is closing,
        # otherwise the callbacks fire against a destroyed interpreter.
        self._closing = False
        self._after_ids: list[str] = []
        # Results handed back from worker threads.  Tk is not thread-safe, so
        # workers never touch a widget: they queue a result and the Tk thread
        # picks it up in _drain_queue().
        self._ui_results: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._after_ids.append(self.after(200, self._drain_queue))
        self._after_ids.append(self.after(1500, self._refresh_snapshot))
        self._load_history_from_db()
        if self.autostart:
            self.after(600, lambda: self._start_monitoring())

    # ------------------------------------------------------------- header ---
    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=0, height=78)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=22, pady=12)
        ctk.CTkLabel(left, text="NET", text_color=theme.TEXT,
                     font=(theme.FONT_FAMILY, 26, "bold")).pack(side="left")
        ctk.CTkLabel(left, text="HAWK", text_color=theme.ACCENT,
                     font=(theme.FONT_FAMILY, 26, "bold")).pack(side="left")
        ctk.CTkLabel(left, text=f"   {config.APP_TAGLINE}", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 12)).pack(side="left", padx=(10, 0))

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.grid(row=0, column=2, sticky="e", padx=22)
        self.status_pill = self._pill(right, "NETWORK STATUS", "IDLE", theme.TEXT_DIM)
        self.mode_pill = self._pill(right, "MODE", self.engine.mode, theme.ACCENT)
        self.model_pill = self._pill(right, "MODEL", "LOADING", theme.TEXT_DIM)

    def _pill(self, master, title: str, value: str, color: str) -> ctk.CTkLabel:
        frame = ctk.CTkFrame(master, fg_color=theme.PANEL_ALT, corner_radius=8,
                             border_width=1, border_color=theme.BORDER)
        frame.pack(side="left", padx=6)
        ctk.CTkLabel(frame, text=title, text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 9, "bold")).pack(padx=14, pady=(6, 0))
        label = ctk.CTkLabel(frame, text=value, text_color=color,
                             font=(theme.FONT_FAMILY, 13, "bold"))
        label.pack(padx=14, pady=(0, 6))
        return label

    # -------------------------------------------------------------- cards ---
    def _build_cards(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=18, pady=(16, 8))
        for i in range(4):
            row.grid_columnconfigure(i, weight=1, uniform="cards")

        self.card_devices = Card(row, "Active Devices", "0", theme.ACCENT)
        self.card_packets = Card(row, "Live Packets", "0", theme.TEXT)
        self.card_threats = Card(row, "Threat Count", "0", theme.WARN)
        self.card_risk = Card(row, "Network Risk", "LOW", theme.OK)
        for i, card in enumerate((self.card_devices, self.card_packets,
                                  self.card_threats, self.card_risk)):
            card.grid(row=0, column=i, sticky="nsew", padx=6)

        self.risk_bar = ctk.CTkProgressBar(self.card_risk, height=6,
                                           progress_color=theme.OK, fg_color=theme.BORDER)
        self.risk_bar.set(0)
        self.risk_bar.pack(fill="x", padx=16, pady=(0, 12))

    # --------------------------------------------------------------- body ---
    def _build_body(self) -> None:
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew", padx=18, pady=(4, 8))
        body.grid_columnconfigure(1, weight=3)
        body.grid_columnconfigure(2, weight=2)
        body.grid_rowconfigure(0, weight=1)

        self._build_controls(body)
        self._build_center(body)
        self._build_detail(body)

    def _build_controls(self, master) -> None:
        panel = ctk.CTkFrame(master, fg_color=theme.PANEL, corner_radius=12, width=250,
                             border_width=1, border_color=theme.BORDER)
        panel.grid(row=0, column=0, sticky="nsw", padx=(0, 12))
        panel.grid_propagate(False)

        ctk.CTkLabel(panel, text="CONTROLS", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=16, pady=(14, 8))

        self.btn_start = ctk.CTkButton(panel, text="Start Monitoring", height=38,
                                       fg_color=theme.ACCENT_DARK, hover_color="#0891b2",
                                       command=self._start_monitoring)
        self.btn_start.pack(fill="x", padx=16, pady=4)

        self.btn_stop = ctk.CTkButton(panel, text="Stop Monitoring", height=38,
                                      fg_color=theme.PANEL_ALT, hover_color=theme.BORDER,
                                      command=self._stop_monitoring, state="disabled")
        self.btn_stop.pack(fill="x", padx=16, pady=4)

        self.btn_sim = ctk.CTkButton(panel, text="RUN SECURITY SIMULATION", height=46,
                                     fg_color="#b91c1c", hover_color="#dc2626",
                                     font=(theme.FONT_FAMILY, 13, "bold"),
                                     command=self._run_simulation)
        self.btn_sim.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(panel, text="Controlled local traffic only.\nNo packets are transmitted.",
                     text_color=theme.TEXT_DIM, justify="left",
                     font=(theme.FONT_FAMILY, 10)).pack(anchor="w", padx=16, pady=(0, 10))

        self.btn_replay = ctk.CTkButton(panel, text="Replay Sample PCAP", height=34,
                                        fg_color="#1e3a8a", hover_color="#1d4ed8",
                                        command=self._replay_pcap)
        self.btn_replay.pack(fill="x", padx=16, pady=(6, 2))
        ctk.CTkLabel(panel, text="Real packet parsing from file.\nNo privileges required.",
                     text_color=theme.TEXT_DIM, justify="left",
                     font=(theme.FONT_FAMILY, 10)).pack(anchor="w", padx=16, pady=(0, 8))

        ctk.CTkLabel(panel, text="MODE", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=16, pady=(8, 4))
        self.mode_switch = ctk.CTkSegmentedButton(
            panel, values=[MODE_DEMO, MODE_LIVE], command=self._switch_mode,
            selected_color=theme.ACCENT_DARK, selected_hover_color="#0891b2")
        self.mode_switch.set(self.engine.mode)
        self.mode_switch.pack(fill="x", padx=16, pady=(0, 6))

        self.btn_probe = ctk.CTkButton(panel, text="Check Live Capture", height=32,
                                       fg_color=theme.PANEL_ALT, hover_color=theme.BORDER,
                                       command=self._probe_capture)
        self.btn_probe.pack(fill="x", padx=16, pady=4)

        self.btn_clear = ctk.CTkButton(panel, text="Clear Demo Data", height=32,
                                       fg_color=theme.PANEL_ALT, hover_color=theme.BORDER,
                                       command=self._clear_data)
        self.btn_clear.pack(fill="x", padx=16, pady=4)

        self.btn_report = ctk.CTkButton(panel, text="Export Report", height=32,
                                        fg_color=theme.PANEL_ALT, hover_color=theme.BORDER,
                                        command=self._export_report)
        self.btn_report.pack(fill="x", padx=16, pady=4)

        ctk.CTkLabel(panel, text="SYSTEM", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=16, pady=(16, 4))
        self.system_info = ctk.CTkLabel(panel, text="", text_color=theme.TEXT_DIM,
                                        justify="left", wraplength=210,
                                        font=(theme.MONO_FAMILY, 10))
        self.system_info.pack(anchor="w", padx=16, pady=(0, 14))

    def _build_center(self, master) -> None:
        center = ctk.CTkFrame(master, fg_color="transparent")
        center.grid(row=0, column=1, sticky="nsew", padx=(0, 12))
        center.grid_rowconfigure(1, weight=1)
        center.grid_columnconfigure(0, weight=1)

        # ---- recent alerts
        alerts = ctk.CTkFrame(center, fg_color=theme.PANEL, corner_radius=12, height=210,
                              border_width=1, border_color=theme.BORDER)
        alerts.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        alerts.grid_propagate(False)
        ctk.CTkLabel(alerts, text="RECENT ALERTS", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
        self.alerts_frame = ctk.CTkScrollableFrame(alerts, fg_color="transparent", height=140)
        self.alerts_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        self.alert_placeholder = ctk.CTkLabel(
            self.alerts_frame, text="No alerts yet - start monitoring or run the simulation.",
            text_color=theme.TEXT_DIM, font=(theme.FONT_FAMILY, 12))
        self.alert_placeholder.pack(anchor="w", padx=8, pady=8)

        # ---- attack history
        history = ctk.CTkFrame(center, fg_color=theme.PANEL, corner_radius=12,
                               border_width=1, border_color=theme.BORDER)
        history.grid(row=1, column=0, sticky="nsew")
        history.grid_rowconfigure(1, weight=1)
        history.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(history, text="ATTACK HISTORY", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        table_wrap = tk.Frame(history, bg=theme.PANEL)
        table_wrap.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        table_wrap.grid_rowconfigure(0, weight=1)
        table_wrap.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            table_wrap, columns=[c[0] for c in HISTORY_COLUMNS], show="headings",
            style="NetHawk.Treeview", selectmode="browse")
        for key, title, width in HISTORY_COLUMNS:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "action"))
        self.tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview,
                                  style="NetHawk.Vertical.TScrollbar")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        for level, color in theme.RISK_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        self.tree.tag_configure("NORMAL", foreground=theme.TEXT_DIM)
        self.tree.bind("<<TreeviewSelect>>", self._on_select_event)

    def _build_detail(self, master) -> None:
        panel = ctk.CTkFrame(master, fg_color=theme.PANEL, corner_radius=12, width=390,
                             border_width=1, border_color=theme.BORDER)
        panel.grid(row=0, column=2, sticky="nsew")
        panel.grid_propagate(False)
        panel.grid_rowconfigure(2, weight=1)
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(panel, text="EVENT DETAIL", text_color=theme.TEXT_DIM,
                     font=(theme.FONT_FAMILY, 11, "bold")).grid(
            row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self.detail_title = ctk.CTkLabel(panel, text="Select an event",
                                         text_color=theme.TEXT, anchor="w",
                                         font=(theme.FONT_FAMILY, 17, "bold"))
        self.detail_title.grid(row=1, column=0, sticky="ew", padx=16)

        self.detail_text = ctk.CTkTextbox(panel, fg_color=theme.PANEL_ALT,
                                          text_color=theme.TEXT, wrap="word",
                                          font=(theme.MONO_FAMILY, 11), corner_radius=8)
        self.detail_text.grid(row=2, column=0, sticky="nsew", padx=12, pady=10)
        self.detail_text.insert("1.0",
                                "Click any row in ATTACK HISTORY to inspect the full "
                                "detection: features, model confidence, risk breakdown "
                                "and the response that was applied.")
        self.detail_text.configure(state="disabled")

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, fg_color=theme.PANEL, corner_radius=0, height=40)
        footer.grid(row=3, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        self.notice_label = ctk.CTkLabel(footer, text="Ready.", text_color=theme.TEXT_DIM,
                                         anchor="w", font=(theme.FONT_FAMILY, 12))
        self.notice_label.grid(row=0, column=0, sticky="w", padx=20, pady=9)
        ctk.CTkLabel(footer, text="RESPONSES ARE SIMULATED - NO REAL NETWORK ACTION",
                     text_color=theme.WARN, font=(theme.FONT_FAMILY, 11, "bold")).grid(
            row=0, column=1, sticky="e", padx=20)

    # ----------------------------------------------------------- actions ----
    def _start_monitoring(self) -> None:
        mode = self.mode_switch.get()
        self.engine.start_monitoring(mode)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self._refresh_snapshot()

    def _stop_monitoring(self) -> None:
        self.engine.stop_monitoring()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self._refresh_snapshot()

    def _run_simulation(self) -> None:
        if not self.engine.monitoring:
            self._start_monitoring()
        self.engine.run_simulation()

    def _replay_pcap(self) -> None:
        """Replay the bundled capture file through the real packet pipeline.

        The engine generates the sample capture on first use, so this works on
        a fresh clone with no preparation.
        """
        self.engine.replay_pcap()

    def _switch_mode(self, value: str) -> None:
        self.engine.switch_mode(value)
        self.mode_switch.set(self.engine.mode)
        self._refresh_snapshot()

    def _probe_capture(self) -> None:
        """Probe capture on a worker thread - capture_available() blocks ~2s."""
        self._set_notice("Probing packet capture availability...", "info")
        self.btn_probe.configure(state="disabled")

        def worker() -> None:
            try:
                status = capture_available()
                if status.available:
                    text = (f"Live capture available. Interfaces: {len(status.interfaces)}. "
                            f"Monitor mode: {'yes' if status.monitor_mode else 'no'}.")
                    level = "success"
                else:
                    text = f"{status.reason} | {platform_hint()}"
                    level = "warning"
            except Exception as exc:
                text, level = f"Capture probe failed: {exc}", "error"
            # Queue it; the Tk thread applies it. No widget is touched here.
            self._ui_results.put((text, level))

        threading.Thread(target=worker, daemon=True, name="nethawk-probe").start()

    def _probe_finished(self, text: str, level: str) -> None:
        if self._closing:
            return
        self._set_notice(text, level)
        self.btn_probe.configure(state="normal")

    def _clear_data(self) -> None:
        self.engine.clear_data()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.events.clear()
        for widget in self.alerts_frame.winfo_children():
            widget.destroy()
        self.alert_placeholder = ctk.CTkLabel(self.alerts_frame, text="Cleared.",
                                              text_color=theme.TEXT_DIM,
                                              font=(theme.FONT_FAMILY, 12))
        self.alert_placeholder.pack(anchor="w", padx=8, pady=8)
        self._refresh_snapshot()

    def _export_report(self) -> None:
        from ..utils.report import write_report
        path = write_report(self.engine.db, self.engine.predictor)
        self._set_notice(f"Report written to {path}", "success")

    # ----------------------------------------------------------- updates ----
    def _drain_queue(self) -> None:
        if self._closing:
            return
        try:
            while True:
                text, level = self._ui_results.get_nowait()
                self._probe_finished(text, level)
        except queue.Empty:
            pass
        try:
            while True:
                message: EngineMessage = self.engine.messages.get_nowait()
                self._handle_message(message)
        except queue.Empty:
            pass
        finally:
            if not self._closing:
                self._after_ids.append(self.after(200, self._drain_queue))

    def _handle_message(self, message: EngineMessage) -> None:
        if message.kind == "event":
            self._add_event(message.payload["event"])
        elif message.kind == "notice":
            self._set_notice(message.payload["text"], message.payload.get("level", "info"))
        elif message.kind == "mode":
            self.mode_pill.configure(text=message.payload["mode"])
            self.mode_switch.set(message.payload["mode"])

    def _add_event(self, event: dict) -> None:
        values = (
            event["timestamp"],
            event.get("source") or "-",
            event["attack_type"],
            f"{event['confidence'] * 100:.0f}%",
            str(event["risk_score"]),
            event["risk_level"],
            event.get("response") or "-",
            event.get("mode", MODE_DEMO),
        )
        tag = event["risk_level"] if event["prediction"] == "ATTACK" else "NORMAL"
        item = self.tree.insert("", 0, values=values, tags=(tag,))
        self.events[item] = event

        children = self.tree.get_children()
        if len(children) > MAX_HISTORY_ROWS:
            for extra in children[MAX_HISTORY_ROWS:]:
                self.events.pop(extra, None)
                self.tree.delete(extra)

        if event.get("alert") or event["risk_score"] >= config.ALERT_MIN_RISK:
            self._add_alert(event)

    def _add_alert(self, event: dict) -> None:
        if self.alert_placeholder is not None:
            self.alert_placeholder.destroy()
            self.alert_placeholder = None
        color = theme.risk_color(event["risk_level"])
        row = ctk.CTkFrame(self.alerts_frame, fg_color=theme.PANEL_ALT, corner_radius=8)
        row.pack(fill="x", padx=6, pady=3)
        ctk.CTkLabel(row, text=f"  {event['risk_level']}  ", text_color="#0b0f16",
                     fg_color=color, corner_radius=6,
                     font=(theme.FONT_FAMILY, 10, "bold")).pack(side="left", padx=8, pady=6)
        ctk.CTkLabel(row,
                     text=f"{event['attack_type']} from {event.get('source', '-')}"
                          f"  ·  risk {event['risk_score']}/100"
                          f"  ·  {event.get('response', '')}",
                     text_color=theme.TEXT, anchor="w",
                     font=(theme.FONT_FAMILY, 12)).pack(side="left", padx=4)
        ctk.CTkLabel(row, text=event["timestamp"].split(" ")[-1], text_color=theme.TEXT_DIM,
                     font=(theme.MONO_FAMILY, 10)).pack(side="right", padx=10)

        rows = [w for w in self.alerts_frame.winfo_children()]
        if len(rows) > MAX_ALERTS:
            rows[0].destroy()

    def _on_select_event(self, _event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        event = self.events.get(selection[0])
        if not event:
            return
        self.detail_title.configure(
            text=f"{event['attack_type']}  ·  {event['risk_level']}",
            text_color=theme.risk_color(event["risk_level"])
            if event["prediction"] == "ATTACK" else theme.OK)

        probabilities = event.get("probabilities") or {}
        top_probs = "\n".join(f"    {k:<18} {v * 100:5.1f}%"
                              for k, v in list(probabilities.items())[:4])
        features = event.get("features") or {}
        key_features = ["Flow Packets/s", "Flow Bytes/s", "Total Fwd Packets",
                        "Destination Port", "SYN Flag Count", "Flow Duration"]
        feature_text = "\n".join(
            f"    {name:<24} {float(features.get(name, 0)):,.2f}"
            for name in key_features if name in features)

        text = f"""DETECTION
    Event ID        #{event.get('id', '-')}
    Timestamp       {event['timestamp']}
    Mode            {event.get('mode')}
    Source          {event.get('source')}
    Destination     {event.get('destination')}
    Protocol        {event.get('protocol')}

CLASSIFICATION
    Prediction      {event['prediction']}
    Attack type     {event['attack_type']}
    Confidence      {event['confidence'] * 100:.1f}%
    Meaning         {event.get('category_description', '')}

MODEL PROBABILITIES
{top_probs or '    n/a'}

RISK SCORE  {event['risk_score']}/100  ({event['risk_level']})
    {event.get('explanation', '')}

RESPONSE
    Action          {event.get('response_action')}
    Applied         {event.get('response')}
    Why             {event.get('response_rationale', '')}

KEY FEATURES
{feature_text or '    n/a'}
"""
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def _set_notice(self, text: str, level: str = "info") -> None:
        self.notice_label.configure(text=text, text_color=theme.LEVEL_COLORS.get(level, theme.TEXT_DIM))

    def _refresh_snapshot(self) -> None:
        if self._closing:
            return
        snap = self.engine.snapshot()
        self.card_devices.update_value(snap["devices"], "seen on the monitored network")
        self.card_packets.update_value(f"{snap['packets']:,}", "analysed this session")
        self.card_threats.update_value(snap["threats"],
                                       f"{snap['high_risk']} high-risk",
                                       theme.DANGER if snap["threats"] else theme.OK)

        risk = snap["avg_attack_risk"]
        level = "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW"
        self.card_risk.update_value(level, f"avg attack risk {risk}/100", theme.risk_color(level))
        self.risk_bar.set(min(1.0, risk / 100))
        self.risk_bar.configure(progress_color=theme.risk_color(level))

        self.status_pill.configure(
            text="MONITORING" if snap["monitoring"] else "IDLE",
            text_color=theme.OK if snap["monitoring"] else theme.TEXT_DIM)
        self.mode_pill.configure(text=snap["mode"])
        self.model_pill.configure(
            text="DEMO DATA" if snap["is_demo_model"] else "CIC-IDS2017",
            text_color=theme.WARN if snap["is_demo_model"] else theme.OK)
        self.system_info.configure(
            text=(f"model: RandomForest\n"
                  f"trained on:\n  {self.engine.predictor.data_source}\n"
                  f"events logged: {snap['events']}\n"
                  f"db: database/nethawk.db"))
        self.btn_start.configure(state="disabled" if snap["monitoring"] else "normal")
        self.btn_stop.configure(state="normal" if snap["monitoring"] else "disabled")
        if not self._closing:
            self._after_ids.append(self.after(1500, self._refresh_snapshot))

    def _load_history_from_db(self) -> None:
        """Repopulate the table from SQLite so history survives a restart."""
        for row in reversed(self.engine.db.recent_events(limit=120)):
            event = dict(row)
            event["alert"] = False
            # events.features_json is stored by the engine; rehydrate it so the
            # detail panel works for history reloaded after a restart.
            try:
                event["features"] = json.loads(event.get("features_json") or "{}")
            except (TypeError, ValueError):
                event["features"] = {}
            event["response_action"] = (event.get("response") or "").split(" ")[0]
            event["response_rationale"] = (
                "Reloaded from the event history in SQLite.")
            event["category_description"] = describe(event["attack_type"])
            item = self.tree.insert("", 0, values=(
                event["timestamp"], event.get("source") or "-", event["attack_type"],
                f"{event['confidence'] * 100:.0f}%", str(event["risk_score"]),
                event["risk_level"], event.get("response") or "-", event.get("mode", MODE_DEMO),
            ), tags=(event["risk_level"] if event["prediction"] == "ATTACK" else "NORMAL",))
            self.events[item] = event

    def _on_close(self) -> None:
        """Stop the engine, cancel pending Tk callbacks, then tear down.

        Idempotent: closing an already-closed window (double click on the close
        button, or a test that closes explicitly before teardown) must not raise.
        """
        if self._closing:
            return
        self._closing = True
        for after_id in self._after_ids:
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        self._after_ids.clear()
        try:
            self.engine.stop_monitoring()
        finally:
            try:
                self.destroy()
            except Exception:
                pass            # interpreter already torn down


def launch(mode: str = MODE_DEMO, autostart: bool = True,
           engine: NetHawkEngine | None = None,
           interface: str | None = None,
           bpf_filter: str | None = None) -> None:
    if engine is None:
        engine = NetHawkEngine(mode=mode, interface=interface, bpf_filter=bpf_filter)
    app = NetHawkDashboard(engine=engine, start_mode=mode, autostart=autostart)
    app.mainloop()
