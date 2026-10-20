"""PCAP replay - the third traffic source (Mode 3).

Why this exists
---------------
Live capture needs root on every OS, so on a normal laptop the Scapy
packet-parsing path cannot be exercised at all.  Replaying a capture file uses
*the same* Scapy sniffing machinery (`sniff(offline=...)`), the same packet
dissection, the same flow assembler and the same feature adapter as LIVE mode -
but reads frames from a file instead of a network interface, which needs no
privileges whatsoever.

That makes the real packet pipeline verifiable, and it matches the "packet
capture **or replay**" stage of the NetHawk design.

Nothing is transmitted: replay only reads a file.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable

from .flows import Flow, aggregate_micro_flows
from .live import LiveCapture


class PcapReplay(LiveCapture):
    """Feeds packets from a .pcap/.pcapng file through the live packet path."""

    def __init__(self, on_flow: Callable[[Flow], None],
                 path: Path | str,
                 flow_timeout: float | None = None,
                 on_packet: Callable[[dict], None] | None = None,
                 use_file_timestamps: bool = True) -> None:
        super().__init__(on_flow=on_flow, interface=None,
                         flow_timeout=flow_timeout, on_packet=on_packet)
        self.path = Path(path)
        self.use_file_timestamps = use_file_timestamps
        self._thread: threading.Thread | None = None
        self.finished = threading.Event()

    def available(self) -> bool:
        return self.path.exists() and self.path.stat().st_size > 0

    # ------------------------------------------------------------- reading ---
    def read_all(self) -> int:
        """Parse every packet in the file, then flush all flows. Returns flows."""
        from scapy.all import sniff

        if not self.available():
            raise FileNotFoundError(f"Capture file not found or empty: {self.path}")

        if self.path.is_dir():
            raise IsADirectoryError(f"Capture path is a directory: {self.path}")

        # store=False keeps memory flat; prn is the same handler LIVE mode uses.
        # stop_filter lets stop() interrupt a long replay instead of waiting.
        sniff(offline=str(self.path), prn=self._handle_packet, store=False,
              stop_filter=lambda _pkt: self._stop.is_set())

        flows = aggregate_micro_flows(self.table.collect_expired(force=True))
        for flow in flows:
            if flow.packet_count >= 1:
                self.on_flow(flow)
        self.finished.set()
        return len(flows)

    # ------------------------------------------------------------ control ----
    def start(self) -> bool:                      # type: ignore[override]
        """Replay in the background so a GUI stays responsive."""
        if not self.available():
            self.last_error = f"Capture file not found or empty: {self.path}"
            return False
        self.finished.clear()

        def _run() -> None:
            try:
                self.read_all()
            except Exception as exc:
                self.last_error = str(exc)
                self.finished.set()

        self._thread = threading.Thread(target=_run, daemon=True,
                                        name="nethawk-pcap-replay")
        self._thread.start()
        return True

    def stop(self) -> None:                       # type: ignore[override]
        self._stop.set()
        self.finished.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def wait(self, timeout: float = 30.0) -> bool:
        return self.finished.wait(timeout)
