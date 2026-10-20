"""Live packet capture (Mode 2) built on Scapy, with graceful degradation.

Capturing raw packets requires elevated privileges on every OS NetHawk targets
(on macOS: read access to /dev/bpf*, i.e. sudo).  `capture_available()` checks
this *before* monitoring starts so the application can fall back to DEMO mode
with a clear message instead of crashing.

802.11 monitor-mode capture is NOT required: NetHawk analyses IP/TCP/UDP flows
from whichever interface is available.  If a monitor-mode adapter is present,
`monitor_mode_available()` reports it, but no feature depends on it.
"""
from __future__ import annotations

import platform
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .. import config
from .flows import Flow, FlowTable, aggregate_micro_flows


@dataclass
class CaptureStatus:
    available: bool
    reason: str
    interfaces: list[str]
    privileged: bool
    monitor_mode: bool = False


def _import_scapy():
    from scapy.all import IP, IPv6, TCP, UDP, AsyncSniffer, conf, get_if_list  # noqa
    return {"AsyncSniffer": AsyncSniffer, "get_if_list": get_if_list, "conf": conf,
            "IP": IP, "IPv6": IPv6, "TCP": TCP, "UDP": UDP}


def list_interfaces() -> list[str]:
    try:
        scapy = _import_scapy()
        return [str(i) for i in scapy["get_if_list"]()]
    except Exception:
        return []


def default_interface() -> str | None:
    try:
        scapy = _import_scapy()
        return str(scapy["conf"].iface) if scapy["conf"].iface else None
    except Exception:
        return None


def monitor_mode_available() -> bool:
    """True only if Scapy reports an interface already in monitor mode."""
    try:
        from scapy.all import conf
        return bool(getattr(conf.iface, "ismonitor", False))
    except Exception:
        return False


def capture_available(interface: str | None = None, probe_timeout: float = 2.0) -> CaptureStatus:
    """Probe whether this machine can actually capture packets right now."""
    interfaces = list_interfaces()
    if not interfaces:
        return CaptureStatus(False, "Scapy is not available or found no interfaces.",
                             [], False)
    try:
        from scapy.all import sniff
        sniff(count=1, timeout=probe_timeout, iface=interface, store=False)
        return CaptureStatus(True, "Packet capture is available.", interfaces, True,
                             monitor_mode_available())
    except PermissionError as exc:
        return CaptureStatus(False, f"Permission denied: {exc}. Run with sudo for LIVE mode.",
                             interfaces, False)
    except Exception as exc:
        message = str(exc)
        if "denied" in message.lower() or "root" in message.lower() or "sudo" in message.lower():
            hint = ("Raw capture needs elevated privileges. On macOS run:  "
                    "sudo $(which python3) app.py --mode live")
            return CaptureStatus(False, f"{message.strip()} | {hint}", interfaces, False)
        return CaptureStatus(False, f"Capture probe failed: {message}", interfaces, False)


class LiveCapture:
    """Sniffs packets, assembles flows, and hands finished flows to a callback."""

    def __init__(self, on_flow: Callable[[Flow], None],
                 interface: str | None = None,
                 flow_timeout: float | None = None,
                 on_packet: Callable[[dict], None] | None = None,
                 bpf_filter: str | None = None) -> None:
        # Resolve the Scapy layer classes once.  _handle_packet runs for every
        # captured packet, so importing there would put avoidable work on the
        # hot path at thousands of packets per second.
        scapy = _import_scapy()
        self._IP = scapy["IP"]
        self._IPv6 = scapy["IPv6"]
        self._TCP = scapy["TCP"]
        self._UDP = scapy["UDP"]
        self._AsyncSniffer = scapy["AsyncSniffer"]
        self.on_flow = on_flow
        self.on_packet = on_packet
        self.interface = interface
        # Optional BPF capture filter, e.g. "tcp port 443" or "host 10.0.0.5".
        # Narrowing the filter is the right default when you only need to see
        # specific traffic: unfiltered capture sees everything on the segment.
        self.bpf_filter = bpf_filter
        self.flow_timeout = flow_timeout or config.LIVE_FLOW_TIMEOUT
        self.table = FlowTable(timeout=self.flow_timeout)
        self.packet_count = 0
        self._sniffer = None
        self._stop = threading.Event()
        self._flusher: threading.Thread | None = None
        self.last_error: str | None = None

    # -------------------------------------------------------- packet path ---
    def _handle_packet(self, packet) -> None:
        try:
            IP, IPv6, TCP, UDP = self._IP, self._IPv6, self._TCP, self._UDP
            if packet.haslayer(IP):
                ip = packet[IP]
                src, dst = ip.src, ip.dst
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                src, dst = ip.src, ip.dst
            else:
                return

            sport = dport = 0
            proto = "IP"
            flags = {}
            window = None
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                sport, dport, proto = int(tcp.sport), int(tcp.dport), "TCP"
                window = int(tcp.window)
                bits = int(tcp.flags)
                flags = {"FIN": bits & 0x01, "SYN": bits & 0x02, "RST": bits & 0x04,
                         "PSH": bits & 0x08, "ACK": bits & 0x10, "URG": bits & 0x20}
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                sport, dport, proto = int(udp.sport), int(udp.dport), "UDP"

            self.packet_count += 1
            timestamp = float(getattr(packet, "time", time.time()))
            self.table.add_packet(src, dst, sport, dport, proto, len(packet),
                                  timestamp, flags, window)
            if self.on_packet:
                self.on_packet({"src": src, "dst": dst, "protocol": proto,
                                "length": len(packet), "timestamp": timestamp})
        except Exception as exc:              # never kill the sniffer thread
            self.last_error = str(exc)

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(1.0)
            expired = aggregate_micro_flows(
                self.table.collect_expired(force=self._stop.is_set()))
            for flow in expired:
                if flow.packet_count >= 1:
                    try:
                        self.on_flow(flow)
                    except Exception as exc:
                        self.last_error = str(exc)

    # ------------------------------------------------------------ control ---
    def start(self) -> bool:
        try:
            kwargs = {"prn": self._handle_packet, "store": False,
                      "iface": self.interface}
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter
            self._sniffer = self._AsyncSniffer(**kwargs)
            self._sniffer.start()
        except Exception as exc:
            self.last_error = str(exc)
            return False
        self._stop.clear()
        self._flusher = threading.Thread(target=self._flush_loop, daemon=True,
                                         name="nethawk-flow-flusher")
        self._flusher.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._flusher is not None:
            self._flusher.join(timeout=2.0)
            self._flusher = None


def platform_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return "macOS: LIVE mode needs sudo (BPF devices are root-owned)."
    if system == "Linux":
        return "Linux: LIVE mode needs sudo or CAP_NET_RAW on the Python binary."
    if system == "Windows":
        return "Windows: LIVE mode needs Npcap installed and an elevated prompt."
    return "LIVE mode needs elevated privileges for raw packet capture."
