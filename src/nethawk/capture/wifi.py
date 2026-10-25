"""Defensive parsing of captured Wi-Fi management frames."""

from collections import defaultdict, deque
from dataclasses import dataclass
from time import time
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas


@dataclass(frozen=True)
class ManagementFrameEvent:
    kind: str
    source: Optional[str]
    destination: Optional[str]
    bssid: Optional[str]
    timestamp: float
    reason_code: Optional[int] = None


@dataclass(frozen=True)
class ManagementFrameAlert:
    kind: str
    bssid: str
    count: int
    window_seconds: float
    message: str


def parse_management_frame(packet) -> Optional[ManagementFrameEvent]:
    """Parse deauthentication/disassociation frames; ignore other packets."""
    try:
        if not packet.haslayer(Dot11):
            return None

        frame = packet.getlayer(Dot11)
        if frame.type != 0:
            return None

        if frame.subtype == 12 and packet.haslayer(Dot11Deauth):
            kind = "deauthentication"
            reason_layer = packet.getlayer(Dot11Deauth)
        elif frame.subtype == 10 and packet.haslayer(Dot11Disas):
            kind = "disassociation"
            reason_layer = packet.getlayer(Dot11Disas)
        else:
            return None

        return ManagementFrameEvent(
            kind=kind,
            source=frame.addr2,
            destination=frame.addr1,
            bssid=frame.addr3,
            timestamp=float(getattr(packet, "time", time())),
            reason_code=getattr(reason_layer, "reason", None),
        )
    except (AttributeError, TypeError, ValueError, IndexError):
        return None


class ManagementFrameDetector:
    """Heuristic alerting for repeated management frames within a time window."""

    def __init__(self, threshold: int = 10, window_seconds: float = 5.0):
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.threshold = threshold
        self.window_seconds = float(window_seconds)
        self._events = defaultdict(deque)

    def observe(self, packet) -> Optional[ManagementFrameAlert]:
        event = parse_management_frame(packet)
        if event is None or not event.bssid:
            return None

        key = (event.kind, event.bssid.lower())
        events = self._events[key]
        cutoff = event.timestamp - self.window_seconds

        while events and events[0] < cutoff:
            events.popleft()

        events.append(event.timestamp)

        if len(events) == self.threshold:
            return ManagementFrameAlert(
                kind=event.kind,
                bssid=event.bssid,
                count=len(events),
                window_seconds=self.window_seconds,
                message=(
                    f"High rate of {event.kind} frames for BSSID "
                    f"{event.bssid}: {len(events)} in "
                    f"{self.window_seconds:g} seconds. Investigate."
                ),
            )

        return None
