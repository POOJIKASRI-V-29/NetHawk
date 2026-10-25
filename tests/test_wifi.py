import pytest

pytest.importorskip("scapy.layers.dot11")

from scapy.layers.dot11 import (
    Dot11,
    Dot11Deauth,
    Dot11Disas,
    Dot11Beacon,
    RadioTap,
)

from nethawk.capture.wifi import (
    ManagementFrameDetector,
    parse_management_frame,
)

BSSID = "02:11:22:33:44:55"
CLIENT = "02:aa:bb:cc:dd:ee"


def deauth_packet(timestamp):
    packet = (
        RadioTap()
        / Dot11(
            type=0, subtype=12,
            addr1=CLIENT, addr2=BSSID, addr3=BSSID,
        )
        / Dot11Deauth(reason=7)
    )
    packet.time = timestamp
    return packet


def disassociation_packet(timestamp):
    packet = (
        RadioTap()
        / Dot11(
            type=0, subtype=10,
            addr1=CLIENT, addr2=BSSID, addr3=BSSID,
        )
        / Dot11Disas(reason=8)
    )
    packet.time = timestamp
    return packet


def test_parses_deauthentication_frame():
    event = parse_management_frame(deauth_packet(100.0))
    assert event is not None
    assert event.kind == "deauthentication"
    assert event.source == BSSID
    assert event.destination == CLIENT
    assert event.bssid == BSSID
    assert event.reason_code == 7


def test_parses_disassociation_frame():
    event = parse_management_frame(disassociation_packet(100.0))
    assert event is not None
    assert event.kind == "disassociation"
    assert event.reason_code == 8


def test_ignores_beacon_frame():
    packet = (
        RadioTap()
        / Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=BSSID, addr3=BSSID,
        )
        / Dot11Beacon()
    )
    assert parse_management_frame(packet) is None


def test_ignores_non_wifi_packet():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    assert parse_management_frame(Ether() / IP() / TCP()) is None


def test_alerts_when_threshold_is_reached():
    detector = ManagementFrameDetector(threshold=3, window_seconds=5)

    assert detector.observe(deauth_packet(100.0)) is None
    assert detector.observe(deauth_packet(101.0)) is None

    alert = detector.observe(deauth_packet(102.0))
    assert alert is not None
    assert alert.kind == "deauthentication"
    assert alert.count == 3
    assert BSSID in alert.message


def test_does_not_alert_below_threshold():
    detector = ManagementFrameDetector(threshold=3, window_seconds=5)

    assert detector.observe(deauth_packet(100.0)) is None
    assert detector.observe(deauth_packet(101.0)) is None


def test_expires_old_events():
    detector = ManagementFrameDetector(threshold=3, window_seconds=5)

    detector.observe(deauth_packet(100.0))
    detector.observe(deauth_packet(101.0))
    assert detector.observe(deauth_packet(106.5)) is None


def test_invalid_detector_settings():
    with pytest.raises(ValueError):
        ManagementFrameDetector(threshold=0)

    with pytest.raises(ValueError):
        ManagementFrameDetector(window_seconds=0)
