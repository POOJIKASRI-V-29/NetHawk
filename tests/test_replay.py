"""PCAP replay: the real Scapy packet path, verified without privileges.

These tests parse genuine, well-formed Ethernet/IP/TCP/UDP frames written to a
capture file, so they exercise exactly the code LIVE mode runs - dissection,
flow assembly, micro-flow aggregation, feature extraction and prediction.
"""
import pytest

from nethawk.capture.flows import Flow, FlowTable, aggregate_micro_flows
from nethawk.capture.replay import PcapReplay
from nethawk.database.db import Database
from nethawk.engine import NetHawkEngine
from nethawk.schema import FEATURE_NAMES, MODE_REPLAY

scapy = pytest.importorskip("scapy.all")


@pytest.fixture(scope="module")
def sample_pcap(tmp_path_factory):
    """Build a capture file in memory and write it to disk - nothing is sent."""
    from nethawk.capture.sample import write_sample_pcap

    path, count = write_sample_pcap(tmp_path_factory.mktemp("pcap") / "sample.pcap")
    assert count > 500
    return path


def test_sample_pcap_is_readable(sample_pcap):
    packets = scapy.rdpcap(str(sample_pcap))
    assert len(packets) > 500
    assert packets[0].haslayer(scapy.IP)


def test_replay_parses_packets_and_builds_flows(sample_pcap):
    flows = []
    replay = PcapReplay(on_flow=flows.append, path=sample_pcap)
    assert replay.available()
    replay.read_all()
    assert replay.packet_count > 500          # real packets parsed by Scapy
    assert flows                               # real flows assembled
    assert all(isinstance(f, Flow) for f in flows)


def test_replay_features_match_the_model_schema(sample_pcap):
    from nethawk.features.adapters import LiveTrafficFeatureAdapter

    flows = []
    PcapReplay(on_flow=flows.append, path=sample_pcap).read_all()
    features = LiveTrafficFeatureAdapter().extract_features(flows[0])
    assert set(features) == set(FEATURE_NAMES)


def test_replay_through_the_engine_detects_the_flood(tmp_path, sample_pcap):
    engine = NetHawkEngine(database=Database(tmp_path / "replay.db"))
    events = []
    engine.on_message = lambda m: (events.append(m.payload["event"])
                                   if m.kind == "event" else None)
    analysed = engine.replay_pcap(sample_pcap, blocking=True)

    assert analysed > 0
    assert all(e["mode"] == MODE_REPLAY for e in events)
    # the 900-packet SYN flood must be detected as a high-rate flood
    floods = [e for e in events
              if e["features"]["Total Fwd Packets"] > 500]
    assert len(floods) == 1, "the flood should collapse into one aggregated flow"
    assert floods[0]["attack_type"] in ("DoS", "DDoS")
    assert floods[0]["risk_level"] == "HIGH"
    # the scan must stay a scan (many separate small flows, not one big one)
    scans = [e for e in events if e["attack_type"] == "Port Scan"]
    assert len(scans) >= 10
    # everything persisted
    assert engine.db.event_counts()["total"] == len(events)


def test_missing_pcap_is_reported_not_raised(tmp_path):
    engine = NetHawkEngine(database=Database(tmp_path / "x.db"))
    notices = []
    engine.on_message = lambda m: (notices.append(m.payload["text"])
                                   if m.kind == "notice" else None)
    assert engine.replay_pcap(tmp_path / "nope.pcap", blocking=True) == 0
    assert any("not found" in n for n in notices)


def test_ipv6_packets_are_handled():
    """Modern macOS traffic is frequently IPv6 - the handler must accept it."""
    from nethawk.capture.live import LiveCapture

    flows = []
    capture = LiveCapture(on_flow=flows.append)
    packet = (scapy.Ether() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
              / scapy.TCP(sport=51000, dport=443, flags="PA") / scapy.Raw(b"x" * 100))
    packet.time = 1_700_000_000.0
    capture._handle_packet(packet)
    assert capture.packet_count == 1
    flow = next(iter(capture.table.flows.values()))
    assert flow.src == "2001:db8::1" and flow.dport == 443


def test_non_ip_packets_are_ignored():
    from nethawk.capture.live import LiveCapture

    capture = LiveCapture(on_flow=lambda f: None)
    capture._handle_packet(scapy.Ether() / scapy.ARP())
    assert capture.packet_count == 0


# --------------------------------------------------- micro-flow aggregation --
def _micro(src, dst, dport, sport, packets=1):
    flow = Flow(src=src, dst=dst, sport=sport, dport=dport, protocol="TCP",
                start=1000.0, last_seen=1000.0 + 0.0003 * packets)
    for i in range(packets):
        flow.add(60, True, 1000.0 + 0.0003 * i, {"SYN": 1})
    return flow


def test_flood_micro_flows_are_merged():
    flows = [_micro("10.0.0.9", "10.0.0.1", 80, 1024 + i) for i in range(40)]
    merged = aggregate_micro_flows(flows)
    assert len(merged) == 1
    assert merged[0].packet_count == 40
    assert merged[0].aggregated == 40
    assert merged[0].dport == 80


def test_scan_micro_flows_are_left_alone():
    """One flow per port across many ports must NOT be merged into a flood."""
    flows = [_micro("10.0.0.9", "10.0.0.1", port, 50000 + i)
             for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 443, 445, 3389])]
    merged = aggregate_micro_flows(flows)
    assert len(merged) == 10
    assert all(f.aggregated == 0 for f in merged)


def test_normal_conversations_are_never_merged():
    flows = [_micro("10.0.0.5", "10.0.0.1", 443, 51000 + i, packets=20) for i in range(8)]
    merged = aggregate_micro_flows(flows)
    assert len(merged) == 8


def test_aggregation_preserves_packet_and_flag_totals():
    flows = [_micro("10.0.0.9", "10.0.0.1", 80, 1024 + i, packets=2) for i in range(12)]
    merged = aggregate_micro_flows(flows)
    assert len(merged) == 1
    assert merged[0].packet_count == 24
    assert merged[0].flags["SYN"] == 24

def test_replay_emits_wifi_management_frame_alert(tmp_path):
    """Replay alerts on repeated deauthentication frames in an offline PCAP."""
    from scapy.all import Dot11, Dot11Deauth, wrpcap

    path = tmp_path / "wifi-management.pcap"
    packets = []
    for timestamp in (1000.0, 1001.0):
        packet = (
            Dot11(
                type=0,
                subtype=12,
                addr1="00:11:22:33:44:55",
                addr2="66:77:88:99:aa:bb",
                addr3="00:11:22:33:44:55",
            )
            / Dot11Deauth(reason=7)
        )
        packet.time = timestamp
        packets.append(packet)

    wrpcap(str(path), packets)
    alerts = []
    replay = PcapReplay(
        on_flow=lambda flow: None,
        path=path,
        on_wifi_alert=alerts.append,
        wifi_threshold=2,
        wifi_window_seconds=5.0,
    )

    replay.read_all()

    assert len(alerts) == 1
    assert alerts[0].kind == "deauthentication"
    assert alerts[0].count == 2
def test_engine_emits_wifi_deauthentication_notice(tmp_path):
    """Offline Wi-Fi management frames should reach the engine notice channel."""
    from scapy.all import Dot11, Dot11Deauth, RadioTap, wrpcap

    path = tmp_path / "wifi_deauth.pcap"
    packets = []
    for i in range(10):
        packet = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:11:22:33:44:55",
                addr3="00:11:22:33:44:55",
            )
            / Dot11Deauth(reason=7)
        )
        packet.time = 1_700_000_000.0 + i * 0.1
        packets.append(packet)

    wrpcap(str(path), packets)

    engine = NetHawkEngine(database=Database(tmp_path / "wifi.db"))
    notices = []
    engine.on_message = lambda m: (
        notices.append(m.payload["text"]) if m.kind == "notice" else None
    )

    engine.replay_pcap(path, blocking=True)

    assert any("deauthentication" in notice.lower() for notice in notices), notices
