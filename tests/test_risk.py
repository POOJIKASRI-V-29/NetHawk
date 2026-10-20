"""Risk scoring: bounds, ordering, banding and the intensity damping rule."""
import pytest

from nethawk.risk.scoring import RiskResult, risk_level, score_event, traffic_intensity

LOW_TRAFFIC = {"Flow Packets/s": 5, "Flow Bytes/s": 2_000,
               "Total Fwd Packets": 20, "Total Backward Packets": 20}
FLOOD = {"Flow Packets/s": 8_000, "Flow Bytes/s": 4_000_000,
         "Total Fwd Packets": 3_000, "Total Backward Packets": 10}


def test_normal_traffic_scores_zero():
    result = score_event("Normal", 0.99, LOW_TRAFFIC)
    assert result.score == 0 and result.level == "LOW"


def test_score_is_bounded():
    for confidence in (0.0, 0.5, 1.0):
        for category in ("DDoS", "Port Scan", "Botnet", "Other Suspicious"):
            score = score_event(category, confidence, FLOOD).score
            assert 0 <= score <= 100


def test_more_severe_category_scores_higher():
    ddos = score_event("DDoS", 0.9, FLOOD).score
    scan = score_event("Port Scan", 0.9, FLOOD).score
    assert ddos > scan


def test_higher_confidence_scores_higher():
    low = score_event("DoS", 0.4, LOW_TRAFFIC).score
    high = score_event("DoS", 1.0, LOW_TRAFFIC).score
    assert high > low


def test_flood_scores_higher_than_quiet_traffic():
    assert score_event("DoS", 0.9, FLOOD).score > score_event("DoS", 0.9, LOW_TRAFFIC).score


@pytest.mark.parametrize("score,expected", [
    (0, "LOW"), (39, "LOW"), (40, "MEDIUM"), (69, "MEDIUM"), (70, "HIGH"), (100, "HIGH")])
def test_banding(score, expected):
    assert risk_level(score) == expected


def test_intensity_is_damped_for_tiny_flows():
    """A 2-packet flow must not count as a sustained flood."""
    tiny = {"Flow Packets/s": 9_000, "Flow Bytes/s": 500_000,
            "Total Fwd Packets": 2, "Total Backward Packets": 0}
    sustained = dict(tiny, **{"Total Fwd Packets": 500, "Total Backward Packets": 100})
    assert traffic_intensity(tiny) < traffic_intensity(sustained)


def test_explanation_is_human_readable():
    result = score_event("DDoS", 0.95, FLOOD)
    assert isinstance(result, RiskResult)
    assert "severity" in result.explanation and "risk" in result.explanation
    assert set(result.components) == {"severity", "confidence", "intensity"}
