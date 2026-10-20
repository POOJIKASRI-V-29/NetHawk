"""Transparent, deterministic risk scoring.

    risk = 0.50 * severity(category)
         + 0.30 * (model confidence * 100)
         + 0.20 * traffic intensity (0-100)

Every term is bounded 0-100, so the result is bounded 0-100 as well.  Normal
traffic is forced to 0.  The scorer also returns the individual contributions
so the dashboard (and the viva answer) can show *why* a score came out.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..schema import (
    CATEGORY_NORMAL,
    CATEGORY_SEVERITY,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
)

W_SEVERITY = 0.50
W_CONFIDENCE = 0.30
W_INTENSITY = 0.20

# Reference points for normalising traffic intensity onto 0-100.
REF_PACKETS_PER_SEC = 2000.0
REF_BYTES_PER_SEC = 2_000_000.0
# Below this many packets a flow rate is not treated as sustained load.
MIN_PACKETS_FOR_FULL_INTENSITY = 10.0


@dataclass
class RiskResult:
    score: int
    level: str
    explanation: str
    components: dict[str, float] = field(default_factory=dict)


def _finite(value: object) -> float:
    """Coerce a feature value to a finite, non-negative float.

    NaN and infinity must not reach the score.  Before this guard a record of
    NaN rates produced intensity 100 - i.e. missing data looked exactly like a
    maximum-rate flood - because NaN silently won the min()/max() comparisons.
    """
    try:
        number = float(value)                       # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(number) or number < 0.0:
        return 0.0
    return number


def traffic_intensity(features: dict) -> float:
    """Normalise packet-rate and byte-rate into a single 0-100 intensity term.

    A logarithmic scale is used because flood traffic is orders of magnitude
    above normal traffic; a linear scale would saturate immediately.
    """
    features = features or {}
    pps = _finite(features.get("Flow Packets/s"))
    bps = _finite(features.get("Flow Bytes/s"))
    pps_term = math.log10(1.0 + pps) / math.log10(1.0 + REF_PACKETS_PER_SEC)
    bps_term = math.log10(1.0 + bps) / math.log10(1.0 + REF_BYTES_PER_SEC)
    intensity = 100.0 * max(0.0, min(1.0, 0.6 * pps_term + 0.4 * bps_term))

    # A rate computed over one or two packets is not a sustained load: a
    # 2-packet scan flow lasting 200 microseconds reports thousands of
    # packets/s.  Damp the term until the flow is long enough to mean it.
    packets = (_finite(features.get("Total Fwd Packets"))
               + _finite(features.get("Total Backward Packets")))
    if packets < MIN_PACKETS_FOR_FULL_INTENSITY:
        intensity *= packets / MIN_PACKETS_FOR_FULL_INTENSITY
    return round(intensity, 2)


def risk_level(score: int) -> str:
    if score >= 70:
        return RISK_HIGH
    if score >= 40:
        return RISK_MEDIUM
    return RISK_LOW


def score_event(category: str, confidence: float, features: dict) -> RiskResult:
    """Compute the risk score for one classified traffic record."""
    confidence = float(max(0.0, min(1.0, confidence)))
    severity = float(CATEGORY_SEVERITY.get(category, 45))
    intensity = traffic_intensity(features or {})

    if category == CATEGORY_NORMAL:
        return RiskResult(
            score=0,
            level=RISK_LOW,
            explanation="Classified as Normal traffic - no risk contribution applied.",
            components={"severity": 0.0, "confidence": round(confidence * 100, 2),
                        "intensity": intensity},
        )

    raw = (W_SEVERITY * severity
           + W_CONFIDENCE * (confidence * 100.0)
           + W_INTENSITY * intensity)
    score = int(round(max(0.0, min(100.0, raw))))
    level = risk_level(score)

    explanation = (
        f"severity({category})={severity:.0f} x {W_SEVERITY:.2f} = {W_SEVERITY * severity:.1f}  |  "
        f"confidence={confidence * 100:.1f} x {W_CONFIDENCE:.2f} = {W_CONFIDENCE * confidence * 100:.1f}  |  "
        f"intensity={intensity:.1f} x {W_INTENSITY:.2f} = {W_INTENSITY * intensity:.1f}  "
        f"=> risk {score}/100 ({level})"
    )
    return RiskResult(
        score=score,
        level=level,
        explanation=explanation,
        components={
            "severity": severity,
            "confidence": round(confidence * 100, 2),
            "intensity": intensity,
        },
    )
