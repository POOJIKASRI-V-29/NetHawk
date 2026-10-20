"""Decision engine and response policy.

Policy (risk level -> action):

    LOW     log the event only
    MEDIUM  log + raise a dashboard warning + flag the source device SUSPICIOUS
    HIGH    log + raise a dashboard alert + SIMULATED block of the source

SAFETY: NetHawk never touches a real network.  There is no firewall backend,
no deauthentication, no packet injection.  `enforcement_enabled` is False and
there is no code path that sets it to True, so every response is recorded with
simulated=1 and is displayed in the UI as SIMULATED.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..schema import RISK_HIGH, RISK_LOW, RISK_MEDIUM

ACTION_MONITOR = "MONITOR"
ACTION_WARN = "WARN"
ACTION_BLOCK = "BLOCK"

STATUS_TRUSTED = "TRUSTED"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_BLOCKED = "BLOCKED (SIM)"


@dataclass
class ResponseDecision:
    action: str
    label: str            # human-readable text stored in events.response
    simulated: bool
    alert: bool           # should this appear in "Recent alerts"?
    device_status: str
    rationale: str

    @property
    def display(self) -> str:
        return f"{self.label} [SIMULATED]" if self.simulated else self.label


class DecisionEngine:
    """Maps a scored detection onto a controlled response."""

    # No real enforcement backend exists in this MVP - see module docstring.
    enforcement_enabled = False

    def __init__(self, database=None) -> None:
        self.db = database

    def decide(self, risk_level: str, attack_type: str, source: str | None) -> ResponseDecision:
        if risk_level == RISK_HIGH:
            return ResponseDecision(
                action=ACTION_BLOCK,
                label=f"ALERT + BLOCK source {source or 'unknown'}",
                simulated=not self.enforcement_enabled,
                alert=True,
                device_status=STATUS_BLOCKED,
                rationale=(f"HIGH risk {attack_type}: policy raises an alert and quarantines "
                           f"the source. No real network action is performed."),
            )
        if risk_level == RISK_MEDIUM:
            return ResponseDecision(
                action=ACTION_WARN,
                label="WARN + flag source as suspicious",
                simulated=not self.enforcement_enabled,
                alert=True,
                device_status=STATUS_SUSPICIOUS,
                rationale=(f"MEDIUM risk {attack_type}: policy warns the operator and "
                           f"marks the source for closer monitoring."),
            )
        return ResponseDecision(
            action=ACTION_MONITOR,
            label="MONITOR - event logged",
            simulated=not self.enforcement_enabled,
            alert=False,
            device_status=STATUS_TRUSTED,
            rationale=f"{risk_level} risk {attack_type}: logged for history, no action taken.",
        )

    def execute(self, decision: ResponseDecision, source: str | None,
                attack_type: str, risk_score: int) -> ResponseDecision:
        """Apply the (simulated) response and persist its side effects."""
        if self.db is None or not source:
            return decision
        if decision.action == ACTION_BLOCK:
            self.db.add_to_blocklist(
                source,
                reason=f"{attack_type} (risk {risk_score})",
                simulated=decision.simulated,
            )
            self.db.upsert_device(source, packets=0, threat=False, status=STATUS_BLOCKED)
        elif decision.action == ACTION_WARN:
            self.db.upsert_device(source, packets=0, threat=False, status=STATUS_SUSPICIOUS)
        return decision
