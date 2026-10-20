"""Attack classification layer.

This layer is deliberately independent of the ML model: the model predicts a
raw label (whatever string the training data used), and this module normalises
that label into one of NetHawk's canonical categories.  Swapping CIC-IDS2017
for AWID3 later only means extending the rules below - nothing else changes.
"""
from __future__ import annotations

import re

from ..schema import (
    ATTACK_CATEGORIES,
    BINARY_ATTACK,
    BINARY_NORMAL,
    CATEGORY_BOTNET,
    CATEGORY_BRUTE_FORCE,
    CATEGORY_DDOS,
    CATEGORY_DOS,
    CATEGORY_DESCRIPTION,
    CATEGORY_NORMAL,
    CATEGORY_OTHER,
    CATEGORY_PORT_SCAN,
    CATEGORY_WEB_ATTACK,
)

# Ordered rules: first matching pattern wins.  DDoS is checked before DoS
# because "DDoS" contains "DoS".
_RULES: list[tuple[str, str]] = [
    (r"^\s*(benign|normal|background)\s*$", CATEGORY_NORMAL),
    (r"ddos", CATEGORY_DDOS),
    (r"\bdos\b|hulk|goldeneye|slowloris|slowhttptest|heartbleed", CATEGORY_DOS),
    (r"portscan|port scan|\bscan\b|nmap|reconnaissance", CATEGORY_PORT_SCAN),
    (r"web.?attack|sql.?injection|xss|\bsqli\b", CATEGORY_WEB_ATTACK),
    (r"brute.?force|patator|ssh-?patator|ftp-?patator|password", CATEGORY_BRUTE_FORCE),
    (r"\bbot\b|botnet|ares|command.?and.?control|\bc2\b", CATEGORY_BOTNET),
    (r"infiltration|deauth|disassoc|evil.?twin|rogue|impersonation|injection", CATEGORY_OTHER),
]


def normalize_label(raw_label: object) -> str:
    """Map any raw dataset/model label onto a canonical NetHawk category."""
    if raw_label is None:
        return CATEGORY_OTHER
    text = str(raw_label).strip()
    if not text:
        return CATEGORY_OTHER
    # Already canonical?
    for category in ATTACK_CATEGORIES:
        if text.lower() == category.lower():
            return category
    lowered = text.lower().replace("\x96", "-").replace("_", " ")
    for pattern, category in _RULES:
        if re.search(pattern, lowered):
            return category
    return CATEGORY_OTHER


def to_binary(category: str) -> str:
    """NORMAL vs ATTACK from a canonical category."""
    return BINARY_NORMAL if category == CATEGORY_NORMAL else BINARY_ATTACK


def describe(category: str) -> str:
    return CATEGORY_DESCRIPTION.get(category, CATEGORY_DESCRIPTION[CATEGORY_OTHER])


def is_attack(category: str) -> bool:
    return category != CATEGORY_NORMAL
