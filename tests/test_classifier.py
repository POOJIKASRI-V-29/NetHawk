"""Label normalisation: raw dataset labels -> canonical NetHawk categories."""
import pytest

from nethawk.detection.classifier import describe, is_attack, normalize_label, to_binary
from nethawk.schema import ATTACK_CATEGORIES


@pytest.mark.parametrize("raw,expected", [
    ("BENIGN", "Normal"),
    ("  benign  ", "Normal"),
    ("Normal", "Normal"),
    ("DoS Hulk", "DoS"),
    ("DoS GoldenEye", "DoS"),
    ("DoS slowloris", "DoS"),
    ("Heartbleed", "DoS"),
    ("DDoS", "DDoS"),
    ("PortScan", "Port Scan"),
    ("FTP-Patator", "Brute Force"),
    ("SSH-Patator", "Brute Force"),
    ("Bot", "Botnet"),
    ("Web Attack – Brute Force", "Web Attack"),
    ("Web Attack - Sql Injection", "Web Attack"),
    ("Web Attack - XSS", "Web Attack"),
    ("Infiltration", "Other Suspicious"),
    ("Deauthentication", "Other Suspicious"),
    ("something-unseen", "Other Suspicious"),
])
def test_normalize_label(raw, expected):
    assert normalize_label(raw) == expected


def test_every_category_is_known():
    for raw in ["BENIGN", "DDoS", "PortScan", "Bot", "weird"]:
        assert normalize_label(raw) in ATTACK_CATEGORIES


def test_binary_mapping():
    assert to_binary(normalize_label("BENIGN")) == "NORMAL"
    assert to_binary(normalize_label("DDoS")) == "ATTACK"
    assert is_attack("DoS") and not is_attack("Normal")


def test_none_and_empty_are_not_crashes():
    assert normalize_label(None) == "Other Suspicious"
    assert normalize_label("") == "Other Suspicious"


def test_describe_returns_text_for_every_category():
    for category in ATTACK_CATEGORIES:
        assert len(describe(category)) > 10
