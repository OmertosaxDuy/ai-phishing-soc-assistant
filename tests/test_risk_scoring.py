from pathlib import Path

from core.email_parser import parse_email
from core.risk_scoring import (
    calculate_risk_score,
    classify_risk,
    assess_email_risk
)


def test_calculate_score():
    findings = [
        {"score": 25},
        {"score": 10},
        {"score": 10}
    ]

    assert calculate_risk_score(findings) == 45


def test_score_maximum():
    findings = [
        {"score": 60},
        {"score": 50}
    ]

    assert calculate_risk_score(findings) == 100


def test_low_risk():
    assert classify_risk(20) == "Low"


def test_medium_risk():
    assert classify_risk(45) == "Medium"


def test_high_risk():
    assert classify_risk(85) == "High"


def test_phishing_email_risk():
    path = Path("data/samples/phishing_01.eml")

    raw = path.read_bytes()
    email_data = parse_email(raw)

    assessment = assess_email_risk(email_data)

    assert assessment["risk_score"] == 45
    assert assessment["risk_level"] == "Medium"
    assert assessment["total_findings"] == 3


def test_legitimate_email_risk():
    path = Path("data/samples/legitimate_01.eml")

    raw = path.read_bytes()
    email_data = parse_email(raw)

    assessment = assess_email_risk(email_data)

    assert assessment["risk_score"] == 0
    assert assessment["risk_level"] == "Low"
    assert assessment["total_findings"] == 0
