from pathlib import Path

from core.email_parser import parse_email
from core.detection_rules import detect_phishing


SAMPLES = Path("data/samples")


def load_sample(filename):
    raw = (SAMPLES / filename).read_bytes()
    return parse_email(raw)


def test_phishing_detection():
    email_data = load_sample("phishing_01.eml")

    findings = detect_phishing(email_data)

    rule_ids = [
        finding["rule_id"]
        for finding in findings
    ]

    assert "R001" in rule_ids
    assert "R002" in rule_ids
    assert "R003" in rule_ids


def test_legitimate_email():
    email_data = load_sample("legitimate_01.eml")

    findings = detect_phishing(email_data)

    assert findings == []


def test_attachment_detection():
    email_data = load_sample("attachment_01.eml")

    findings = detect_phishing(email_data)

    # The sample only contains a harmless .txt file
    assert not any(
        finding["rule_id"] == "R005"
        for finding in findings
    )


def test_suspicious_attachment():
    email_data = {
        "subject": "Document",
        "from": "sender@example.com",
        "reply_to": "",
        "body_text": "",
        "body_html": "",
        "iocs": {
            "urls": [],
            "link_mismatches": []
        },
        "attachments": [
            {"filename": "invoice.exe"}
        ]
    }

    findings = detect_phishing(email_data)

    rule_ids = [
        finding["rule_id"]
        for finding in findings
    ]

    assert "R005" in rule_ids


def test_ip_address_url():
    email_data = {
        "subject": "Check this link",
        "from": "sender@example.com",
        "reply_to": "",
        "body_text": "",
        "body_html": "",
        "iocs": {
            "urls": ["http://192.0.2.10/login"],
            "link_mismatches": []
        },
        "attachments": []
    }

    findings = detect_phishing(email_data)

    rule_ids = [
        finding["rule_id"]
        for finding in findings
    ]

    assert "R004" in rule_ids
