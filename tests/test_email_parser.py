
from pathlib import Path

import pytest

from core.email_parser import parse_email


SAMPLES = Path("data/samples")


def load_sample(filename):
    return (SAMPLES / filename).read_bytes()


def test_phishing_email():
    raw = load_sample("phishing_01.eml")

    result = parse_email(raw)

    assert "Verify" in result["subject"]

    assert result["from_address"] == (
        "security@micros0ft.example"
    )

    assert len(result["iocs"]["urls"]) >= 1

    assert len(
        result["iocs"]["link_mismatches"]
    ) == 1


def test_legitimate_email():
    raw = load_sample("legitimate_01.eml")

    result = parse_email(raw)

    assert result["subject"] == (
        "Weekly Team Meeting"
    )

    assert len(result["iocs"]["urls"]) == 0

    assert len(result["attachments"]) == 0


def test_attachment_email():
    raw = load_sample("attachment_01.eml")

    result = parse_email(raw)

    assert len(result["attachments"]) == 1

    attachment = result["attachments"][0]

    assert attachment["filename"] == "notes.txt"

    assert len(attachment["sha256"]) == 64


def test_empty_email():
    with pytest.raises(ValueError):
        parse_email(b"")


def test_large_email():
    large_data = b"A" * (10 * 1024 * 1024 + 1)

    with pytest.raises(ValueError):
        parse_email(large_data)
