
from unittest.mock import patch, Mock

from core.threat_intel import (
    check_domain,
    validate_domain
)


def test_valid_domain():
    assert validate_domain("google.com") is True


def test_invalid_sample_domain():
    assert validate_domain(
        "login-check.example"
    ) is False


def test_invalid_ip():
    assert validate_domain("192.0.2.10") is False


def test_missing_api_key():
    with patch.dict("os.environ", {}, clear=True):
        result = check_domain("google.com")

    assert result["status"] == "not_configured"


@patch("core.threat_intel.requests.get")
def test_domain_report(mock_get):
    response = Mock()

    response.status_code = 200
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 20
                }
            }
        }
    }

    mock_get.return_value = response

    result = check_domain(
        "google.com",
        api_key="fake-test-key"
    )

    assert result["status"] == "found"
    assert result["malicious"] == 3
    assert result["suspicious"] == 2


@patch("core.threat_intel.requests.get")
def test_rate_limit(mock_get):
    response = Mock()
    response.status_code = 429

    mock_get.return_value = response

    result = check_domain(
        "google.com",
        api_key="fake-test-key"
    )

    assert result["status"] == "rate_limited"


@patch("core.threat_intel.requests.get")
def test_unknown_domain(mock_get):
    response = Mock()
    response.status_code = 404

    mock_get.return_value = response

    result = check_domain(
        "google.com",
        api_key="fake-test-key"
    )

    assert result["status"] == "unknown"
