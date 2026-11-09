
import os
import ipaddress

import requests


VT_API_URL = "https://www.virustotal.com/api/v3"


def validate_domain(domain):
    """
    Validate a domain before querying VirusTotal.
    Reject reserved sample domains.
    """
    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        return False

    if domain.endswith(
        (".example", ".invalid", ".test", ".localhost")
    ):
        return False

    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

        if not all(
            char.isascii()
            and (char.isalnum() or char == "-")
            for char in label
        ):
            return False

    return True


def check_domain(domain, api_key=None):
    """
    Retrieve an existing VirusTotal domain report.

    No file upload, URL submission or rescan.
    """
    domain = str(domain).strip().lower().rstrip("")

    # Normalize a trailing dot, if present.
    domain = domain.rstrip(".")

    if not validate_domain(domain):
        return {
            "domain": domain,
            "status": "invalid",
            "message": "Invalid or reserved sample domain."
        }

    key = api_key or os.getenv("VIRUSTOTAL_API_KEY")

    if not key:
        return {
            "domain": domain,
            "status": "not_configured",
            "message": "VirusTotal API key is missing."
        }

    headers = {
        "x-apikey": key,
        "accept": "application/json"
    }

    try:
        response = requests.get(
            f"{VT_API_URL}/domains/{domain}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            return {
                "domain": domain,
                "status": "unknown",
                "message": "No existing domain report."
            }

        if response.status_code == 429:
            return {
                "domain": domain,
                "status": "rate_limited",
                "message": "VirusTotal API quota exceeded."
            }

        if response.status_code in (401, 403):
            return {
                "domain": domain,
                "status": "auth_error",
                "message": "API key or permissions rejected."
            }

        response.raise_for_status()

        data = response.json()
        attributes = data["data"]["attributes"]

        stats = attributes.get(
            "last_analysis_stats", {}
        )

        return {
            "domain": domain,
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            )
        }

    except (requests.RequestException, ValueError,
            KeyError, TypeError) as exc:
        return {
            "domain": domain,
            "status": "error",
            "message": type(exc).__name__
        }
