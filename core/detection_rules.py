import ipaddress
import re

from email.utils import parseaddr
from urllib.parse import urlsplit


# Suspicious words commonly found in phishing emails
URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "account suspended",
    "account suspension",
    "account disabled",
    "verify your account",
    "password expired",
    "action required",
]

# Attachment extensions that deserve additional review
SUSPICIOUS_EXTENSIONS = (
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
)


def get_email_domain(address):
    """
    Extract domain from an email address.

    Example:
    support@example.com -> example.com
    """
    email_address = parseaddr(address or "")[1]

    if "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


def add_finding(findings, rule_id, description, score):
    """
    Add a detection finding.
    """
    findings.append({
        "rule_id": rule_id,
        "description": description,
        "score": score
    })


def detect_phishing(email_data):
    """
    Analyze parsed email data and return
    a list of suspicious findings.

    This function does not make network requests.
    """
    findings = []

    iocs = email_data.get("iocs", {})

    # RULE 1: Hyperlink mismatch
    mismatches = iocs.get("link_mismatches", [])

    if mismatches:
        add_finding(
            findings,
            "R001",
            (
                "Displayed hyperlink domain differs "
                "from the actual destination domain."
            ),
            25
        )

    # RULE 2: Reply-To mismatch
    from_domain = get_email_domain(
        email_data.get("from", "")
    )

    reply_to_domain = get_email_domain(
        email_data.get("reply_to", "")
    )

    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    ):
        add_finding(
            findings,
            "R002",
            (
                f"Reply-To domain ({reply_to_domain}) "
                f"differs from sender domain ({from_domain})."
            ),
            10
        )

    # RULE 3: Urgency keywords
    content = " ".join([
        email_data.get("subject", "") or "",
        email_data.get("body_text", "") or "",
        re.sub(
            r"<[^>]+>",
            " ",
            email_data.get("body_html", "") or ""
        )
    ]).lower()

    matched_keywords = [
        keyword
        for keyword in URGENCY_KEYWORDS
        if keyword in content
    ]

    if matched_keywords:
        add_finding(
            findings,
            "R003",
            (
                "Suspicious urgency language detected: "
                + ", ".join(matched_keywords)
            ),
            10
        )

    # RULE 4: IP address used as URL hostname
    for url in iocs.get("urls", []):
        try:
            hostname = urlsplit(url).hostname

            if hostname:
                ipaddress.ip_address(hostname)

                add_finding(
                    findings,
                    "R004",
                    f"URL uses an IP address: {url}",
                    15
                )
                break

        except (ValueError, TypeError):
            continue

    # RULE 5: Suspicious attachment extensions
    for attachment in email_data.get("attachments", []):
        filename = str(
            attachment.get("filename", "")
        ).lower()

        if filename.endswith(SUSPICIOUS_EXTENSIONS):
            add_finding(
                findings,
                "R005",
                f"Potentially dangerous attachment: {filename}",
                25
            )
            break

    return findings
