
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from core.ioc_extractor import extract_iocs


MAX_EMAIL_SIZE = 10 * 1024 * 1024


def safe_content(part):
    """Safely decode a text MIME part."""
    try:
        content = part.get_content()

        if isinstance(content, str):
            return content

        if isinstance(content, bytes):
            return content.decode(
                "utf-8",
                errors="replace"
            )

    except (UnicodeError, LookupError, ValueError):
        pass

    payload = part.get_payload(decode=True)

    if isinstance(payload, bytes):
        return payload.decode(
            "utf-8",
            errors="replace"
        )

    return ""


def get_attachment_info(part):
    """Extract attachment metadata without executing it."""
    try:
        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        if not isinstance(payload, bytes):
            payload = b""

        filename = part.get_filename() or "unnamed"

        return {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest()
        }

    except (ValueError, TypeError) as exc:
        return {
            "filename": part.get_filename() or "unnamed",
            "content_type": part.get_content_type(),
            "size": None,
            "sha256": None,
            "error": str(exc)
        }


def parse_email(raw):
    """
    Parse an EML email and return structured data.

    raw: bytes
    """
    if not isinstance(raw, bytes):
        raise TypeError("Email data must be bytes")

    if not raw:
        raise ValueError("Email file is empty")

    if len(raw) > MAX_EMAIL_SIZE:
        raise ValueError(
            "Email exceeds maximum size of 10 MB"
        )

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw)

    from_header = str(message.get("From", ""))
    to_header = str(message.get("To", ""))
    reply_to = str(message.get("Reply-To", ""))
    return_path = str(message.get("Return-Path", ""))

    from_address = parseaddr(from_header)[1]

    body_text_parts = []
    body_html_parts = []
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        # Consider a part with filename an attachment.
        if disposition == "attachment" or filename:
            attachments.append(
                get_attachment_info(part)
            )
            continue

        if content_type == "text/plain":
            body_text_parts.append(
                safe_content(part)
            )

        elif content_type == "text/html":
            body_html_parts.append(
                safe_content(part)
            )

    body_text = "\n".join(body_text_parts)
    body_html = "\n".join(body_html_parts)

    iocs = extract_iocs(
        text=body_text,
        html=body_html
    )

    auth_results = [
        str(value)
        for value in message.get_all(
            "Authentication-Results", []
        )
    ]

    return {
        "subject": str(message.get("Subject", "")),
        "from": from_header,
        "from_address": from_address,
        "to": to_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "authentication_results": auth_results,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "iocs": iocs,
        "email_sha256": hashlib.sha256(raw).hexdigest(),
        "email_size": len(raw)
    }
