
import re
import ipaddress
from urllib.parse import urlsplit

from bs4 import BeautifulSoup


URL_REGEX = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)

IP_REGEX = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)


def unique(items):
    """Remove duplicates while preserving order."""
    return list(dict.fromkeys(items))


def clean_url(url):
    """Remove common trailing punctuation."""
    return url.strip().rstrip(".,;!?)]}")


def get_domain(url):
    """Get hostname from HTTP/HTTPS URL."""
    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        hostname = parsed.hostname

        if hostname:
            return hostname.lower().rstrip(".")

    except ValueError:
        pass

    return None


def extract_urls(text):
    """Extract URLs from plain text."""
    if not text:
        return []

    matches = URL_REGEX.findall(text)
    urls = []

    for match in matches:
        url = clean_url(match)

        if get_domain(url):
            urls.append(url)

    return unique(urls)


def extract_ips(text):
    """Extract valid IPv4 addresses."""
    if not text:
        return []

    candidates = IP_REGEX.findall(text)
    results = []

    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)

            if isinstance(ip, ipaddress.IPv4Address):
                results.append(str(ip))

        except ValueError:
            continue

    return unique(results)


def analyze_html_links(html):
    """
    Extract hyperlink destinations and detect
    displayed URL hostname mismatches.
    """
    if not html:
        return [], []

    soup = BeautifulSoup(html, "html.parser")

    urls = []
    mismatches = []

    for anchor in soup.find_all("a", href=True):
        href = clean_url(str(anchor.get("href", "")))

        destination_domain = get_domain(href)

        if not destination_domain:
            continue

        urls.append(href)

        displayed_text = anchor.get_text(" ", strip=True)

        displayed_urls = extract_urls(displayed_text)

        for displayed_url in displayed_urls:
            displayed_domain = get_domain(displayed_url)

            if (
                displayed_domain
                and displayed_domain != destination_domain
            ):
                mismatches.append({
                    "displayed_url": displayed_url,
                    "actual_url": href,
                    "displayed_domain": displayed_domain,
                    "actual_domain": destination_domain
                })

    return unique(urls), mismatches


def extract_iocs(text="", html=""):
    """
    Extract indicators from plain text and HTML.

    Does not visit URLs or make network requests.
    """
    text = text or ""
    html = html or ""

    plain_urls = extract_urls(text)

    html_urls, mismatches = analyze_html_links(html)

    html_text = (
        BeautifulSoup(html, "html.parser")
        .get_text(" ", strip=True)
        if html else ""
    )

    visible_urls = extract_urls(html_text)

    urls = unique(
        plain_urls + html_urls + visible_urls
    )

    domains = unique([
        domain
        for url in urls
        if (domain := get_domain(url))
    ])

    ips = unique(
        extract_ips(text)
        + extract_ips(html_text)
        + [
            domain
            for domain in domains
            if is_ipv4(domain)
        ]
    )

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "link_mismatches": mismatches
    }


def is_ipv4(value):
    try:
        return isinstance(
            ipaddress.ip_address(value),
            ipaddress.IPv4Address
        )
    except ValueError:
        return False
