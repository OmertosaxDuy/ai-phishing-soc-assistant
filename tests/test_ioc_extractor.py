
from core.ioc_extractor import (
    extract_iocs,
    extract_urls,
    extract_ips,
    get_domain
)


def test_extract_urls():
    text = """
    Visit https://example.com/test
    and https://example.com/test
    """

    urls = extract_urls(text)

    assert len(urls) == 1


def test_domain_extraction():
    domain = get_domain(
        "https://login.example.com/verify"
    )

    assert domain == "login.example.com"


def test_extract_ips():
    text = """
    Connect to 192.0.2.10
    or 999.999.999.999
    """

    ips = extract_ips(text)

    assert ips == ["192.0.2.10"]


def test_html_link_mismatch():
    html = """
    <a href="https://fake.example/login">
        https://real.example/login
    </a>
    """

    result = extract_iocs(html=html)

    assert len(result["link_mismatches"]) == 1

    mismatch = result["link_mismatches"][0]

    assert mismatch["actual_domain"] == "fake.example"

    assert mismatch["displayed_domain"] == "real.example"


def test_no_mismatch():
    html = """
    <a href="https://example.com/login">
        https://example.com/login
    </a>
    """

    result = extract_iocs(html=html)

    assert len(result["link_mismatches"]) == 0
