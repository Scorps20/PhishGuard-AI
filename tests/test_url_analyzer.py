import pytest

from src.url_analyzer import MALFORMED_WARNING, analyse_message_urls, analyse_url, extract_urls

SETTINGS = {
    "max_url_length": 75,
    "max_subdomains": 3,
    "max_urls_to_analyse": 20,
    "shorteners": ["bit.ly", "tinyurl.com"],
    "suspicious_hostname_words": ["login", "verify"],
}


def warnings_text(url):
    return " ".join(analyse_url(url, SETTINGS).warnings).lower()


def test_message_without_url():
    assert extract_urls("Hi, see you at 5pm. Bring the notes.") == []
    assert analyse_message_urls("No links here.", SETTINGS) == []
    assert extract_urls(None) == []


def test_urls_are_extracted_in_order_without_trailing_punctuation():
    text = "Go to https://example.com/a, then www.test.org. Or bit.ly/xyz!"
    assert extract_urls(text) == ["https://example.com/a", "www.test.org", "bit.ly/xyz"]


def test_email_addresses_are_not_treated_as_urls():
    assert extract_urls("Contact support@bank-help.com for help") == []


def test_duplicate_urls_reported_once():
    assert extract_urls("http://a.com http://a.com") == ["http://a.com"]


def test_normal_url_has_no_warnings():
    report = analyse_url("https://www.example.com/about", SETTINGS)
    assert report.hostname == "www.example.com"
    assert report.warnings == []
    assert not report.has_warnings


def test_ip_address_host():
    assert "ip address" in warnings_text("http://192.168.10.5/login.php")


def test_url_shortener():
    assert "shortener" in warnings_text("bit.ly/abc123")
    assert "shortener" in warnings_text("https://www.tinyurl.com/xyz")


def test_long_url():
    assert "long" in warnings_text("https://example.com/" + "a" * 100)


def test_at_sign_hides_real_destination():
    report = analyse_url("http://paypal.com@evil.example/login", SETTINGS)
    assert report.hostname == "evil.example"
    assert any("@" in w for w in report.warnings)


def test_excessive_subdomains():
    assert "subdomains" in warnings_text("http://a.b.c.d.example.com/")


def test_suspicious_hostname_words():
    assert "login" in warnings_text("http://secure-login-example.com")


def test_punycode_domain():
    assert "look-alike" in warnings_text("http://xn--pple-43d.com")


@pytest.mark.parametrize("bad_url", ["http://[not-an-ip/path", "http://", "https://:80", "www."])
def test_malformed_urls_do_not_crash(bad_url):
    report = analyse_url(bad_url, SETTINGS)
    assert report.warnings == [MALFORMED_WARNING]


def test_malformed_url_inside_message_does_not_crash():
    reports = analyse_message_urls("Click http://[broken now", SETTINGS)
    assert len(reports) == 1 and reports[0].has_warnings


def test_default_settings_load_from_config():
    # Uses config/settings.json
    assert analyse_url("https://bit.ly/x").has_warnings
