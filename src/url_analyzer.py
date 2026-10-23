"""Find URLs in a message and check their STRUCTURE for warning signs.

Safety: URLs are only treated as text. Nothing here opens, visits, resolves
or sends a URL anywhere. A structural warning is NOT proof that a link is
malicious: many legitimate links are long or use shorteners.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from src.config import load_settings

# Links that start with http://, https:// or www.
_FULL_URL = r"(?:https?://|www\.)[^\s<>\"'(){}]+"
# Bare domains such as "bit.ly/abc" or "secure-bank.com/login" (common in SMS).
# The look-behind stops "name@bank.com" email addresses from matching.
_BARE_DOMAIN = (
    r"(?<![@\w.-])(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|info|biz|co|in|io|ly|me|xyz|top|ru|cn|uk|link|click|site|online|app)"
    r"(?:/[^\s<>\"'(){}\[\]]*)?(?![\w@-])"
)
URL_PATTERN = re.compile(f"{_FULL_URL}|{_BARE_DOMAIN}", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,;:!?'\")]}>"
_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}
_HAS_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

MALFORMED_WARNING = "The URL is malformed, so its destination could not be read."


@dataclass
class UrlReport:
    url: str
    hostname: str | None
    warnings: list[str] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


def _strip_trailing_punctuation(url: str) -> str:
    """Remove sentence punctuation after a URL, but keep a closing bracket
    that belongs to the URL itself, e.g. "http://[::1]"."""
    while url and url[-1] in _TRAILING_PUNCTUATION:
        closing = url[-1]
        if closing in _BRACKET_PAIRS and url.count(_BRACKET_PAIRS[closing]) >= url.count(closing):
            break
        url = url[:-1]
    return url


def extract_urls(text, max_urls: int = 20) -> list[str]:
    """Return the unique URLs found in the text, in order of appearance."""
    if not isinstance(text, str):
        return []
    urls = []
    for match in URL_PATTERN.finditer(text):
        url = _strip_trailing_punctuation(match.group(0))
        if url and url not in urls:
            urls.append(url)
        if len(urls) >= max_urls:
            break
    return urls


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyse_url(url: str, url_settings: dict | None = None) -> UrlReport:
    """Check one URL's structure. Never raises for malformed input."""
    settings = url_settings or load_settings()["url"]

    # urlsplit only finds the hostname when a scheme is present
    to_parse = url if _HAS_SCHEME.match(url) else f"http://{url}"
    try:
        parts = urlsplit(to_parse)
        hostname = parts.hostname
    except ValueError:  # e.g. "http://[not-an-ip"
        return UrlReport(url, None, [MALFORMED_WARNING])
    is_ip = bool(hostname) and _is_ip_address(hostname)
    labels = hostname.split(".") if hostname else []
    # A real domain has at least two non-empty parts, e.g. "example.com" (not "www.")
    if not hostname or (not is_ip and (len(labels) < 2 or "" in labels)):
        return UrlReport(url, hostname or None, [MALFORMED_WARNING])

    warnings = []

    if is_ip:
        warnings.append("Uses an IP address instead of a domain name.")

    if "@" in parts.netloc:
        warnings.append(
            f"Contains '@' before the address, which can disguise the real destination ({hostname})."
        )

    if any(hostname == s or hostname.endswith("." + s) for s in settings["shorteners"]):
        warnings.append("Uses a URL shortener, which hides the real destination.")

    if len(url) > settings["max_url_length"]:
        warnings.append(f"Unusually long URL ({len(url)} characters).")

    if not is_ip:
        subdomain_count = len(labels) - 2
        if subdomain_count > settings["max_subdomains"]:
            warnings.append(f"Has many subdomains ({subdomain_count}), which can imitate a trusted site.")

        if "xn--" in hostname or not hostname.isascii():
            warnings.append("Uses special or look-alike characters in the domain name.")

        words = [w for w in settings["suspicious_hostname_words"] if w in hostname]
        if words:
            warnings.append(
                "Domain name contains words often used to look official: " + ", ".join(words) + "."
            )

    return UrlReport(url, hostname, warnings)


def analyse_message_urls(text, url_settings: dict | None = None) -> list[UrlReport]:
    """Extract every URL in a message and check each one."""
    settings = url_settings or load_settings()["url"]
    return [analyse_url(url, settings) for url in extract_urls(text, settings["max_urls_to_analyse"])]
