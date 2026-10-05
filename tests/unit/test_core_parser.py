"""Unit tests for Phase 2 URLParser, defanging, and Shannon entropy computation."""

from phish_analyzer.core.defanger import (
    defang_domain,
    defang_ip,
    defang_url,
    refang_url,
)
from phish_analyzer.core.entropy import calculate_shannon_entropy
from phish_analyzer.core.parser import URLParser


def test_defanging_and_refanging_urls() -> None:
    # 1. Defanging standard URLs
    url_http = "http://malicious.org/update"
    assert defang_url(url_http) == "hxxp://malicious[.]org/update"

    url_https = "https://phish.target.com/login?token=abc@123"
    assert defang_url(url_https) == "hxxps://phish[.]target[.]com/login?token=abc[@]123"

    url_ftp = "ftp://files.site.ru/trojan.exe"
    assert defang_url(url_ftp) == "fxp://files[.]site[.]ru/trojan[.]exe"

    # Empty
    assert defang_url("") == ""
    assert refang_url("") == ""

    # 2. Refanging back to canonical form
    defanged = "hxxps://evil[.]com/verify"
    assert refang_url(defanged) == "https://evil.com/verify"

    defanged_dot = "hxxp://bad-site(.)net/login"
    assert refang_url(defanged_dot) == "http://bad-site.net/login"

    defanged_at = "hxxps://domain[.]com/user[@]login"
    assert refang_url(defanged_at) == "https://domain.com/user@login"

    # 3. Defang domain & IP
    assert defang_domain("suspicious-login.xyz") == "suspicious-login[.]xyz"
    assert defang_domain("") == ""
    assert defang_ip("10.0.0.1") == "10[.]0[.]0[.]1"
    assert defang_ip("") == ""


def test_shannon_entropy_calculation() -> None:
    # Empty string has 0 entropy
    assert calculate_shannon_entropy("") == 0.0

    # Uniform single character has 0 entropy
    assert calculate_shannon_entropy("aaaaaaa") == 0.0

    # Repetitive pattern
    ent_low = calculate_shannon_entropy("abababab")
    assert ent_low == 1.0

    # Diverse randomized string has high entropy
    ent_high = calculate_shannon_entropy("7f8d3b9e2a1c4f5g6h")
    assert ent_high > 3.5


def test_url_parser_standard_components() -> None:
    target = "https://secure.login.paypal.com:8443/auth/verify?user=admin#section1"
    parsed = URLParser.parse(target)

    assert parsed.scheme == "https"
    assert parsed.hostname == "secure.login.paypal.com"
    assert parsed.port == 8443
    assert parsed.path == "/auth/verify"
    assert parsed.query == "user=admin"
    assert parsed.fragment == "section1"
    assert parsed.tld == "com"
    assert parsed.registered_domain == "paypal.com"
    assert parsed.subdomains == ["secure", "login"]
    assert parsed.subdomain_depth == 2
    assert parsed.has_ip_host is False
    assert parsed.is_punycode is False
    assert parsed.domain_entropy > 0.0


def test_url_parser_two_part_tld() -> None:
    target = "http://auth.hsbc.co.uk/portal/login"
    parsed = URLParser.parse(target)

    assert parsed.tld == "co.uk"
    assert parsed.registered_domain == "hsbc.co.uk"
    assert parsed.subdomains == ["auth"]
    assert parsed.subdomain_depth == 1


def test_url_parser_schemeless_input() -> None:
    target = "paypal-account-update.com/signin"
    parsed = URLParser.parse(target)

    assert parsed.scheme == "http"
    assert parsed.hostname == "paypal-account-update.com"
    assert parsed.registered_domain == "paypal-account-update.com"
    assert parsed.path == "/signin"


def test_url_parser_ip_address_host() -> None:
    target = "http://192.168.1.100:8080/shell.sh"
    parsed = URLParser.parse(target)

    assert parsed.has_ip_host is True
    assert parsed.hostname == "192.168.1.100"
    assert parsed.port == 8080
    assert parsed.registered_domain == ""
    assert parsed.tld == ""


def test_url_parser_punycode_decoding() -> None:
    # xn--pple-43d.com is Punycode for Cyrillic 'а' in 'аpple.com'
    target = "https://xn--pple-43d.com/login"
    parsed = URLParser.parse(target)

    assert parsed.is_punycode is True
    assert parsed.decoded_punycode is not None
    assert "apple" in parsed.decoded_punycode or "а" in parsed.decoded_punycode
