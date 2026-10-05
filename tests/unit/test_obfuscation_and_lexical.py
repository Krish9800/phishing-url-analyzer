"""Unit tests for Phase 3 IP obfuscation and lexical heuristic detectors."""

from phish_analyzer.core.parser import URLParser
from phish_analyzer.detection.ip_obfuscation import IPObfuscationDetector
from phish_analyzer.detection.lexical import LexicalDetector
from phish_analyzer.models.heuristic import HeuristicSeverity


def test_dword_ip_obfuscation_and_ssrf() -> None:
    # 2130706433 is integer dword for 127.0.0.1 (loopback)
    url = "http://2130706433/admin"
    parsed = URLParser.parse(url)
    triggers = IPObfuscationDetector.detect(parsed)

    rule_ids = {t.rule_id for t in triggers}
    assert "OBFUSCATED_IP_HOST" in rule_ids
    assert "PRIVATE_IP_SSRF_RISK" in rule_ids

    obf_trigger = next(t for t in triggers if t.rule_id == "OBFUSCATED_IP_HOST")
    assert obf_trigger.severity == HeuristicSeverity.CRITICAL
    assert "127.0.0.1" in obf_trigger.evidence


def test_hex_ip_obfuscation() -> None:
    # Single hex: 0x7f000001 -> 127.0.0.1
    parsed1 = URLParser.parse("http://0x7f000001/status")
    triggers1 = IPObfuscationDetector.detect(parsed1)
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in triggers1)

    # Dotted hex: 0x7f.0x0.0x0.0x1
    parsed2 = URLParser.parse("http://0x7f.0x0.0x0.0x1/")
    triggers2 = IPObfuscationDetector.detect(parsed2)
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in triggers2)


def test_octal_ip_obfuscation() -> None:
    # 0177 is octal 127
    parsed = URLParser.parse("http://0177.0.0.1/login")
    triggers = IPObfuscationDetector.detect(parsed)
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in triggers)
    assert any(t.rule_id == "PRIVATE_IP_SSRF_RISK" for t in triggers)


def test_raw_public_ip() -> None:
    parsed = URLParser.parse("http://93.184.216.34/payload.exe")
    triggers = IPObfuscationDetector.detect(parsed)

    assert any(t.rule_id == "RAW_IP_HOST" for t in triggers)
    # Must NOT trigger private SSRF risk
    assert not any(t.rule_id == "PRIVATE_IP_SSRF_RISK" for t in triggers)


def test_embedded_at_symbol_detection() -> None:
    url = "https://legitimate-service.com@attacker-controlled-host.com/auth"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    assert any(t.rule_id == "EMBEDDED_AT_CREDENTIAL" for t in triggers)


def test_high_risk_tld_detection() -> None:
    url = "http://account-update.tk/index.html"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    assert any(t.rule_id == "HIGH_RISK_TLD" for t in triggers)
    tld_trigger = next(t for t in triggers if t.rule_id == "HIGH_RISK_TLD")
    assert tld_trigger.severity == HeuristicSeverity.HIGH


def test_subdomain_stuffing_detection() -> None:
    url = "http://login.secure.verify.portal.account.evil.com/session"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    assert any(t.rule_id == "SUBDOMAIN_STUFFING" for t in triggers)


def test_multiple_phishing_keywords_detection() -> None:
    url = "https://example.com/login/verify/security"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    assert any(t.rule_id == "MULTIPLE_PHISHING_KEYWORDS" for t in triggers)


def test_hyphen_stuffing_and_non_standard_port() -> None:
    url = "http://my-secure-bank-login-update.com:8443/portal"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    rule_ids = {t.rule_id for t in triggers}
    assert "HYPHEN_STUFFING" in rule_ids
    assert "NON_STANDARD_PORT" in rule_ids
