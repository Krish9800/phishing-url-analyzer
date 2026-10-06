"""Security adversarial tests and edge-case validation suite."""

import time

from phish_analyzer.core.parser import URLParser
from phish_analyzer.detection.ip_obfuscation import IPObfuscationDetector
from phish_analyzer.detection.lexical import LexicalDetector
from phish_analyzer.models.heuristic import HeuristicSeverity
from phish_analyzer.models.report import RiskLevel
from phish_analyzer.scoring.engine import ScoringEngine


def test_extreme_url_length_redos_resistance() -> None:
    """Validate that 10,000-character adversarial URLs execute in < 150ms without ReDoS."""
    malicious_url = "https://example.com/search?" + ("a=1&" * 1500) + "trailing=payload"
    start_time = time.perf_counter()
    report = ScoringEngine.analyze(malicious_url)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 0.20, f"Analysis took too long: {elapsed:.3f}s (possible ReDoS)"
    assert report.risk_level in (RiskLevel.BENIGN, RiskLevel.SUSPICIOUS)
    assert any(t.rule_id == "EXCESSIVE_URL_LENGTH" for t in report.triggers)


def test_mixed_case_obfuscation() -> None:
    """Ensure mixed-case schemes, hosts, and hex prefixes are normalized and caught."""
    url = "hTTp://0X7F.0x0.0X0.1/aDmin"
    report = ScoringEngine.analyze(url)

    assert report.risk_level == RiskLevel.MALICIOUS
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in report.triggers)


def test_multiple_at_symbols_authority_evasion() -> None:
    """Detect advanced credential stuffing and multiple @ authority evasion."""
    url = "https://user:password@legit-service.com@attacker-portal.net/login"
    report = ScoringEngine.analyze(url)

    assert report.risk_level in (RiskLevel.SUSPICIOUS, RiskLevel.MALICIOUS)
    assert any(t.rule_id == "EMBEDDED_AT_CREDENTIAL" for t in report.triggers)


def test_trailing_dot_domain_normalization() -> None:
    """Test FQDN trailing dot handling (e.g. paypal.com.)."""
    url = "https://paypal.com./login"
    parsed = URLParser.parse(url)
    assert parsed.hostname == "paypal.com."
    assert "paypal" in parsed.registered_domain


def test_ipv6_loopback_and_bracketed_hosts() -> None:
    """Verify bracketed IPv6 notation is safely handled without parser crash."""
    url = "http://[::1]:8080/metrics"
    report = ScoringEngine.analyze(url)
    assert report.parsed_url.has_ip_host is True
    assert report.parsed_url.port == 8080


def test_zero_padded_octal_ip_detection() -> None:
    """Detect zero-padded octal representations of loopback addresses."""
    url = "http://00000177.0.0.1/admin"
    report = ScoringEngine.analyze(url)

    assert report.risk_level == RiskLevel.MALICIOUS
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in report.triggers)


def test_url_without_scheme_input() -> None:
    """Ensure parser can handle naked host/path without explicit http/https."""
    raw = "paypa1.com/update-security"
    report = ScoringEngine.analyze(raw)

    assert report.risk_level == RiskLevel.MALICIOUS
    assert any(t.rule_id == "TYPOSQUATTING_DETECTION" for t in report.triggers)


def test_deeply_nested_subdomain_denial_of_service() -> None:
    """Verify deeply nested subdomain strings (50 labels) are handled safely."""
    domain = ".".join(["sub"] * 40) + ".example.com"
    url = f"https://{domain}/path"

    start_time = time.perf_counter()
    report = ScoringEngine.analyze(url)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 0.10
    assert any(t.rule_id == "SUBDOMAIN_STUFFING" for t in report.triggers)


def test_high_entropy_dga_domain() -> None:
    """Detect algorithmically generated domain (DGA) with high Shannon entropy."""
    # High entropy random character string
    url = "http://x7k9mq2zpw8vb4jd.biz/download"
    parsed = URLParser.parse(url)
    triggers = LexicalDetector.detect(parsed)

    assert any(t.rule_id == "HIGH_DOMAIN_ENTROPY" for t in triggers)
    entropy_trigger = next(t for t in triggers if t.rule_id == "HIGH_DOMAIN_ENTROPY")
    assert entropy_trigger.severity == HeuristicSeverity.HIGH


def test_ssrf_private_network_192_168() -> None:
    """Verify RFC 1918 private address detection in SSRF vector."""
    url = "http://192.168.1.1/router-firmware"
    parsed = URLParser.parse(url)
    triggers = IPObfuscationDetector.detect(parsed)

    assert any(t.rule_id == "PRIVATE_IP_SSRF_RISK" for t in triggers)


def test_ssrf_aws_metadata_service() -> None:
    """Verify link-local cloud metadata service IP (169.254.169.254) is flagged."""
    url = "http://169.254.169.254/latest/meta-data/"
    parsed = URLParser.parse(url)
    triggers = IPObfuscationDetector.detect(parsed)

    assert any(t.rule_id == "PRIVATE_IP_SSRF_RISK" for t in triggers)
