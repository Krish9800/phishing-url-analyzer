"""Unit tests for Phase 6 Scoring Engine and Threat Report models."""

from phish_analyzer.models.report import RiskLevel, ThreatReport
from phish_analyzer.scoring.engine import ScoringEngine


def test_scoring_engine_benign_url() -> None:
    """Analyze benign legitimate URL."""
    url = "https://www.google.com/search?q=cybersecurity"
    report = ScoringEngine.analyze(url)

    assert isinstance(report, ThreatReport)
    assert report.risk_level == RiskLevel.BENIGN
    assert report.threat_score < 40
    assert "google[.]com" in report.defanged_url
    assert "hxxps://" in report.defanged_url
    assert len(report.recommendations) > 0


def test_scoring_engine_malicious_homoglyph() -> None:
    """Analyze malicious homoglyph attack targeting PayPal."""
    # Cyrillic 'а'
    url = "http://p\u0430ypal.com/signin"
    report = ScoringEngine.analyze(url)

    assert report.risk_level == RiskLevel.MALICIOUS
    assert report.threat_score >= 70
    assert any(t.rule_id == "HOMOGLYPH_BRAND_IMPERSONATION" for t in report.triggers)
    assert any("Punycode" in r or "brand" in r.lower() for r in report.recommendations)


def test_scoring_engine_obfuscated_hex_ip() -> None:
    """Analyze hex obfuscated IP address."""
    url = "http://0x7f000001/malware.exe"
    report = ScoringEngine.analyze(url)

    assert report.risk_level == RiskLevel.MALICIOUS
    assert any(t.rule_id == "OBFUSCATED_IP_HOST" for t in report.triggers)
    assert any("firewall" in r.lower() or "ssrf" in r.lower() for r in report.recommendations)


def test_scoring_engine_suspicious_tld_and_keywords() -> None:
    """Analyze suspicious URL with high-risk TLD and suspicious keywords."""
    url = "http://verify-account-update.tk/login"
    report = ScoringEngine.analyze(url)

    assert report.risk_level in (RiskLevel.SUSPICIOUS, RiskLevel.MALICIOUS)
    assert report.threat_score >= 40


def test_threat_report_cef_export() -> None:
    """Validate ArcSight CEF format string generation."""
    url = "http://0x7f000001/payload"
    report = ScoringEngine.analyze(url)
    cef = report.to_cef()

    assert cef.startswith("CEF:0|DefensiveSecurity|PhishAnalyzer|0.1.0|")
    assert "request=" in cef
    assert "cs1=" in cef
    assert "cn1=" in cef
    assert "cn2=" in cef


def test_threat_report_to_dict() -> None:
    """Validate JSON serializability through to_dict."""
    url = "https://example.com"
    report = ScoringEngine.analyze(url)
    data = report.to_dict()

    assert isinstance(data, dict)
    assert data["raw_url"] == url
    assert data["risk_level"] == "BENIGN"
    assert "threat_score" in data
