"""Unit tests for Phase 4 Homoglyph IDN and Phase 5 Typosquatting detectors."""

from phish_analyzer.core.parser import URLParser
from phish_analyzer.detection.homoglyph import HomoglyphDetector
from phish_analyzer.detection.typosquat import TyposquatDetector, levenshtein_distance


def test_levenshtein_distance_properties() -> None:
    """Validate Levenshtein distance edge cases and symmetric properties."""
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("paypal", "") == 6
    assert levenshtein_distance("", "google") == 6
    assert levenshtein_distance("same", "same") == 0
    assert levenshtein_distance("kitten", "sitting") == 3
    assert levenshtein_distance("sitting", "kitten") == 3
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("netflix", "netfflix") == 1


def test_homoglyph_normalization() -> None:
    """Validate confusable character normalization."""
    # Cyrillic 'а' (\u0430) and 'о' (\u043e)
    cyrillic_paypal = "p\u0430yp\u0430l"
    normalized, found = HomoglyphDetector.normalize_confusables(cyrillic_paypal)
    assert normalized == "paypal"
    assert len(found) == 2
    assert found[0][0] == "\u0430"
    assert found[0][1] == "a"


def test_homoglyph_punycode_detection() -> None:
    """Detect Punycode IDN encoded domain."""
    # xn--pple-43d.com is apple.com with Cyrillic 'а'
    parsed = URLParser.parse("http://xn--pple-43d.com/login")
    triggers = HomoglyphDetector.detect(parsed)

    trigger_ids = {t.rule_id for t in triggers}
    assert "PUNYCODE_DOMAIN_PRESENT" in trigger_ids


def test_homoglyph_brand_impersonation() -> None:
    """Detect Cyrillic lookalike brand impersonation."""
    # pаypal with Cyrillic 'а'
    parsed = URLParser.parse("http://p\u0430ypal.com/auth")
    triggers = HomoglyphDetector.detect(parsed)

    trigger_ids = {t.rule_id for t in triggers}
    assert "HOMOGLYPH_BRAND_IMPERSONATION" in trigger_ids
    trigger = next(t for t in triggers if t.rule_id == "HOMOGLYPH_BRAND_IMPERSONATION")
    assert "paypal" in trigger.description.lower()


def test_homoglyph_generic_confusables() -> None:
    """Detect non-brand confusable characters."""
    # wеbsite with Cyrillic 'е' (\u0435)
    parsed = URLParser.parse("http://w\u0435bsite-example.org")
    triggers = HomoglyphDetector.detect(parsed)

    trigger_ids = {t.rule_id for t in triggers}
    assert "UNICODE_CONFUSABLE_GLYPHS" in trigger_ids


def test_typosquat_compound_sld() -> None:
    """Detect brand embedded into a compound domain SLD."""
    parsed = URLParser.parse("https://paypal-security-verification.com/login")
    triggers = TyposquatDetector.detect(parsed)

    trigger_ids = {t.rule_id for t in triggers}
    assert "BRAND_COMPOUND_SLD" in trigger_ids


def test_typosquat_brand_in_subdomain() -> None:
    """Detect brand hidden inside subdomain structure."""
    parsed = URLParser.parse("https://paypal.com.account-verify.attacker.net/auth")
    triggers = TyposquatDetector.detect(parsed)

    trigger_ids = {t.rule_id for t in triggers}
    assert "BRAND_IN_SUBDOMAIN" in trigger_ids


def test_typosquat_levenshtein_distance_and_l33t() -> None:
    """Detect single character distance and l33tspeak variations."""
    test_cases = [
        ("https://paypa1.com", "TYPOSQUATTING_DETECTION"),
        ("https://g00gle.com", "TYPOSQUATTING_DETECTION"),
        ("https://netfflix.com", "TYPOSQUATTING_DETECTION"),
        ("https://amazn.com", "TYPOSQUATTING_DETECTION"),
    ]

    for url, expected_rule in test_cases:
        parsed = URLParser.parse(url)
        triggers = TyposquatDetector.detect(parsed)
        trigger_ids = {t.rule_id for t in triggers}
        assert expected_rule in trigger_ids, f"Failed for {url}"


def test_legitimate_brand_does_not_trigger_typosquat() -> None:
    """Legitimate brand exact domain should not trigger typosquatting."""
    parsed = URLParser.parse("https://paypal.com/signin")
    triggers = TyposquatDetector.detect(parsed)
    assert len(triggers) == 0
