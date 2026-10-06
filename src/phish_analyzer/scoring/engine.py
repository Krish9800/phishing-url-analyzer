"""Threat scoring engine and risk classifier."""

from phish_analyzer.config.settings import settings
from phish_analyzer.core.defanger import defang_url
from phish_analyzer.core.parser import URLParser
from phish_analyzer.detection.homoglyph import HomoglyphDetector
from phish_analyzer.detection.ip_obfuscation import IPObfuscationDetector
from phish_analyzer.detection.lexical import LexicalDetector
from phish_analyzer.detection.typosquat import TyposquatDetector
from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.report import RiskLevel, ThreatReport


class ScoringEngine:
    """Orchestrates heuristic detectors, aggregates threat scores, and builds reports."""

    @classmethod
    def generate_recommendations(cls, triggers: list[HeuristicTrigger]) -> list[str]:
        """Produce actionable defensive recommendations based on active threat indicators."""
        recs: list[str] = []
        if not triggers:
            recs.append(
                "No immediate phishing indicators detected; maintain standard zero-trust telemetry."
            )
            return recs

        rule_ids = {t.rule_id for t in triggers}

        if any(
            r in rule_ids
            for r in [
                "OBFUSCATED_IP_HOST",
                "RAW_IP_HOST",
                "PRIVATE_IP_SSRF_RISK",
            ]
        ):
            recs.append(
                "Block host at network firewall; inspect internal traffic for SSRF "
                "or C2 beaconing attempts."
            )

        if "HOMOGLYPH_BRAND_IMPERSONATION" in rule_ids or "UNICODE_CONFUSABLE_GLYPHS" in rule_ids:
            recs.append(
                "Enforce Punycode domain display in mail user agents and web browsers; "
                "block domain at Secure Web Gateway (SWG)."
            )

        if any(
            r in rule_ids
            for r in [
                "TYPOSQUATTING_DETECTION",
                "BRAND_COMPOUND_SLD",
                "BRAND_IN_SUBDOMAIN",
            ]
        ):
            recs.append(
                "Block domain at DNS/SWG perimeter; issue proactive brand takedown notice "
                "and reset credentials for users who visited."
            )

        if "EMBEDDED_AT_CREDENTIAL" in rule_ids:
            recs.append(
                "Configure edge reverse proxies to strip embedded userinfo credentials "
                "and reject authority masking."
            )

        if (
            "HIGH_RISK_TLD" in rule_ids
            or "SUBDOMAIN_STUFFING" in rule_ids
            or "HIGH_DOMAIN_ENTROPY" in rule_ids
        ):
            recs.append(
                "Isolate sessions targeting newly observed high-risk TLDs and dynamic DNS "
                "providers using Remote Browser Isolation (RBI)."
            )

        if not recs:
            recs.append(
                "Review URL context in incident response queue; monitor for secondary redirects."
            )

        return recs

    @classmethod
    def analyze(cls, raw_url: str) -> ThreatReport:
        """Run all static and heuristic detectors against the URL and generate a ThreatReport.

        Args:
            raw_url: Input URL string to evaluate.

        Returns:
            Structured ThreatReport model.
        """
        parsed = URLParser.parse(raw_url)

        # Execute all detection engines
        triggers: list[HeuristicTrigger] = []
        triggers.extend(IPObfuscationDetector.detect(parsed))
        triggers.extend(LexicalDetector.detect(parsed))
        triggers.extend(HomoglyphDetector.detect(parsed))
        triggers.extend(TyposquatDetector.detect(parsed))

        # Compute raw weighted score
        raw_score = sum(t.score_weight for t in triggers)

        # Critical severity escalation: if any critical indicator is flagged,
        # ensure score is at least the malicious threshold
        if any(t.severity == HeuristicSeverity.CRITICAL for t in triggers):
            raw_score = max(raw_score, settings.MALICIOUS_SCORE_THRESHOLD)

        threat_score = min(100, max(0, raw_score))

        # Classify risk level
        if threat_score >= settings.MALICIOUS_SCORE_THRESHOLD:
            risk_level = RiskLevel.MALICIOUS
        elif threat_score >= settings.SUSPICIOUS_SCORE_THRESHOLD:
            risk_level = RiskLevel.SUSPICIOUS
        else:
            risk_level = RiskLevel.BENIGN

        recommendations = cls.generate_recommendations(triggers)
        defanged = defang_url(raw_url)

        return ThreatReport(
            raw_url=raw_url,
            defanged_url=defanged,
            threat_score=threat_score,
            risk_level=risk_level,
            parsed_url=parsed,
            triggers=triggers,
            recommendations=recommendations,
        )
