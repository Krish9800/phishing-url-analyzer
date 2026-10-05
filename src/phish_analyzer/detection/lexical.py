"""Lexical, structural, and keyword heuristic detectors for phishing URLs."""

from phish_analyzer.config.settings import settings
from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.url_record import ParsedURL


class LexicalDetector:
    """Analyzes URL tokens, character distributions, keywords, and structural patterns."""

    @classmethod
    def detect(cls, parsed_url: ParsedURL) -> list[HeuristicTrigger]:
        """Inspect parsed URL and evaluate lexical and structural security rules.

        Args:
            parsed_url: Structured ParsedURL model.

        Returns:
            List of triggered security heuristics.
        """
        triggers: list[HeuristicTrigger] = []

        # 1. HTTP Basic Auth / Embedded '@' Symbol (Authority Confusion)
        if "@" in parsed_url.refanged_url:
            triggers.append(
                HeuristicTrigger(
                    rule_id="EMBEDDED_AT_CREDENTIAL",
                    name="Embedded '@' Symbol in URL Authority",
                    severity=HeuristicSeverity.CRITICAL,
                    score_weight=30,
                    description=(
                        "URL contains an '@' character. Browsers treat text before '@' as HTTP "
                        "basic auth credentials, masking the real destination host from the victim."
                    ),
                    evidence=f"url='{parsed_url.refanged_url}'",
                )
            )

        # 2. High-Risk / Abused Top-Level Domain (TLD)
        tld_clean = parsed_url.tld.lower().strip(".")
        if tld_clean in settings.HIGH_RISK_TLDS:
            triggers.append(
                HeuristicTrigger(
                    rule_id="HIGH_RISK_TLD",
                    name="High-Risk Top-Level Domain (TLD)",
                    severity=HeuristicSeverity.HIGH,
                    score_weight=20,
                    description=(
                        f"The domain uses '.{tld_clean}' TLD, which is correlated with "
                        "high concentrations of malicious disposable phishing infrastructure."
                    ),
                    evidence=f"tld='.{tld_clean}'",
                )
            )

        # 3. Subdomain Stuffing & Depth
        if parsed_url.subdomain_depth > settings.MAX_SUBDOMAIN_DEPTH:
            triggers.append(
                HeuristicTrigger(
                    rule_id="SUBDOMAIN_STUFFING",
                    name="Excessive Subdomain Depth",
                    severity=HeuristicSeverity.HIGH,
                    score_weight=20,
                    description=(
                        f"URL contains {parsed_url.subdomain_depth} subdomain levels "
                        f"(threshold {settings.MAX_SUBDOMAIN_DEPTH}). Often masks brands."
                    ),
                    evidence=f"subdomains={parsed_url.subdomains}",
                )
            )

        # 4. Suspicious Phishing Keywords
        found_keywords: list[str] = []
        host_lower = parsed_url.hostname.lower()
        path_lower = parsed_url.path.lower()

        for kw in settings.SUSPICIOUS_KEYWORDS:
            if kw in host_lower or kw in path_lower:
                found_keywords.append(kw)

        if len(found_keywords) >= 2:
            triggers.append(
                HeuristicTrigger(
                    rule_id="MULTIPLE_PHISHING_KEYWORDS",
                    name="Multiple Phishing Lure Keywords Detected",
                    severity=HeuristicSeverity.HIGH,
                    score_weight=25,
                    description=(
                        f"Found {len(found_keywords)} high-risk security/account keywords "
                        f"({', '.join(found_keywords)}) in URL structure."
                    ),
                    evidence=f"keywords={found_keywords}",
                )
            )
        elif len(found_keywords) == 1:
            triggers.append(
                HeuristicTrigger(
                    rule_id="PHISHING_KEYWORD_DETECTED",
                    name="Phishing Lure Keyword Detected",
                    severity=HeuristicSeverity.MEDIUM,
                    score_weight=10,
                    description=(
                        f"Found security/account keyword '{found_keywords[0]}' in URL structure."
                    ),
                    evidence=f"keyword='{found_keywords[0]}'",
                )
            )

        # 5. Hyphen Stuffing in Domain
        hyphen_count = parsed_url.hostname.count("-")
        if hyphen_count >= 3:
            triggers.append(
                HeuristicTrigger(
                    rule_id="HYPHEN_STUFFING",
                    name="Excessive Hyphens in Hostname",
                    severity=HeuristicSeverity.MEDIUM,
                    score_weight=15,
                    description=(
                        f"Hostname contains {hyphen_count} hyphens. Attackers frequently use "
                        "compound words to fabricate misleading domain names."
                    ),
                    evidence=f"hostname='{parsed_url.hostname}', count={hyphen_count}",
                )
            )

        # 6. Excessive URL Length
        if len(parsed_url.raw_url) > 100 or len(parsed_url.path) > settings.MAX_PATH_LENGTH:
            triggers.append(
                HeuristicTrigger(
                    rule_id="EXCESSIVE_URL_LENGTH",
                    name="Excessive URL / Path Length",
                    severity=HeuristicSeverity.LOW,
                    score_weight=10,
                    description=(
                        "URL length is abnormally long. Attackers construct lengthy paths to push "
                        "the actual domain name out of view on mobile address bars."
                    ),
                    evidence=(
                        f"total_len={len(parsed_url.raw_url)}, path_len={len(parsed_url.path)}"
                    ),
                )
            )

        # 7. Non-Standard Network Port
        if parsed_url.port is not None and parsed_url.port not in (80, 443):
            triggers.append(
                HeuristicTrigger(
                    rule_id="NON_STANDARD_PORT",
                    name="Non-Standard Web Service Port",
                    severity=HeuristicSeverity.MEDIUM,
                    score_weight=15,
                    description=(
                        f"URL connects over non-standard port {parsed_url.port} "
                        "rather than standard HTTP(S) ports 80 or 443."
                    ),
                    evidence=f"port={parsed_url.port}",
                )
            )

        # 8. High Lexical Shannon Entropy (Domain Generation Algorithm Indicator)
        if parsed_url.domain_entropy > settings.SHANNON_ENTROPY_THRESHOLD:
            triggers.append(
                HeuristicTrigger(
                    rule_id="HIGH_DOMAIN_ENTROPY",
                    name="High Domain Lexical Entropy",
                    severity=HeuristicSeverity.HIGH,
                    score_weight=20,
                    description=(
                        f"Domain lexical entropy ({parsed_url.domain_entropy:.2f} bits) exceeds "
                        f"threshold ({settings.SHANNON_ENTROPY_THRESHOLD}). Characteristic of DGAs "
                        "or randomized disposable hostnames."
                    ),
                    evidence=f"entropy={parsed_url.domain_entropy:.4f}",
                )
            )

        return triggers
