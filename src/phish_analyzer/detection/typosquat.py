"""Typosquatting and brand impersonation detector using Levenshtein distance."""

from phish_analyzer.config.settings import settings
from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.url_record import ParsedURL


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the minimum number of single-character edits between two strings.

    Edits include: insertion, deletion, substitution.
    Space complexity: O(min(len(s1), len(s2))).
    """
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    # Ensure s1 is the shorter string to optimize row buffer memory
    if len(s1) > len(s2):
        s1, s2 = s2, s1

    previous_row = list(range(len(s1) + 1))
    for i, c2 in enumerate(s2):
        current_row = [i + 1] + [0] * len(s1)
        for j, c1 in enumerate(s1):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row[j + 1] = min(insertions, deletions, substitutions)
        previous_row = current_row

    return previous_row[-1]


class TyposquatDetector:
    """Identifies typosquatting, bitsquatting, and brand impersonation in domain names."""

    @classmethod
    def detect(cls, parsed_url: ParsedURL) -> list[HeuristicTrigger]:
        """Inspect domain for brand impersonation or typosquatting deviations.

        Args:
            parsed_url: Structured ParsedURL model.

        Returns:
            List of triggered security heuristics.
        """
        triggers: list[HeuristicTrigger] = []
        domain = parsed_url.registered_domain.lower()
        if not domain:
            return triggers

        # Extract SLD (second-level domain / main brand portion without TLD)
        sld = domain.split(".")[0] if "." in domain else domain

        # Common l33tspeak substitutions (0 -> o, 1 -> l/i, etc.)
        l33t_clean = sld.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")

        for brand in settings.TARGETED_BRANDS:
            # Check 1: Brand appears in SLD as a compound (e.g. paypal-security, login-google)
            if brand in sld and sld != brand:
                triggers.append(
                    HeuristicTrigger(
                        rule_id="BRAND_COMPOUND_SLD",
                        name="Brand Name in Compound Domain",
                        severity=HeuristicSeverity.HIGH,
                        score_weight=25,
                        description=(
                            f"Domain '{domain}' embeds the protected brand name '{brand}' in an "
                            "unauthorized compound second-level domain name."
                        ),
                        evidence=f"domain='{domain}', brand='{brand}'",
                    )
                )
                continue

            # Check 2: Brand appears in subdomains when main domain is different
            if not parsed_url.has_ip_host and any(brand in sub for sub in parsed_url.subdomains):
                if sld != brand:
                    triggers.append(
                        HeuristicTrigger(
                            rule_id="BRAND_IN_SUBDOMAIN",
                            name="Brand Name Masked in Subdomain",
                            severity=HeuristicSeverity.HIGH,
                            score_weight=25,
                            description=(
                                f"Subdomain structure references brand '{brand}', while the "
                                f"authoritative domain is '{domain}'. Common brand spoof."
                            ),
                            evidence=(
                                f"subdomains={parsed_url.subdomains}, registered_domain='{domain}'"
                            ),
                        )
                    )
                    continue

            # Check 3: L33tspeak substitution impersonation
            if l33t_clean == brand and sld != brand:
                triggers.append(
                    HeuristicTrigger(
                        rule_id="TYPOSQUATTING_DETECTION",
                        name="L33tspeak Brand Impersonation",
                        severity=HeuristicSeverity.CRITICAL,
                        score_weight=30,
                        description=(
                            f"Second-level domain '{sld}' uses l33tspeak character substitution "
                            f"to spoof protected brand '{brand}'."
                        ),
                        evidence=f"sld='{sld}' -> l33t_clean='{l33t_clean}' (brand: {brand})",
                    )
                )
                continue

            # Check 4: Levenshtein distance typosquatting
            dist_raw = levenshtein_distance(sld, brand)
            dist_l33t = levenshtein_distance(l33t_clean, brand)
            min_dist = min(dist_raw, dist_l33t)

            if 1 <= min_dist <= settings.TYPOSQUAT_MAX_DISTANCE:
                triggers.append(
                    HeuristicTrigger(
                        rule_id="TYPOSQUATTING_DETECTION",
                        name="Typosquatting Brand Impersonation",
                        severity=HeuristicSeverity.CRITICAL,
                        score_weight=30,
                        description=(
                            f"Second-level domain '{sld}' has a Levenshtein edit distance of "
                            f"{min_dist} from protected brand '{brand}'. High probability of "
                            "typosquatting or bitsquatting."
                        ),
                        evidence=(
                            f"sld='{sld}' -> target_brand='{brand}' (edit_distance={min_dist})"
                        ),
                    )
                )

        return triggers
