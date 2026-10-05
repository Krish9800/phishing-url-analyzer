"""IDN homoglyph, Punycode, and Unicode confusable spoofing detector."""

import unicodedata

import idna

from phish_analyzer.config.settings import settings
from phish_analyzer.models.heuristic import HeuristicSeverity, HeuristicTrigger
from phish_analyzer.models.url_record import ParsedURL

# Comprehensive mapping of common visual confusable glyphs (Cyrillic, Greek, Latin lookalikes)
CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es (c)
    "\u0434": "d",  # Cyrillic small letter de
    "\u0435": "e",  # Cyrillic small letter ie (e)
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er (p)
    "\u0455": "s",  # Cyrillic small letter dze (s)
    "\u0443": "y",  # Cyrillic small letter u (y)
    "\u0445": "x",  # Cyrillic small letter ha (x)
    # Greek lowercase
    "\u03b1": "a",  # Greek small letter alpha
    "\u03b2": "b",  # Greek small letter beta
    "\u03b5": "e",  # Greek small letter epsilon
    "\u03b9": "i",  # Greek small letter iota
    "\u03ba": "k",  # Greek small letter kappa
    "\u03bf": "o",  # Greek small letter omicron
    "\u03c1": "p",  # Greek small letter rho
    "\u03c5": "u",  # Greek small letter upsilon
    "\u03bd": "v",  # Greek small letter nu
    "\u03c7": "x",  # Greek small letter chi
    # Additional lookalikes
    "\u0251": "a",  # Latin small letter alpha
    "\u0131": "i",  # Latin small letter dotless i
    "\u0261": "g",  # Latin small letter script g
    "\u00f8": "o",  # Latin small letter o with stroke
}


class HomoglyphDetector:
    """Detects Internationalized Domain Name (IDN) homoglyph spoofing and Punycode attacks."""

    @classmethod
    def normalize_confusables(cls, text: str) -> tuple[str, list[tuple[str, str, str]]]:
        """Translate confusable Unicode glyphs to standard Latin equivalents.

        Args:
            text: Input string (domain label or path).

        Returns:
            Tuple of (normalized_latin_text, list_of_confusables_found)
            where each confusable is (char, latin_equivalent, unicode_name).
        """
        normalized_chars: list[str] = []
        found_confusables: list[tuple[str, str, str]] = []

        for char in text:
            if char in CONFUSABLE_MAP:
                latin_equiv = CONFUSABLE_MAP[char]
                try:
                    u_name = unicodedata.name(char)
                except ValueError:
                    u_name = "UNKNOWN_UNICODE"
                found_confusables.append((char, latin_equiv, u_name))
                normalized_chars.append(latin_equiv)
            else:
                normalized_chars.append(char)

        return "".join(normalized_chars), found_confusables

    @classmethod
    def detect(cls, parsed_url: ParsedURL) -> list[HeuristicTrigger]:
        """Analyze hostname for Punycode encoding, mixed scripts, and homoglyphs.

        Args:
            parsed_url: Structured ParsedURL model.

        Returns:
            List of triggered security heuristics.
        """
        triggers: list[HeuristicTrigger] = []
        host = parsed_url.hostname.lower()
        if not host:
            return triggers

        # 1. Inspect Punycode encoding
        unicode_host = host
        if parsed_url.is_punycode or "xn--" in host:
            try:
                unicode_host = idna.decode(host)
            except (idna.IDNAError, UnicodeError):
                unicode_host = host

            triggers.append(
                HeuristicTrigger(
                    rule_id="PUNYCODE_DOMAIN_PRESENT",
                    name="Punycode (IDN) Encoded Hostname",
                    severity=HeuristicSeverity.MEDIUM,
                    score_weight=15,
                    description=(
                        "Hostname uses Punycode (xn--) encoding. While valid for non-ASCII "
                        "languages, it is frequently leveraged to visually impersonate "
                        f"brands: '{unicode_host}'."
                    ),
                    evidence=f"punycode='{host}' -> unicode='{unicode_host}'",
                )
            )

        # 2. Check for confusable characters in Unicode host
        normalized_host, confusables = cls.normalize_confusables(unicode_host)

        if confusables:
            confusable_summary = ", ".join(f"'{c[0]}' ({c[2]}) -> '{c[1]}'" for c in confusables)

            # Check if normalized domain targets a monitored high-value brand
            targeted_brand: str | None = None
            for brand in settings.TARGETED_BRANDS:
                if brand in normalized_host:
                    targeted_brand = brand
                    break

            if targeted_brand:
                triggers.append(
                    HeuristicTrigger(
                        rule_id="HOMOGLYPH_BRAND_IMPERSONATION",
                        name="Homoglyph IDN Brand Impersonation Attack",
                        severity=HeuristicSeverity.CRITICAL,
                        score_weight=35,
                        description=(
                            f"Host visually mimics protected brand '{targeted_brand}' by "
                            f"substituting Latin characters with confusable Unicode lookalikes: "
                            f"{confusable_summary}."
                        ),
                        evidence=(
                            f"original='{unicode_host}' -> normalized='{normalized_host}' "
                            f"(brand: {targeted_brand})"
                        ),
                    )
                )
            else:
                triggers.append(
                    HeuristicTrigger(
                        rule_id="UNICODE_CONFUSABLE_GLYPHS",
                        name="Unicode Confusable Characters Detected",
                        severity=HeuristicSeverity.HIGH,
                        score_weight=25,
                        description=(
                            f"Host contains {len(confusables)} visual confusable character(s): "
                            f"{confusable_summary}."
                        ),
                        evidence=f"original='{unicode_host}' -> normalized='{normalized_host}'",
                    )
                )

        return triggers
