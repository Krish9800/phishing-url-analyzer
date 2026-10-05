"""URL Lexical and structural parser decomposing web addresses into security components."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit

import idna

from phish_analyzer.core.defanger import refang_url
from phish_analyzer.core.entropy import calculate_shannon_entropy
from phish_analyzer.models.url_record import ParsedURL

# Common two-part public suffixes for accurate registered domain parsing
TWO_PART_TLDS = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "org.nz",
    "co.jp",
    "ne.jp",
    "co.kr",
    "com.br",
    "com.cn",
    "gov.cn",
    "edu.cn",
    "com.mx",
    "co.za",
    "com.sg",
    "co.in",
    "org.in",
    "gov.in",
}


class URLParser:
    """Safely extracts structural, domain, path, and cryptographic metrics from URLs."""

    @classmethod
    def parse(cls, raw_url: str) -> ParsedURL:
        """Parse, refang, and decompose a target URL.

        Args:
            raw_url: Input URL string (standard or defanged).

        Returns:
            Populated ParsedURL domain model.
        """
        cleaned = raw_url.strip()
        refanged = refang_url(cleaned)

        # Handle scheme-less URLs (e.g. "example.com/login" or "//example.com")
        working_url = refanged
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", working_url):
            if working_url.startswith("//"):
                working_url = "http:" + working_url
            else:
                working_url = "http://" + working_url

        try:
            parts = urlsplit(working_url)
        except ValueError:
            # Malformed URL split fallback
            return ParsedURL(
                raw_url=raw_url,
                refanged_url=refanged,
                scheme="unknown",
                netloc="",
                hostname="",
            )

        scheme = parts.scheme.lower()
        netloc = parts.netloc
        path = unquote(parts.path)
        query = parts.query
        fragment = parts.fragment
        port = parts.port

        # Extract pure hostname (strip port and credentials if present)
        hostname = parts.hostname or ""
        hostname = hostname.strip().lower()

        # Check for IP address
        has_ip_host = False
        try:
            ipaddress.ip_address(hostname)
            has_ip_host = True
        except ValueError:
            # Check for alternative numeric/hex/octal representations
            if re.match(r"^(0x[0-9a-fA-F]+|[0-9]+)$", hostname):
                has_ip_host = True

        # Check for Punycode
        is_punycode = "xn--" in hostname
        decoded_punycode: str | None = None
        if is_punycode:
            try:
                decoded_punycode = idna.decode(hostname)
            except (idna.IDNAError, UnicodeError):
                decoded_punycode = None

        # Decompose domain labels
        subdomains: list[str] = []
        registered_domain = ""
        tld = ""

        if not has_ip_host and "." in hostname:
            labels = hostname.split(".")
            # Check two-part TLD match
            if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_TLDS:
                tld = ".".join(labels[-2:])
                registered_domain = f"{labels[-3]}.{tld}"
                subdomains = labels[:-3]
            elif len(labels) >= 2:
                tld = labels[-1]
                registered_domain = f"{labels[-2]}.{tld}"
                subdomains = labels[:-2]
            else:
                tld = labels[-1]
                registered_domain = hostname
        elif not has_ip_host:
            registered_domain = hostname

        # Calculate lexical entropies
        domain_entropy = calculate_shannon_entropy(registered_domain or hostname)
        path_entropy = calculate_shannon_entropy(path)

        return ParsedURL(
            raw_url=raw_url,
            refanged_url=refanged,
            scheme=scheme,
            netloc=netloc,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            tld=tld,
            registered_domain=registered_domain,
            subdomains=subdomains,
            subdomain_depth=len(subdomains),
            has_ip_host=has_ip_host,
            is_punycode=is_punycode,
            decoded_punycode=decoded_punycode,
            domain_entropy=domain_entropy,
            path_entropy=path_entropy,
        )
