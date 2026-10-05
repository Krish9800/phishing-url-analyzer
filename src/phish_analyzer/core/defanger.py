"""Safe URL and IP defanging utilities to prevent accidental execution."""

import re


def defang_url(url: str) -> str:
    """Defang a URL for safe display in consoles, tickets, and SIEM logs.

    Transforms:
        - http:// -> hxxp://
        - https:// -> hxxps://
        - ftp:// -> fxp://
        - . -> [.]
        - @ -> [@]
    """
    if not url:
        return ""

    defanged = url
    # Defang scheme
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)

    # Defang periods and @ symbols in host and path
    defanged = defanged.replace(".", "[.]")
    defanged = defanged.replace("@", "[@]")

    return defanged


def refang_url(url: str) -> str:
    """Normalize a defanged URL back into a standard URL for algorithmic analysis.

    Reverses:
        - hxxps:// -> https://
        - hxxp:// -> http://
        - fxp:// -> ftp://
        - [.] / (dot) / {.} -> .
        - [@] / (at) / {@} -> @
        - [:] -> :
    """
    if not url:
        return ""

    refanged = url.strip()
    # Normalize common bracketed dots
    refanged = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", refanged)
    # Normalize bracketed at signs
    refanged = re.sub(r"\[@\]|\(@\)|\{@\}", "@", refanged)
    # Normalize bracketed colons
    refanged = re.sub(r"\[:\]|\(:\)|\{:\}", ":", refanged)

    # Reconstruct scheme
    refanged = re.sub(r"^hxxps://", "https://", refanged, flags=re.IGNORECASE)
    refanged = re.sub(r"^hxxp://", "http://", refanged, flags=re.IGNORECASE)
    refanged = re.sub(r"^fxp://", "ftp://", refanged, flags=re.IGNORECASE)

    return refanged


def defang_domain(domain: str) -> str:
    """Defang a domain name string (e.g. evil.com -> evil[.]com)."""
    if not domain:
        return ""
    return domain.replace(".", "[.]")


def defang_ip(ip_address: str) -> str:
    """Defang an IP address string (e.g. 1.2.3.4 -> 1[.]2[.]3[.]4)."""
    if not ip_address:
        return ""
    return ip_address.replace(".", "[.]")
