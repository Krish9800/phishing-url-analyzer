"""Core utilities for URL parsing, entropy analysis, and defanging."""

from phish_analyzer.core.defanger import (
    defang_domain,
    defang_ip,
    defang_url,
    refang_url,
)
from phish_analyzer.core.entropy import calculate_shannon_entropy
from phish_analyzer.core.parser import URLParser

__all__ = [
    "URLParser",
    "calculate_shannon_entropy",
    "defang_domain",
    "defang_ip",
    "defang_url",
    "refang_url",
]
