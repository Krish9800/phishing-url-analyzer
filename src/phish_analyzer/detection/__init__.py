"""Detection heuristic modules."""

from phish_analyzer.detection.ip_obfuscation import IPObfuscationDetector
from phish_analyzer.detection.lexical import LexicalDetector

__all__ = [
    "IPObfuscationDetector",
    "LexicalDetector",
]
