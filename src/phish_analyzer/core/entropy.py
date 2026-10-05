"""Shannon entropy computation for lexical and algorithmic randomness detection."""

import math
from collections import Counter


def calculate_shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of an input string in bits per character.

    Formula:
        H(X) = - sum( P(x) * log2(P(x)) )

    Args:
        text: String sequence (e.g. domain label, path, query).

    Returns:
        Entropy float value >= 0.0. Higher values signify greater randomness.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)
