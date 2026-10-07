"""Shannon entropy scorer used by generic secret heuristics."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits) of *text*. Returns 0.0 for empty strings."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
