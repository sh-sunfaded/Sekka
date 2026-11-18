"""Plaintext/ciphertext heuristics for multi-capture selection.

When several snapshots of the same image exist (for example captures taken
at different moments of a run), the same region may be readable in one
snapshot and transformed beyond recognition in another.  This module
estimates, per capture, whether the page covering a target RVA looks like
ordinary structured data ("plain-like") or like high-entropy transformed
data ("cipher-like"), so callers can pick the right capture before parsing.
"""

from __future__ import annotations

import math

CIPHER_ENTROPY = 7.2
DEFAULT_PAGE = 0x1000


def shannon_entropy(data):
    """Shannon entropy (bits/byte) of a byte string."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / float(n)
            entropy -= p * math.log2(p)
    return entropy


def zero_ratio(data):
    if not data:
        return 1.0
    return data.count(0) / float(len(data))


def classify(data):
    """Verdict for a byte region: ``empty`` / ``cipher-like`` / ``plain-like``."""
    if not data or not any(data):
        return {"entropy": 0.0, "zero_ratio": 1.0, "verdict": "empty"}
    entropy = shannon_entropy(data)
    zeros = zero_ratio(data)
    if entropy >= CIPHER_ENTROPY and zeros < 0.02:
        verdict = "cipher-like"
    else:
        verdict = "plain-like"
    return {"entropy": round(entropy, 3), "zero_ratio": round(zeros, 4),
            "verdict": verdict}


def region(image, rva, size=0x10, page=DEFAULT_PAGE):
    """Classify the page of *image* that contains *rva*."""
    start = rva & ~(page - 1)
    data = image.read(start, page)
    if data is None:
        data = image.read(start, size)
    if data is None:
        return {"entropy": None, "zero_ratio": None, "verdict": "unavailable"}
    return classify(data)


def choose(images, rva, size=0x10, page=DEFAULT_PAGE):
    """Rank images by readability at *rva*.

    *images* is a mapping of name to :class:`sekka.pe.Image`.  Returns a list
    of ``{"name", "entropy", "zero_ratio", "verdict"}`` rows, plain-like
    first, then by ascending entropy.
    """
    rows = []
    for name in sorted(images):
        info = region(images[name], rva, size, page)
        rows.append(dict(info, name=name))
    rows.sort(key=lambda r: (0 if r["verdict"] == "plain-like" else 1,
                             r["entropy"] if r["entropy"] is not None else 99.0))
    return rows
