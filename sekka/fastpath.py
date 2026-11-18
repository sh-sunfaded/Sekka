"""NumPy-vectorized hot paths (optional dependency).

The core always runs on the standard library alone.  When NumPy is
installed, hot paths switch automatically to vectorized implementations
(see :data:`HAVE_NUMPY`).  Equivalence between the two implementations is
guarded by the test suite; on NumPy-less environments those tests skip
and the core runs the pure implementations.

What gets vectorized:

- shannon_entropy / zero_ratio:
    the byte histogram is built with one ``bincount`` call and the zero
    ratio with one equality mask (the per-byte Python loop disappears).
- RUNTIME_FUNCTION extraction (pdata.load_entries):
    the whole directory is read once and viewed as a ``(N, 3)`` ``<u4``
    matrix; invalid entries (begin == 0, end <= begin, unwind == 0) are
    removed with a single boolean mask.
- scan_candidates pre-filter (pdata.scan_candidates):
    the capture is viewed as a ``<u4`` array and every 4-aligned offset is
    tested at once with masks (covers target, plausible size, non-null
    unwind).

What stays pure (sequential by nature, or already cheap):

- UNWIND_CODE decoding (a slot-walking state machine),
- the binary search in lookup (already O(log n)),
- per-candidate UNWIND_INFO validation (bounded by the candidate count).
"""
from __future__ import annotations

try:
    import numpy as _np
    HAVE_NUMPY = True
except ImportError:  # pragma: no cover - environment dependent
    _np = None
    HAVE_NUMPY = False


def _require_numpy():
    if _np is None:
        raise RuntimeError("sekka.fastpath requires numpy (not installed)")


def shannon_entropy(data):
    """Vectorized :func:`sekka.state.shannon_entropy`."""
    _require_numpy()
    arr = _np.frombuffer(data, dtype=_np.uint8)
    n = int(arr.size)
    if n == 0:
        return 0.0
    counts = _np.bincount(arr, minlength=256).astype(_np.float64)
    p = counts / n
    nz = p > 0
    return float(-(p[nz] * _np.log2(p[nz])).sum())


def zero_ratio(data):
    """Vectorized :func:`sekka.state.zero_ratio`."""
    _require_numpy()
    arr = _np.frombuffer(data, dtype=_np.uint8)
    if arr.size == 0:
        return 1.0
    return float(int((arr == 0).sum())) / float(int(arr.size))


def load_entries(image, rva, size):
    """Extract RUNTIME_FUNCTION triples from ``[rva, rva + size)``.

    Returns ``(begins, ends, unwinds)`` lists, or ``None`` when the
    directory is not fully readable; the caller then falls back to the
    pure loop, which can consume a truncated directory entry by entry.
    """
    _require_numpy()
    usable = (size // 12) * 12
    if usable <= 0:
        return [], [], []
    chunk = image.read(rva, usable)
    if chunk is None:
        return None
    view = _np.frombuffer(chunk, dtype="<u4").reshape(-1, 3)
    begin = view[:, 0]
    end = view[:, 1]
    unwind = view[:, 2]
    mask = (begin != 0) & (end > begin) & (unwind != 0)
    rows = view[mask]
    return rows[:, 0].tolist(), rows[:, 1].tolist(), rows[:, 2].tolist()


def scan_triples(data, rva, max_size):
    """4-aligned offsets whose (begin, end, unwind) triple covers *rva*.

    Vectorized mask pre-filter of :func:`sekka.pdata.scan_candidates`;
    the caller validates each offset (UNWIND_INFO parse) afterwards.
    """
    _require_numpy()
    usable = len(data) - (len(data) % 4)
    if usable < 12:
        return []
    v = _np.frombuffer(data[:usable], dtype="<u4")
    n = int(v.size)
    if n < 3:
        return []
    begin = v[: n - 2]
    end = v[1: n - 1]
    unwind = v[2:]
    mask = ((begin != 0) & (begin <= rva) & (end > rva)
            & ((end - begin) <= max_size) & (unwind != 0))
    return (_np.flatnonzero(mask) * 4).tolist()
