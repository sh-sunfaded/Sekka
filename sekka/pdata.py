"""RUNTIME_FUNCTION enumeration and lookup over the x64 exception table.

Each .pdata entry is a 12-byte RUNTIME_FUNCTION triple::

    struct RUNTIME_FUNCTION {
        ULONG BeginAddress;   // inclusive
        ULONG EndAddress;     // exclusive
        ULONG UnwindDataAddress;
    };

Entries are sorted by BeginAddress, and functions do not overlap.  When the
exception data directory is absent or empty, a section literally named
``.pdata`` is used as a fallback.  :func:`scan_candidates` provides a
brute-force fallback for captures whose directory is unreadable.
"""

from __future__ import annotations

import struct

from . import fastpath
from .pe import PEError

ENTRY_SIZE = 12

MAX_PLAUSIBLE_FUNCTION = 0x1000000  # 16 MB: beyond this a "function" is junk


class RuntimeFunction(object):
    __slots__ = ("begin", "end", "unwind")

    def __init__(self, begin, end, unwind):
        self.begin = begin
        self.end = end
        self.unwind = unwind

    def covers(self, rva):
        return self.begin <= rva < self.end

    def __repr__(self):
        return "RuntimeFunction(begin=0x%x, end=0x%x, unwind=0x%x)" % (
            self.begin, self.end, self.unwind)

    def to_dict(self):
        return {"begin_rva": self.begin, "end_rva": self.end, "unwind_rva": self.unwind}


def load_entries(image):
    """Enumerate all RUNTIME_FUNCTION entries present in *image*."""
    rva, size = image.exception_dir()
    if not rva or not size:
        for section in image.sections:
            if section.name == ".pdata":
                rva, size = section.vaddr, section.vsize
                break
    if not rva or not size:
        return []
    if fastpath.HAVE_NUMPY:
        triples = fastpath.load_entries(image, rva, size)
        if triples is not None:
            begins, ends, unwinds = triples
            return [RuntimeFunction(b, e, u)
                    for b, e, u in zip(begins, ends, unwinds)]
    entries = []
    for off in range(0, size - ENTRY_SIZE + 1, ENTRY_SIZE):
        chunk = image.read(rva + off, ENTRY_SIZE)
        if chunk is None:
            break
        begin, end, unwind = struct.unpack("<III", chunk)
        if begin == 0 or end <= begin or unwind == 0:
            continue
        entries.append(RuntimeFunction(begin, end, unwind))
    return entries


def lookup(image, rva):
    """Return the RUNTIME_FUNCTION covering *rva*, or None."""
    entries = load_entries(image)
    lo, hi = 0, len(entries)
    while lo < hi:
        mid = (lo + hi) // 2
        if entries[mid].begin <= rva:
            lo = mid + 1
        else:
            hi = mid
    if lo > 0 and entries[lo - 1].covers(rva):
        return entries[lo - 1]
    # Tolerate unsorted tables with a linear pass.
    for entry in entries:
        if entry.covers(rva):
            return entry
    return None


def scan_candidates(image, rva, limit=16):
    """Brute-force scan for plausible RUNTIME_FUNCTION entries covering *rva*.

    Used when the exception directory is missing or unreadable (for example
    when the directory itself was not readable at capture time).  Walks the
    whole image looking for 12-byte triples that cover the target and whose
    UnwindData resolves to a parseable UNWIND_INFO.  Returns a list of
    ``(offset, RuntimeFunction)`` pairs.

    With NumPy installed the offset pre-filter runs as one vectorized mask
    (:func:`sekka.fastpath.scan_triples`); per-candidate UNWIND_INFO
    validation stays pure either way.
    """
    from .unwind import parse as parse_unwind  # local import: avoids a cycle

    data = image.data
    results = []
    if fastpath.HAVE_NUMPY:
        for off in fastpath.scan_triples(data, rva, MAX_PLAUSIBLE_FUNCTION):
            begin, end, unwind = struct.unpack_from("<III", data, off)
            if unwind == 0 or image.rva_to_off(unwind) is None:
                continue
            try:
                parse_unwind(image, unwind)
            except PEError:
                continue
            results.append((off, RuntimeFunction(begin, end, unwind)))
            if len(results) >= limit:
                break
        return results
    n = len(data)
    for off in range(0, n - ENTRY_SIZE, 4):
        begin, end, unwind = struct.unpack_from("<III", data, off)
        if begin == 0 or not (begin <= rva < end):
            continue
        if end - begin > MAX_PLAUSIBLE_FUNCTION:
            continue
        if unwind == 0 or image.rva_to_off(unwind) is None:
            continue
        try:
            parse_unwind(image, unwind)
        except PEError:
            continue
        results.append((off, RuntimeFunction(begin, end, unwind)))
        if len(results) >= limit:
            break
    return results
