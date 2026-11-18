"""Minimal PE32+ (x64) image reader for exception-table (.pdata) analysis.

Sekka accepts two kinds of input:

* on-disk PE files, where section raw offsets differ from RVAs, and
* memory-image captures (dumps), where the file offset equals the RVA.

:class:`Image` supports both transparently: RVA translation goes through
the section table first and falls back to a flat RVA==offset mapping.
Captures that carry a textual prefix (``REGION ...`` style headers) are
accepted as well; :func:`load` locates the ``MZ`` signature first.
"""

from __future__ import annotations

import struct

MZ = 0x4D5A
PE32PLUS_MAGIC = 0x20B

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

MACHINE_NAMES = {
    MACHINE_I386: "i386",
    MACHINE_AMD64: "amd64",
    MACHINE_ARM64: "arm64",
}

EXCEPTION_DIRECTORY_INDEX = 3  # DataDirectory[3] = exception table (.pdata)


class PEError(Exception):
    """Raised when input cannot be parsed as a usable PE image."""


class Section(object):
    __slots__ = ("name", "vsize", "vaddr", "rsize", "raw_off")

    def __init__(self, name, vsize, vaddr, rsize, raw_off):
        self.name = name
        self.vsize = vsize
        self.vaddr = vaddr
        self.rsize = rsize
        self.raw_off = raw_off

    def __repr__(self):
        return "Section(%r, vaddr=0x%x, vsize=0x%x)" % (self.name, self.vaddr, self.vsize)


class Image(object):
    """A parsed PE32+ image."""

    def __init__(self, data, name=""):
        self.data = data
        self.name = name
        if len(data) < 0x40:
            raise PEError("truncated image (no DOS header)")
        (self.e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if not (0x40 <= self.e_lfanew < 0x400) or self.e_lfanew + 24 + 240 > len(data):
            raise PEError("bad e_lfanew (0x%X)" % self.e_lfanew)
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("PE signature not found")
        (self.machine, number_of_sections, _timestamp, _symptr, _nsyms,
         size_of_optional_header, _characteristics) = struct.unpack_from(
            "<HHIIIHH", data, self.e_lfanew + 4)
        opt = self.e_lfanew + 24
        if size_of_optional_header < 112 or opt + size_of_optional_header > len(data):
            raise PEError("bad optional header size")
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic != PE32PLUS_MAGIC:
            raise PEError("not a PE32+ image (magic=0x%X)" % magic)
        (self.image_base,) = struct.unpack_from("<Q", data, opt + 24)
        (self.size_of_image,) = struct.unpack_from("<I", data, opt + 56)
        self.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        self.data_directories = []
        dd = opt + 112
        for i in range(16):
            if dd + i * 8 + 8 > len(data):
                break
            rva, size = struct.unpack_from("<II", data, dd + i * 8)
            self.data_directories.append((rva, size))
        self.sections = []
        sh = opt + size_of_optional_header
        for i in range(number_of_sections):
            off = sh + i * 40
            if off + 40 > len(data):
                break
            raw = data[off:off + 40]
            name = raw[0:8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, raw_off = struct.unpack_from("<IIII", raw, 8)
            self.sections.append(Section(name, vsize, vaddr, rsize, raw_off))

    # ------------------------------------------------------------------
    def machine_name(self):
        return MACHINE_NAMES.get(self.machine, "unknown(0x%X)" % self.machine)

    def va(self, rva):
        """Translate an RVA to a virtual address using ImageBase."""
        return self.image_base + rva

    def exception_dir(self):
        """Return the (rva, size) of the exception table directory."""
        if len(self.data_directories) > EXCEPTION_DIRECTORY_INDEX:
            return self.data_directories[EXCEPTION_DIRECTORY_INDEX]
        return (0, 0)

    def rva_to_off(self, rva):
        """Translate an RVA to an offset into this image's byte buffer.

        Section mapping is tried first; a flat RVA==offset fallback covers
        memory captures and header regions.
        """
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + s.rsize:
                return s.raw_off + (rva - s.vaddr)
        if 0 <= rva < len(self.data):
            return rva
        return None

    def read(self, rva, size):
        """Read *size* bytes at *rva*, or None when unavailable."""
        off = self.rva_to_off(rva)
        if off is None:
            return None
        chunk = self.data[off:off + size]
        if len(chunk) != size:
            return None
        return chunk


def load(data, name=""):
    """Parse raw bytes into an :class:`Image`, stripping any dump prefix.

    A textual capture header before the ``MZ`` signature (up to the first
    4096 bytes) is skipped automatically.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PEError("input must be a bytes-like object")
    image = bytes(data)
    mz = image.find(b"MZ", 0, 4096)
    if mz < 0:
        raise PEError("MZ signature not found in first 4096 bytes")
    return Image(image[mz:], name=name)
