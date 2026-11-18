"""x64 UNWIND_INFO parsing (per the PE/COFF x64 exception-handling spec).

Layout of UNWIND_INFO (all offsets relative to the record start)::

    +0x0  Version:3 | Flags:5
    +0x1  SizeOfProlog
    +0x2  CountOfCodes
    +0x3  FrameRegister:4 | FrameOffset:4
    +0x4  UNWIND_CODE[CountOfCodes]   (2 bytes each)

    +0x4 + align4(CountOfCodes * 2):
          ULONG HandlerRva           when UNW_FLAG_EHANDLER / UHANDLER
          RUNTIME_FUNCTION chained  when UNW_FLAG_CHAININFO

Each UNWIND_CODE is ``[CodeOffset, Op | OpInfo << 4]``.
"""

from __future__ import annotations

import struct

from .pe import PEError
from .pdata import RuntimeFunction

UNW_FLAG_EHANDLER = 0x01
UNW_FLAG_UHANDLER = 0x02
UNW_FLAG_CHAININFO = 0x04

UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SPARE_CODE = 6
UWOP_EPILOG = 7
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10

OP_NAMES = {
    UWOP_PUSH_NONVOL: "UWOP_PUSH_NONVOL",
    UWOP_ALLOC_LARGE: "UWOP_ALLOC_LARGE",
    UWOP_ALLOC_SMALL: "UWOP_ALLOC_SMALL",
    UWOP_SET_FPREG: "UWOP_SET_FPREG",
    UWOP_SAVE_NONVOL: "UWOP_SAVE_NONVOL",
    UWOP_SAVE_NONVOL_FAR: "UWOP_SAVE_NONVOL_FAR",
    UWOP_SPARE_CODE: "UWOP_SPARE_CODE",
    UWOP_EPILOG: "UWOP_EPILOG",
    UWOP_SAVE_XMM128: "UWOP_SAVE_XMM128",
    UWOP_SAVE_XMM128_FAR: "UWOP_SAVE_XMM128_FAR",
    UWOP_PUSH_MACHFRAME: "UWOP_PUSH_MACHFRAME",
}

REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
XMM = ["xmm%d" % i for i in range(16)]


class UnwindCode(object):
    __slots__ = ("slot", "code_offset", "op", "op_info", "slots", "text")

    def __init__(self, slot, code_offset, op, op_info, slots, text):
        self.slot = slot
        self.code_offset = code_offset
        self.op = op
        self.op_info = op_info
        self.slots = slots
        self.text = text

    def to_dict(self):
        return {
            "slot": self.slot,
            "code_offset": self.code_offset,
            "op": OP_NAMES.get(self.op, "UNKNOWN_%d" % self.op),
            "op_info": self.op_info,
            "slots": self.slots,
            "text": self.text,
        }


def _decode_codes(raw, count):
    """Decode a UNWIND_CODE array into a list of :class:`UnwindCode`."""
    codes = []

    def u16(index):
        if 0 <= index < count and index * 2 + 2 <= len(raw):
            return struct.unpack_from("<H", raw, index * 2)[0]
        return 0

    i = 0
    while i < count:
        base = i
        code_offset = raw[i * 2] if i * 2 < len(raw) else 0
        op_byte = raw[i * 2 + 1] if i * 2 + 1 < len(raw) else 0
        op = op_byte & 0x0F
        info = op_byte >> 4
        i += 1
        text = None
        if op == UWOP_PUSH_NONVOL:
            text = "push %s" % REG64[info & 0x0F]
        elif op == UWOP_ALLOC_LARGE:
            if info == 0:
                value = u16(i)
                i += 1
                text = "sub rsp, 0x%X" % (value * 8)
            elif info == 1:
                value = u16(i) | (u16(i + 1) << 16)
                i += 2
                text = "sub rsp, 0x%X" % ((value & 0xFFFFFF) * 8)
            else:
                text = "ALLOC_LARGE(info=%d)" % info
        elif op == UWOP_ALLOC_SMALL:
            text = "sub rsp, 0x%X" % ((info + 1) * 8)
        elif op == UWOP_SET_FPREG:
            text = "set frame pointer (rsp = frame register - 0x%X*16)" % info
        elif op == UWOP_SAVE_NONVOL:
            value = u16(i)
            i += 1
            text = "save %s at frame offset 0x%X" % (REG64[info & 0x0F], value * 8)
        elif op == UWOP_SAVE_NONVOL_FAR:
            value = u16(i) | (u16(i + 1) << 16)
            i += 2
            text = "save %s at frame offset 0x%X" % (REG64[info & 0x0F], value * 8)
        elif op == UWOP_SAVE_XMM128:
            value = u16(i)
            i += 1
            text = "save %s at frame offset 0x%X" % (XMM[info & 0x0F], value * 16)
        elif op == UWOP_SAVE_XMM128_FAR:
            value = u16(i) | (u16(i + 1) << 16)
            i += 2
            text = "save %s at frame offset 0x%X" % (XMM[info & 0x0F], value * 16)
        elif op == UWOP_PUSH_MACHFRAME:
            text = "push machine frame (error code included)" if info == 1 else \
                "push machine frame (no error code)"
        elif op == UWOP_SPARE_CODE:
            text = "spare code"
        elif op == UWOP_EPILOG:
            text = "epilog marker (info=%d)" % info
        else:
            text = "unknown op %d (info=%d)" % (op, info)
        codes.append(UnwindCode(base, code_offset, op, info, i - base, text))
    return codes


class UnwindInfo(object):
    __slots__ = ("rva", "version", "flags", "size_of_prolog", "count_of_codes",
                 "frame_register", "frame_offset", "codes", "handler_rva", "chained")

    def __init__(self, rva, version, flags, size_of_prolog, count_of_codes,
                 frame_register, frame_offset, codes, handler_rva, chained):
        self.rva = rva
        self.version = version
        self.flags = flags
        self.size_of_prolog = size_of_prolog
        self.count_of_codes = count_of_codes
        self.frame_register = frame_register
        self.frame_offset = frame_offset
        self.codes = codes
        self.handler_rva = handler_rva
        self.chained = chained

    def flag_names(self):
        names = []
        if self.flags & UNW_FLAG_EHANDLER:
            names.append("EHANDLER")
        if self.flags & UNW_FLAG_UHANDLER:
            names.append("UHANDLER")
        if self.flags & UNW_FLAG_CHAININFO:
            names.append("CHAININFO")
        return names

    def to_dict(self):
        return {
            "rva": self.rva,
            "version": self.version,
            "flags": self.flags,
            "flag_names": self.flag_names(),
            "size_of_prolog": self.size_of_prolog,
            "count_of_codes": self.count_of_codes,
            "frame_register": self.frame_register,
            "frame_offset": self.frame_offset,
            "codes": [c.to_dict() for c in self.codes],
            "handler_rva": self.handler_rva,
            "chained": self.chained.to_dict() if self.chained is not None else None,
        }


def parse(image, unwind_rva):
    """Parse the UNWIND_INFO record at *unwind_rva* in *image*."""
    header = image.read(unwind_rva, 4)
    if header is None:
        raise PEError("unwind info at rva 0x%X is outside the image" % unwind_rva)
    b0, size_of_prolog, count, frame = header
    version = b0 & 0x07
    flags = (b0 >> 3) & 0x1F
    if version != 1:
        raise PEError("unsupported UNWIND_INFO version %d at rva 0x%X"
                      % (version, unwind_rva))
    raw = b""
    if count:
        raw = image.read(unwind_rva + 4, count * 2)
        if raw is None:
            raise PEError("unwind code array at rva 0x%X is truncated"
                          % (unwind_rva + 4))
    codes = _decode_codes(raw, count)
    param_off = 4 + ((count * 2 + 3) & ~3)
    handler_rva = None
    chained = None
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        chunk = image.read(unwind_rva + param_off, 4)
        if chunk is None:
            raise PEError("handler rva at 0x%X is outside the image"
                          % (unwind_rva + param_off))
        (handler_rva,) = struct.unpack("<I", chunk)
    if flags & UNW_FLAG_CHAININFO:
        chunk = image.read(unwind_rva + param_off, 12)
        if chunk is None:
            raise PEError("chained entry at 0x%X is outside the image"
                          % (unwind_rva + param_off))
        begin, end, next_unwind = struct.unpack("<III", chunk)
        chained = RuntimeFunction(begin, end, next_unwind)
    return UnwindInfo(unwind_rva, version, flags, size_of_prolog, count,
                      frame >> 4, frame & 0x0F, codes, handler_rva, chained)


def resolve_chain(image, unwind_rva, max_depth=8):
    """Follow UNW_FLAG_CHAININFO links; return the list of UnwindInfo."""
    infos = []
    seen = set()
    rva = unwind_rva
    while rva and len(infos) < max_depth:
        if rva in seen:
            break
        seen.add(rva)
        info = parse(image, rva)
        infos.append(info)
        rva = info.chained.unwind if info.chained is not None else None
    return infos
