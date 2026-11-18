"""Sekka test suite (pure standard library, synthetic fixtures only).

Every test builds a small synthetic PE32+ image in memory with a known
.pdata / UNWIND_INFO layout and verifies the parsers against it.
Run with:  python3 tests/test_sekka.py
"""

import contextlib
import io
import json
import os
import random
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sekka import cli, fastpath, pe, pdata  # noqa: E402
from sekka import unwind as uw  # noqa: E402
from sekka.state import classify, choose, shannon_entropy, zero_ratio  # noqa: E402

# ----------------------------------------------------------------------
# Synthetic PE32+ builder
# ----------------------------------------------------------------------

BASE = 0x140000000
AMD64 = 0x8664
OPT = 0x58           # optional header offset (after 0x40 PE + 0x18 COFF)
SIZE_OPT = 240       # PE32+ optional header with 16 data directories
SECT_OFF = 0x148


def build_image(sections, base=BASE, machine=AMD64, raw_mode=False,
                dir_exception=None, magic=0x20B):
    """Build a synthetic PE32+ image.

    sections: list of (name, rva, data).
    raw_mode=False: file offset == RVA (memory capture layout).
    raw_mode=True:  sections are packed at 0x200-aligned file offsets.
    """
    n = len(sections)
    if SECT_OFF + 40 * n > 0x400:
        raise ValueError("too many sections")
    hdr = bytearray(b"\x00" * 0x400)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x40)
    hdr[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, 0x44, machine, n, 0, 0, 0, SIZE_OPT, 0x22)
    struct.pack_into("<H", hdr, OPT, magic)
    struct.pack_into("<Q", hdr, OPT + 24, base)

    table = []
    size_of_image = 0x1000
    raw_cursor = 0x400
    for name, rva, data in sections:
        vsize = len(data)
        if raw_mode:
            rsize = (vsize + 0x1FF) & ~0x1FF
            raw_off = raw_cursor
            raw_cursor += rsize
        else:
            rsize = vsize
            raw_off = rva
        table.append((name, rva, vsize, rsize, raw_off))
        size_of_image = max(size_of_image, rva + vsize)
    size_of_image = (size_of_image + 0xFFF) & ~0xFFF
    struct.pack_into("<I", hdr, OPT + 56, size_of_image)
    struct.pack_into("<I", hdr, OPT + 60, 0x400)
    for i, (name, rva, vsize, rsize, raw_off) in enumerate(table):
        off = SECT_OFF + i * 40
        hdr[off:off + 8] = name.encode("ascii").ljust(8, b"\x00")
        struct.pack_into("<IIII", hdr, off + 8, vsize, rva, rsize, raw_off)
    if dir_exception:
        struct.pack_into("<II", hdr, OPT + 112 + 3 * 8,
                         dir_exception[0], dir_exception[1])

    body = bytearray(hdr)
    for (name, rva, data) in sections:
        info = [t for t in table if t[0] == name and t[1] == rva][0]
        raw_off = info[4]
        end = raw_off + len(data)
        if len(body) < end:
            body.extend(b"\x00" * (end - len(body)))
        body[raw_off:end] = data
    return bytes(body)


def rfun(begin, end, unwind_rva):
    return struct.pack("<III", begin, end, unwind_rva)


def unwind_info_blob(flags=0, prolog=0, codes=b"", handler=None,
                    chained=None, frame_reg=0, frame_off=0, version=1):
    count = len(codes) // 2
    head = bytes([(version & 0x07) | ((flags & 0x1F) << 3), prolog, count,
                  ((frame_reg << 4) | frame_off) & 0xFF])
    body = bytearray(head)
    body += codes
    while len(body) % 4:
        body += b"\x00"
    if flags & (uw.UNW_FLAG_EHANDLER | uw.UNW_FLAG_UHANDLER):
        body += struct.pack("<I", handler)
    if flags & uw.UNW_FLAG_CHAININFO:
        body += chained
    return bytes(body)


E = uw.UNW_FLAG_EHANDLER
U = uw.UNW_FLAG_UHANDLER
CHAIN = uw.UNW_FLAG_CHAININFO

# Shared fixtures -----------------------------------------------------
# .rdata layout: blob_A@0x2000 (12B) blob_B@0x200C (8B)
#                 blob_C@0x2014 (16B) blob_D@0x2024 (8B)

BLOB_A = unwind_info_blob(flags=E, prolog=3, codes=b"\x01\x50", handler=0xBEEF)
BLOB_B = unwind_info_blob(flags=U, prolog=0, codes=b"", handler=0x1234)
BLOB_C = unwind_info_blob(flags=CHAIN, prolog=0, codes=b"",
                          chained=rfun(0x1500, 0x1600, 0x2024))
BLOB_D = unwind_info_blob(flags=E, prolog=0, codes=b"", handler=0x5678)
RDATA = BLOB_A + BLOB_B + BLOB_C + BLOB_D
assert len(BLOB_A) == 12 and len(BLOB_B) == 8 and len(BLOB_C) == 16 \
    and len(BLOB_D) == 8

ENTRY_D = rfun(0x1500, 0x1600, 0x2024)
ENTRY_A = rfun(0x1400, 0x1500, 0x2000)
ENTRY_B = rfun(0x1600, 0x1700, 0x200C)
ENTRY_C = rfun(0x1800, 0x1900, 0x2014)
PDATA = ENTRY_D + ENTRY_A + ENTRY_B + ENTRY_C
TEXT = b"\x48\x89\x5c\x24\x08" + b"\x90" * 0xFB


def std_sections(text=TEXT, pdata_bytes=PDATA):
    return [
        (".text", 0x1000, text),
        (".rdata", 0x2000, RDATA),
        (".pdata", 0x3000, pdata_bytes),
    ]


def std_image(**kwargs):
    kw = dict(raw_mode=False, dir_exception=(0x3000, len(PDATA)))
    kw.update(kwargs)
    return pe.load(build_image(std_sections(**{k: kw.pop(k) for k in list(kw)
                                               if k in ("text", "pdata_bytes")}),
                               **kw))


def make_single(blob, entry=(0x1400, 0x1500, 0x2000)):
    sections = [
        (".text", 0x1000, b"\x90" * 0x1000),
        (".rdata", 0x2000, blob),
        (".pdata", 0x3000, rfun(*entry)),
    ]
    return pe.load(build_image(sections, dir_exception=(0x3000, 12)))


class TestPELoading(unittest.TestCase):
    def test_load_flat(self):
        img = std_image()
        self.assertEqual(img.machine, AMD64)
        self.assertEqual(img.image_base, BASE)
        self.assertEqual(img.size_of_image, 0x4000)
        self.assertEqual([s.name for s in img.sections],
                         [".text", ".rdata", ".pdata"])

    def test_load_raw_mode(self):
        raw = pe.load(build_image(std_sections(), raw_mode=True,
                                  dir_exception=(0x3000, len(PDATA))))
        self.assertNotEqual(raw.rva_to_off(0x1400), 0x1400)
        self.assertEqual(raw.read(0x1000, 5), b"\x48\x89\x5c\x24\x08")
        self.assertEqual(raw.read(0x2000, 4), BLOB_A[0:4])

    def test_load_strips_text_prefix(self):
        prefixed = b"REGION image addr=140000000 size=4000\n" + \
            build_image(std_sections(), dir_exception=(0x3000, len(PDATA)))
        img = pe.load(prefixed)
        self.assertEqual(img.read(0x1000, 5), b"\x48\x89\x5c\x24\x08")

    def test_load_rejects_garbage(self):
        with self.assertRaises(pe.PEError):
            pe.load(b"nope" * 100)

    def test_load_rejects_pe32(self):
        blob = build_image(std_sections(), magic=0x10B)
        with self.assertRaises(pe.PEError):
            pe.load(blob)

    def test_load_bad_lfanew(self):
        blob = bytearray(build_image(std_sections(),
                                     dir_exception=(0x3000, len(PDATA))))
        struct.pack_into("<I", blob, 0x3C, 0)
        with self.assertRaises(pe.PEError):
            pe.load(bytes(blob))


class TestRVAMapping(unittest.TestCase):
    def setUp(self):
        self.flat = std_image()
        self.raw = pe.load(build_image(std_sections(), raw_mode=True,
                                       dir_exception=(0x3000, len(PDATA))))

    def test_read_flat(self):
        self.assertEqual(self.flat.read(0x2000, 4), BLOB_A[0:4])

    def test_read_raw(self):
        self.assertEqual(self.raw.read(0x2000, 4), BLOB_A[0:4])

    def test_read_out_of_range(self):
        self.assertIsNone(self.flat.read(0x40000, 4))
        self.assertIsNone(self.raw.read(0x40000, 4))


class TestPdata(unittest.TestCase):
    def setUp(self):
        self.img = std_image()

    def test_entries_count(self):
        self.assertEqual(len(pdata.load_entries(self.img)), 4)

    def test_lookup_begin_inclusive(self):
        self.assertEqual(pdata.lookup(self.img, 0x1400).unwind, 0x2000)

    def test_lookup_interior(self):
        self.assertEqual(pdata.lookup(self.img, 0x1450).unwind, 0x2000)

    def test_lookup_end_exclusive(self):
        self.assertIsNone(pdata.lookup(self.img, 0x1700))

    def test_lookup_miss(self):
        self.assertIsNone(pdata.lookup(self.img, 0x1100))

    def test_fallback_pdata_section(self):
        img = std_image(dir_exception=None)
        self.assertIsNotNone(pdata.lookup(img, 0x1400))

    def test_lookup_unsorted_table(self):
        unsorted = ENTRY_C + ENTRY_A + ENTRY_D + ENTRY_B
        img = std_image(pdata_bytes=unsorted)
        self.assertEqual(pdata.lookup(img, 0x1400).unwind, 0x2000)


class TestUnwindParse(unittest.TestCase):
    def setUp(self):
        self.img = std_image()

    def test_parse_ehandler(self):
        info = uw.parse(self.img, 0x2000)
        self.assertEqual(info.version, 1)
        self.assertEqual(info.flags, E)
        self.assertEqual(info.size_of_prolog, 3)
        self.assertEqual(info.count_of_codes, 1)
        self.assertEqual(info.handler_rva, 0xBEEF)

    def test_parse_uhandler(self):
        info = uw.parse(self.img, 0x200C)
        self.assertEqual(info.flag_names(), ["UHANDLER"])
        self.assertEqual(info.count_of_codes, 0)
        self.assertEqual(info.handler_rva, 0x1234)

    def test_parse_chaininfo(self):
        info = uw.parse(self.img, 0x2014)
        self.assertEqual(info.flag_names(), ["CHAININFO"])
        self.assertIsNone(info.handler_rva)
        self.assertEqual((info.chained.begin, info.chained.end,
                          info.chained.unwind), (0x1500, 0x1600, 0x2024))
        chain = uw.resolve_chain(self.img, 0x2014)
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[-1].handler_rva, 0x5678)

    def test_parse_bad_version(self):
        img = make_single(unwind_info_blob(flags=E, version=2, handler=1))
        with self.assertRaises(pe.PEError):
            uw.parse(img, 0x2000)

    def test_parse_truncated(self):
        end = len(self.img.data)
        with self.assertRaises(pe.PEError):
            uw.parse(self.img, end - 2)

    def test_handler_alignment_odd_count(self):
        blob = unwind_info_blob(flags=E, prolog=6,
                                codes=b"\x01\x50\x02\x30\x03\x52",
                                handler=0x9999)
        img = make_single(blob)
        info = uw.parse(img, 0x2000)
        self.assertEqual(info.count_of_codes, 3)
        self.assertEqual(info.handler_rva, 0x9999)


class TestUnwindCodeDecode(unittest.TestCase):
    def _codes(self, codes):
        blob = unwind_info_blob(flags=E, codes=codes, handler=0x1)
        return uw.parse(make_single(blob), 0x2000).codes

    def test_push_nonvol(self):
        self.assertEqual(self._codes(b"\x01\x50")[0].text, "push rbp")

    def test_alloc_small(self):
        self.assertEqual(self._codes(b"\x03\x52")[0].text, "sub rsp, 0x30")

    def test_alloc_large_16bit(self):
        codes = self._codes(b"\x04\x01" + struct.pack("<H", 0x100))
        self.assertEqual(codes[0].text, "sub rsp, 0x800")
        self.assertEqual(codes[0].slots, 2)

    def test_alloc_large_24bit(self):
        raw = b"\x05\x11" + struct.pack("<HH", 0x3456, 0x0012)
        codes = self._codes(raw)
        self.assertEqual(codes[0].text, "sub rsp, 0x91A2B0")
        self.assertEqual(codes[0].slots, 3)

    def test_save_nonvol(self):
        codes = self._codes(b"\x05\x14" + struct.pack("<H", 0x10))
        self.assertEqual(codes[0].text, "save rcx at frame offset 0x80")

    def test_save_xmm128(self):
        raw = b"\x07\x68" + struct.pack("<H", 0x20)
        self.assertEqual(self._codes(raw)[0].text, "save xmm6 at frame offset 0x200")

    def test_push_machframe(self):
        self.assertEqual(self._codes(b"\x08\x1A")[0].text,
                         "push machine frame (error code included)")

    def test_unknown_op(self):
        code = self._codes(b"\x09\x2F")[0]
        self.assertTrue(code.text.startswith("unknown op"))


class TestState(unittest.TestCase):
    def test_entropy_zero(self):
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)

    def test_entropy_random(self):
        rng = random.Random(42)
        self.assertGreater(shannon_entropy(rng.randbytes(0x1000)), 7.5)

    def test_classify_verdicts(self):
        rng = random.Random(7)
        self.assertEqual(classify(rng.randbytes(0x1000))["verdict"], "cipher-like")
        self.assertEqual(classify(b"\x00" * 0x100)["verdict"], "empty")
        self.assertEqual(classify(b"\x90" * 0x1000)["verdict"], "plain-like")

    def test_choose_prefers_plain(self):
        rng = random.Random(9)
        plain = std_image()
        cipher = std_image(text=rng.randbytes(0x1000))
        rows = choose({"a-cipher.bin": cipher, "b-plain.bin": plain}, 0x1400)
        self.assertEqual(rows[0]["name"], "b-plain.bin")
        self.assertEqual(rows[0]["verdict"], "plain-like")
        self.assertEqual(rows[1]["verdict"], "cipher-like")


class TestScan(unittest.TestCase):
    def test_scan_finds_hidden_entries(self):
        # Directory empty, entries buried in .rdata (no .pdata section).
        sections = [
            (".text", 0x1000, b"\x90" * 0x1000),
            (".rdata", 0x2000, RDATA + PDATA),
        ]
        img = pe.load(build_image(sections))
        self.assertIsNone(pdata.lookup(img, 0x1400))
        candidates = pdata.scan_candidates(img, 0x1400)
        self.assertEqual(len(candidates), 1)
        off, entry = candidates[0]
        self.assertEqual(entry.unwind, 0x2000)
        self.assertEqual(off, 0x2038)

    def test_scan_no_candidates_in_junk(self):
        rng = random.Random(3)
        sections = [(".text", 0x1000, rng.randbytes(0x2000))]
        img = pe.load(build_image(sections))
        self.assertEqual(pdata.scan_candidates(img, 0x1400), [])


def run_cli(argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "std-image.bin")
        with open(self.path, "wb") as fh:
            fh.write(build_image(std_sections(),
                                 dir_exception=(0x3000, len(PDATA))))

    def tearDown(self):
        self.tmp.cleanup()

    def test_lookup_text(self):
        code, out, _ = run_cli(["lookup", self.path, "--rva", "0x1400"])
        self.assertEqual(code, 0)
        self.assertIn("image: std-image.bin", out)
        self.assertIn("language handler: rva 0xBEEF", out)

    def test_lookup_json(self):
        code, out, _ = run_cli(["lookup", self.path, "--rva", "0x1400",
                                "--json"])
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual(rows[0]["unwind"]["handler_rva"], 0xBEEF)
        self.assertEqual(rows[0]["function"]["begin_rva"], 0x1400)

    def test_lookup_missing_exit_code(self):
        code, _, err = run_cli(["lookup", self.path, "--rva", "0x1100"])
        self.assertEqual(code, 2)
        self.assertIn("no RUNTIME_FUNCTION", err)

    def test_lookup_scan_fallback(self):
        scan_path = os.path.join(self.tmp.name, "scan-image.bin")
        with open(scan_path, "wb") as fh:
            fh.write(build_image([
                (".text", 0x1000, b"\x90" * 0x1000),
                (".rdata", 0x2000, RDATA + PDATA),
            ]))
        code, out, _ = run_cli(["lookup", scan_path, "--rva", "0x1400",
                                "--scan"])
        self.assertEqual(code, 0)
        self.assertIn("scan candidate", out)
        self.assertIn("language handler: rva 0xBEEF", out)

    def test_table_json(self):
        code, out, _ = run_cli(["table", self.path, "--json"])
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual(len(rows), 4)

    def test_handlers(self):
        code, out, _ = run_cli(["handlers", self.path])
        self.assertEqual(code, 0)
        for handler in ("0x00BEEF", "0x001234", "0x005678"):
            self.assertIn(handler, out)
        self.assertIn("total: 3", out)

    def test_validate_pass(self):
        code, out, _ = run_cli(["validate", self.path, "--rva", "0x1400",
                                "--handler", "0xbeef"])
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_validate_fail(self):
        code, out, _ = run_cli(["validate", self.path, "--rva", "0x1400",
                                "--handler", "0xdead"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)

    def test_multi_capture_selection(self):
        rng = random.Random(11)
        plain_path = os.path.join(self.tmp.name, "plain-capture.bin")
        cipher_path = os.path.join(self.tmp.name, "cipher-capture.bin")
        with open(plain_path, "wb") as fh:
            fh.write(build_image(std_sections(),
                                 dir_exception=(0x3000, len(PDATA))))
        with open(cipher_path, "wb") as fh:
            fh.write(build_image(std_sections(text=rng.randbytes(0x1000)),
                                 dir_exception=(0x3000, len(PDATA))))
        code, out, _ = run_cli(["lookup", cipher_path, plain_path,
                                "--rva", "0x1400"])
        self.assertEqual(code, 0)
        self.assertIn("captures at rva 0x1400", out)
        self.assertIn("image: plain-capture.bin", out)


# ----------------------------------------------------------------------
# Fastpath (NumPy) verification
#
# This sandbox has no NumPy, so the vectorized implementations are
# verified in two layers, following the same approach as izayoi:
#   1. pure-Python mirrors of the fastpath index arithmetic, checked
#      against the pure reference implementations (always runs);
#   2. true equivalence tests against the NumPy implementations
#      (skipped without NumPy, run in CI and on NumPy environments).
# ----------------------------------------------------------------------

def _sim_scan_offsets(data, rva, max_size):
    """Pure mirror of fastpath.scan_triples index arithmetic."""
    usable = len(data) - (len(data) % 4)
    words = list(struct.unpack("<%dI" % (usable // 4), data[:usable])) \
        if usable >= 4 else []
    n = len(words)
    out = []
    for i in range(max(n - 2, 0)):
        b, e, u = words[i], words[i + 1], words[i + 2]
        if b != 0 and b <= rva and e > rva and (e - b) <= max_size and u != 0:
            out.append(i * 4)
    return out


def _sim_load_triples(chunk):
    """Pure mirror of fastpath.load_entries mask filter."""
    triples = [struct.unpack_from("<III", chunk, i)
               for i in range(0, len(chunk) - 11, 12)]
    return [t for t in triples if t[0] != 0 and t[1] > t[0] and t[2] != 0]


class TestFastpathSimulation(unittest.TestCase):
    def test_sim_scan_offsets_clean_image(self):
        # Only planted entries: pre-filter offsets == pure scan results.
        sections = [
            (".text", 0x1000, b"\x90" * 0x1000),
            (".rdata", 0x2000, RDATA + PDATA),
        ]
        img = pe.load(build_image(sections))
        pure = pdata.scan_candidates(img, 0x1400)
        sim = _sim_scan_offsets(img.data, 0x1400,
                                pdata.MAX_PLAUSIBLE_FUNCTION)
        # The mask pre-filter is a superset of the validated pure scan:
        # header bytes and non-entry data can also satisfy the coarse
        # begin/end/unwind mask, but only validated entries survive.
        self.assertEqual([off for off, _ in pure], [0x2038])
        self.assertIn(0x2038, sim)
        self.assertTrue(set(off for off, _ in pure) <= set(sim))

    def test_sim_scan_offsets_superset_of_pure(self):
        # A mask hit with an out-of-image unwind must appear in the
        # pre-filter but be dropped by the validated pure scan.
        rng = random.Random(77)
        junk = bytearray(rng.randbytes(0x100))
        planted = rfun(0x1400, 0x1500, 0x2900)  # unwind beyond the image
        blob = bytearray(RDATA + PDATA) + junk
        blob[len(RDATA) + len(PDATA):len(RDATA) + len(PDATA) + 12] = planted
        sections = [
            (".text", 0x1000, b"\x90" * 0x1000),
            (".rdata", 0x2000, bytes(blob)),
        ]
        img = pe.load(build_image(sections))
        pure_offsets = [off for off, _ in pdata.scan_candidates(img, 0x1400)]
        sim = _sim_scan_offsets(img.data, 0x1400,
                                pdata.MAX_PLAUSIBLE_FUNCTION)
        self.assertIn(0x2038, pure_offsets)     # valid entry
        self.assertNotIn(0x205C, pure_offsets)  # planted, fails validation
        self.assertIn(0x2038, sim)
        self.assertIn(0x205C, sim)
        self.assertTrue(set(pure_offsets) <= set(sim))

    def test_sim_load_triples_matches_pure(self):
        rng = random.Random(555)
        triples = []
        for i in range(48):
            kind = i % 4
            if kind == 0:
                triples.append(rfun(0, 0, 0))                       # begin 0
            elif kind == 1:
                triples.append(rfun(0x100 + i, 0x100 + i - 1, 1))   # end<=begin
            elif kind == 2:
                triples.append(rfun(0x100 + i, 0x200 + i, 0))       # unwind 0
            else:
                triples.append(rfun(0x1000 + i, 0x1100 + i, 0x2000 + i))
        pdata_bytes = b"".join(triples)
        img = std_image(pdata_bytes=pdata_bytes,
                            dir_exception=(0x3000, len(pdata_bytes)))
        pure = [(e.begin, e.end, e.unwind)
                for e in pdata.load_entries(img)]
        chunk = img.read(0x3000, (len(pdata_bytes) // 12) * 12)
        self.assertEqual(pure, _sim_load_triples(chunk))
        self.assertEqual(len(pure), 12)


@unittest.skipUnless(fastpath.HAVE_NUMPY, "requires numpy")
class TestFastpathEquivalence(unittest.TestCase):
    def test_entropy_and_zero_ratio(self):
        rng = random.Random(6)
        for _ in range(25):
            data = rng.randbytes(rng.randrange(1, 0x3000))
            self.assertAlmostEqual(fastpath.shannon_entropy(data),
                                    shannon_entropy(data), places=9)
            self.assertAlmostEqual(fastpath.zero_ratio(data),
                                    zero_ratio(data), places=9)

    def test_load_entries(self):
        rng = random.Random(555)
        triples = []
        for i in range(48):
            kind = i % 4
            if kind == 0:
                triples.append(rfun(0, 0, 0))
            elif kind == 1:
                triples.append(rfun(0x100 + i, 0x100 + i - 1, 1))
            elif kind == 2:
                triples.append(rfun(0x100 + i, 0x200 + i, 0))
            else:
                triples.append(rfun(0x1000 + i, 0x1100 + i, 0x2000 + i))
        pdata_bytes = b"".join(triples)
        img = std_image(pdata_bytes=pdata_bytes,
                            dir_exception=(0x3000, len(pdata_bytes)))
        begins, ends, unwinds = fastpath.load_entries(
            img, 0x3000, len(pdata_bytes))
        pure = [(e.begin, e.end, e.unwind)
                for e in pdata.load_entries(img)]
        self.assertEqual(list(zip(begins, ends, unwinds)), pure)

    def test_scan_triples(self):
        rng = random.Random(88)
        for _ in range(10):
            blob = rng.randbytes(rng.randrange(0, 0x1000))
            rva = rng.randrange(0, 0x10000)
            self.assertEqual(
                fastpath.scan_triples(blob, rva, pdata.MAX_PLAUSIBLE_FUNCTION),
                _sim_scan_offsets(blob, rva, pdata.MAX_PLAUSIBLE_FUNCTION))


class TestFastpathGuard(unittest.TestCase):
    def test_fastpath_raises_without_numpy(self):
        if fastpath.HAVE_NUMPY:
            self.skipTest("numpy installed")
        with self.assertRaises(RuntimeError):
            fastpath.shannon_entropy(b"abc")
        with self.assertRaises(RuntimeError):
            fastpath.zero_ratio(b"abc")
        with self.assertRaises(RuntimeError):
            fastpath.load_entries(None, 0x1000, 12)
        with self.assertRaises(RuntimeError):
            fastpath.scan_triples(b"abcdefabcdef", 1, 16)


if __name__ == "__main__":
    unittest.main(verbosity=2)
