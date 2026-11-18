"""sekka command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import pe, pdata
from . import unwind as unwind_mod
from .state import choose as choose_state


def _load_image(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    return pe.load(raw, name=os.path.basename(path))


def _parse_int(text):
    return int(text, 0)


def _flag_names(info):
    return "|".join(info.flag_names()) or "none"


def _entry_dict(image, entry, with_unwind=True):
    result = {
        "image": image.name,
        "function": entry.to_dict(),
        "function_va": {
            "begin": image.va(entry.begin),
            "end": image.va(entry.end),
            "unwind": image.va(entry.unwind),
        },
    }
    if with_unwind:
        try:
            info = unwind_mod.parse(image, entry.unwind)
        except pe.PEError as exc:
            result["unwind"] = {"error": str(exc)}
        else:
            result["unwind"] = info.to_dict()
            if info.chained is not None:
                chain = []
                try:
                    for sub in unwind_mod.resolve_chain(image, info.chained.unwind):
                        chain.append(sub.to_dict())
                except pe.PEError:
                    pass
                result["chain"] = chain
    return result


def _print_entry(image, entry, note=None):
    print("image: %s" % image.name)
    if note:
        print("note: %s" % note)
    print("function: begin rva 0x%X (VA 0x%X)  end rva 0x%X (VA 0x%X)" % (
        entry.begin, image.va(entry.begin), entry.end, image.va(entry.end)))
    print("unwind: rva 0x%X (VA 0x%X)" % (entry.unwind, image.va(entry.unwind)))
    try:
        info = unwind_mod.parse(image, entry.unwind)
    except pe.PEError as exc:
        print("unwind info: parse failed: %s" % exc)
        return
    print("unwind info: version %d  flags %s  prolog 0x%X  codes %d" % (
        info.version, _flag_names(info), info.size_of_prolog, info.count_of_codes))
    if info.frame_register:
        reg = unwind_mod.REG64[info.frame_register] if info.frame_register < 16 else "?"
        print("frame register: %s (offset %d)" % (reg, info.frame_offset))
    for code in info.codes:
        print("  [%d] %s" % (code.slot, code.text))
    if info.handler_rva is not None:
        print("language handler: rva 0x%X (VA 0x%X)" % (
            info.handler_rva, image.va(info.handler_rva)))
    if info.chained is not None:
        print("chained entry: begin 0x%X end 0x%X unwind 0x%X" % (
            info.chained.begin, info.chained.end, info.chained.unwind))
        try:
            sub = unwind_mod.parse(image, info.chained.unwind)
            if sub.handler_rva is not None:
                print("chained handler: rva 0x%X (VA 0x%X)" % (
                    sub.handler_rva, image.va(sub.handler_rva)))
        except pe.PEError as exc:
            print("chained unwind info: parse failed: %s" % exc)


def _warn_machine(image):
    if image.machine != pe.MACHINE_AMD64:
        sys.stderr.write("warning: %s: machine is %s; "
                         "x64 unwind parsing may not apply\n"
                         % (image.name, image.machine_name()))


def cmd_lookup(args):
    images = [_load_image(p) for p in args.image]
    for image in images:
        _warn_machine(image)
    ordered = images
    if len(images) > 1:
        # Same-basename captures from different directories would silently
        # clobber each other in the mapping; disambiguate with a "#N" suffix.
        mapping = {}
        for image in images:
            name = image.name
            n = 2
            while name in mapping:
                name = "%s #%d" % (image.name, n)
                n += 1
            if name != image.name:
                image.name = name
            mapping[name] = image
        rows = choose_state(mapping, args.rva)
        print("captures at rva 0x%X (plain-like first):" % args.rva)
        for row in rows:
            print("  %-24s entropy=%s zero=%s %s" % (
                row["name"],
                "%.3f" % row["entropy"] if row["entropy"] is not None else "-",
                "%.4f" % row["zero_ratio"] if row["zero_ratio"] is not None else "-",
                row["verdict"]))
        ordered = [mapping[row["name"]] for row in rows
                   if row["name"] in mapping]
    found = []
    for image in ordered:
        entry = pdata.lookup(image, args.rva)
        if entry is not None:
            found.append((image, entry, None))
            break
        if args.scan:
            candidates = pdata.scan_candidates(image, args.rva)
            if candidates:
                for off, candidate in candidates:
                    found.append((image, candidate,
                                  "scan candidate at file offset 0x%X" % off))
                break
    if args.json:
        rows = []
        for image, entry, note in found:
            row = _entry_dict(image, entry)
            if note:
                row["note"] = note
            rows.append(row)
        print(json.dumps(rows, indent=2))
    else:
        for image, entry, note in found:
            print()
            _print_entry(image, entry, note=note)
    if not found:
        sys.stderr.write("no RUNTIME_FUNCTION covers rva 0x%X\n" % args.rva)
        return 2
    return 0


def cmd_table(args):
    image = _load_image(args.image)
    _warn_machine(image)
    entries = pdata.load_entries(image)
    rows = []
    for entry in entries:
        if args.start is not None and entry.end <= args.start:
            continue
        if args.end is not None and entry.begin >= args.end:
            continue
        rows.append({
            "begin_rva": entry.begin, "end_rva": entry.end,
            "unwind_rva": entry.unwind, "begin_va": image.va(entry.begin),
            "end_va": image.va(entry.end),
        })
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no RUNTIME_FUNCTION entries")
        return 0
    for row in rows[:args.limit]:
        print("0x%06X-0x%06X  (VA 0x%X-0x%X)  unwind 0x%X" % (
            row["begin_rva"], row["end_rva"], row["begin_va"], row["end_va"],
            row["unwind_rva"]))
    if len(rows) > args.limit:
        print("... %d more (use --limit)" % (len(rows) - args.limit))
    print("total: %d entries" % len(rows))
    return 0


def cmd_handlers(args):
    image = _load_image(args.image)
    _warn_machine(image)
    rows = []
    for entry in pdata.load_entries(image):
        try:
            info = unwind_mod.parse(image, entry.unwind)
        except pe.PEError:
            continue
        if info.handler_rva is not None:
            rows.append({
                "begin_rva": entry.begin, "end_rva": entry.end,
                "handler_rva": info.handler_rva,
                "handler_va": image.va(info.handler_rva),
                "flags": info.flag_names(),
            })
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for row in rows:
        print("function 0x%06X-0x%06X  handler rva 0x%06X (VA 0x%X)  [%s]" % (
            row["begin_rva"], row["end_rva"], row["handler_rva"],
            row["handler_va"], ",".join(row["flags"])))
    print("total: %d entries with a language handler" % len(rows))
    return 0


def cmd_validate(args):
    image = _load_image(args.image)
    entry = pdata.lookup(image, args.rva)
    if entry is None:
        print("FAIL: no RUNTIME_FUNCTION covers rva 0x%X" % args.rva)
        return 1
    try:
        info = unwind_mod.parse(image, entry.unwind)
    except pe.PEError as exc:
        print("FAIL: unwind parse error: %s" % exc)
        return 1
    if info.handler_rva == args.handler:
        print("PASS: function 0x%X-0x%X handler rva 0x%X (VA 0x%X)" % (
            entry.begin, entry.end, info.handler_rva, image.va(info.handler_rva)))
        return 0
    print("FAIL: expected handler 0x%X, found 0x%X" % (
        args.handler, info.handler_rva if info.handler_rva is not None else 0))
    return 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sekka",
        description="Static analysis for x64 PE exception tables (.pdata)")
    parser.add_argument("--version", action="version",
                        version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("lookup", help="find the RUNTIME_FUNCTION covering an RVA")
    p.add_argument("image", nargs="+", help="image or capture file(s)")
    p.add_argument("--rva", required=True, type=_parse_int,
                   help="target RVA (hex with 0x prefix)")
    p.add_argument("--scan", action="store_true",
                   help="fall back to a brute-force scan when the table misses")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("table", help="list RUNTIME_FUNCTION entries")
    p.add_argument("image", help="image or capture file")
    p.add_argument("--start", type=_parse_int, default=None)
    p.add_argument("--end", type=_parse_int, default=None)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true", help="JSON output")
    p.set_defaults(func=cmd_table)

    p = sub.add_parser("handlers", help="list entries with a language handler")
    p.add_argument("image", help="image or capture file")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.set_defaults(func=cmd_handlers)

    p = sub.add_parser(
        "validate", help="assert that an RVA resolves to an expected handler")
    p.add_argument("image", help="image or capture file")
    p.add_argument("--rva", required=True, type=_parse_int)
    p.add_argument("--handler", required=True, type=_parse_int)
    p.set_defaults(func=cmd_validate)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
