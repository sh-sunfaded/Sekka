# sekka (雪華)

Static analysis toolkit for the x64 PE exception table (`.pdata`) and unwind
information (`UNWIND_INFO`).

sekka answers the question a stack walker, a profiler, or a compatibility
layer has to answer: **given an address, which function covers it, and which
language handler should run if it faults?**

The name comes from the Japanese word for a snow crystal, 雪華.

## What it does

- **RUNTIME_FUNCTION lookup** - enumerate the x64 exception table and find
  the `RUNTIME_FUNCTION` (begin / end / unwind-data) covering any RVA.
- **UNWIND_INFO parsing** - version, flags (`EHANDLER` / `UHANDLER` /
  `CHAININFO`), prolog size, frame register, the full unwind-code array
  (decoded into readable text), and the **language handler RVA**.
- **Chained info** - follows `UNW_FLAG_CHAININFO` links and resolves the
  whole handler chain.
- **Multi-capture selection** - when several snapshots of the same image are
  available (captures taken at different moments), sekka estimates which one
  holds the target region in a readable state (entropy heuristics) and uses
  that capture. Transformed high-entropy pages are detected and skipped in
  favour of plain-looking ones.
- **Brute-force scan** - if the exception directory is missing or not
  readable in a capture, `--scan` walks the image for plausible
  `RUNTIME_FUNCTION` triples that cover the target and resolve to a
  parseable `UNWIND_INFO`.
- **Both input kinds** - on-disk PE files (section-mapped) and memory-image
  captures (flat, RVA == offset), with automatic stripping of textual
  capture headers.

## Why

The x64 exception table is ordinary, documented Windows metadata, and a
surprising amount of tooling needs it:

- **crash reporting** - offline stack walking from minidumps requires
  reading `.pdata` and replaying unwind codes (the Breakpad/Crashpad
  approach);
- **sampling profilers** - reconstructing a call stack from another process
  needs the same records on every sample;
- **function boundaries** - `.pdata` is a free, authoritative function
  table for binaries without symbols;
- **build checks** - a function without unwind info only fails when an
  exception actually fires; sekka can lint for that in CI;
- **OS compatibility work** - any layer that dispatches Windows x64
  exceptions itself has to read these tables.

Existing Python tooling mostly stops at enumerating `RUNTIME_FUNCTION`
entries; sekka decodes the `UNWIND_INFO` records as well, in pure Python.

## Install

```
pip install sekka
```

or from source:

```
git clone https://github.com/sh-sunfaded/Sekka
cd Sekka
pip install .
```

No third-party dependencies: sekka is pure standard library.

## CLI

```
# Which function covers RVA 0xB42B3, and who is its handler?
sekka lookup image.exe --rva 0xB42B3

# Several captures of the same image? sekka picks the readable one.
sekka lookup capture1.bin capture2.bin capture3.bin --rva 0xB42B3

# Directory missing in the capture? fall back to a brute-force scan.
sekka lookup capture.bin --rva 0xB42B3 --scan

# Machine-readable output
sekka lookup capture.bin --rva 0xB42B3 --json

# List the whole exception table
sekka table image.exe --start 0x1400 --end 0x2000

# List every function that registers a language handler
sekka handlers image.exe

# Assert a known-good pair (exit code 0/1) - useful as a regression check
sekka validate image.exe --rva 0xAD239 --handler 0xB63F0
```

Example output:

```
image: capture.bin
function: begin rva 0xAD200 (VA 0x1400AD200)  end rva 0xAD400 (VA 0x1400AD400)
unwind: rva 0x1B000 (VA 0x14001B000)
unwind info: version 1  flags EHANDLER  prolog 0x9  codes 4
  [0] push rbp
  [1] push rbx
  [2] sub rsp, 0x30
  [3] save rcx at frame offset 0x80
language handler: rva 0xB63F0 (VA 0x1400B63F0)
```

## Python API

```python
from sekka import pe, pdata, unwind

image = pe.load(open("capture.bin", "rb").read())
entry = pdata.lookup(image, 0xB42B3)
if entry is not None:
    info = unwind.parse(image, entry.unwind)
    print(hex(entry.begin), hex(entry.end), hex(info.handler_rva or 0))
```

Multi-capture selection:

```python
from sekka import pe
from sekka.state import choose

images = {name: pe.load(open(p, "rb").read())
          for name, p in [("run-a", "a.bin"), ("run-b", "b.bin")]}
rows = choose(images, rva=0xB42B3)  # plain-like captures first
```

## Modules

| module      | contents                                                       |
|-------------|----------------------------------------------------------------|
| `sekka.pe`     | minimal PE32+ reader: headers, sections, data directories, RVA mapping |
| `sekka.pdata`  | RUNTIME_FUNCTION enumeration, lookup, brute-force scan          |
| `sekka.unwind` | UNWIND_INFO parsing, unwind-code decoding, chained info        |
| `sekka.state`  | entropy heuristics, multi-capture selection                    |
| `sekka.cli`    | the `sekka` command                                             |

## Design notes

- Pure standard library; runs on Python 3.9+; no platform-specific code.
- All tests run against synthetic PE images built in memory - no external
  fixtures and no real binaries.
- RVA translation goes through the section table first, then falls back to
  a flat RVA==offset mapping, so the same code handles on-disk files and
  memory captures.

## Testing

```
python3 tests/test_sekka.py
```

## License

Apache-2.0
