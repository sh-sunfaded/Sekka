"""sekka - static analysis for x64 PE exception tables (.pdata).

Sekka reads the exception-handling metadata of x64 PE images:

* RUNTIME_FUNCTION enumeration and lookup (function ranges from .pdata),
* UNWIND_INFO parsing: flags, prolog size, unwind codes, the language
  handler RVA, and chained info,
* multi-capture selection: when several snapshots of the same image are
  available, estimate which one holds the target region in a readable
  state before parsing.

The name comes from the Japanese word for a snow crystal.
"""

__version__ = "0.1.0"

from .pe import (  # noqa: F401
    EXCEPTION_DIRECTORY_INDEX,
    MACHINE_AMD64,
    MACHINE_ARM64,
    MACHINE_I386,
    Image,
    PEError,
    load,
)
from .pdata import (  # noqa: F401
    RuntimeFunction,
    load_entries,
    lookup,
    scan_candidates,
)
from .unwind import (  # noqa: F401
    REG64,
    UNW_FLAG_CHAININFO,
    UNW_FLAG_EHANDLER,
    UNW_FLAG_UHANDLER,
    UnwindInfo,
    parse,
    resolve_chain,
)
from .state import classify, choose, shannon_entropy  # noqa: F401

__all__ = [
    "Image", "PEError", "load",
    "RuntimeFunction", "load_entries", "lookup", "scan_candidates",
    "UnwindInfo", "parse", "resolve_chain",
    "UNW_FLAG_EHANDLER", "UNW_FLAG_UHANDLER", "UNW_FLAG_CHAININFO",
    "classify", "choose", "shannon_entropy",
    "__version__",
]
