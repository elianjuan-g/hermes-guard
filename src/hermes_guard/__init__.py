"""Hermes Guard — defensive prompt-injection guard for Hermes Agent.

Scans every inbound message before the model sees it, and blocks hidden
prompt-injection attempts at the gate. Local, deterministic, fail-closed.

Public API (import from this package):
    scan_text(text)            -> detector.scan_text (tier/score/reasons)
    scan_tool_arguments(args)  -> detector.scan_tool_arguments
    strip_invisible(text)      -> detector.strip_invisible
    detect_obfuscated_base64   -> roots.detect_obfuscated_base64
    render_xray_preview        -> xray.render_xray_preview
    Ledger                     -> ledger.Ledger (SHA-256 chain)
    TaintTracker               -> taint.TaintTracker
    register(ctx)              -> hooks.register (Hermes entry point)
    guard_review(action, ...)  -> tools.guard_review (5 model actions;
                               release/delete are owner-only slash
                               commands /guard-release, /guard-delete)

Version: 1.1.2
License: MIT
"""

from .detector import (
    scan_text,
    scan_tool_arguments,
    strip_invisible,
    invis_counts,
    decode_tag,
    decode_zerowidth,
)
from .roots import (
    detect_obfuscated_base64,
    shannon_entropy,
    scan_roots,
    LAYER_NAMES,
)
from .xray import render_xray_preview
from .ledger import Ledger
from .taint import TaintTracker
from .hooks import register

__version__ = "1.1.2"
__all__ = [
    "scan_text",
    "scan_tool_arguments",
    "strip_invisible",
    "invis_counts",
    "decode_tag",
    "decode_zerowidth",
    "detect_obfuscated_base64",
    "shannon_entropy",
    "scan_roots",
    "LAYER_NAMES",
    "render_xray_preview",
    "Ledger",
    "TaintTracker",
    "register",
    "__version__",
]
