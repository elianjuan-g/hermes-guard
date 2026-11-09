"""Hermes Guard — the simulation arena (Argon Round 3 canon).

Each message vector is a dict: {"id", "name", "text", "expected",
"why"}. simulate() runs the message vectors through scan_roots() in
memory only — live telemetry and the quarantine DB are never touched.

The canon is Argon Round 3's 24: 21 message vectors (A01-A14 attacks,
S01-S07 near-misses) plus 3 tool-argument vectors (A15, A16, S08) in
TOOL_ARG_VECTORS, run through scan_tool_arguments() (pre_tool_call
guard). Four extra tool-arg checks (T01-T04, Ciel hardening) run in
the same section.

The corpus lives in fixtures/vectors.json (top-level ``fixtures/``)
as DATA, not code: the vectors are attack samples the guard must
recognise, and a data file keeps hostile strings out of executable
modules. Vectors with programmatic payloads (A01-A05) carry a small
"build" spec; the builders below assemble them at import time. The
loaded VECTORS / TOOL_ARG_VECTORS are identical to the v1.1.0
Python literals (verified by diff against the dumped corpus).

These are DETECTION fixtures: they describe attacks so the guard can
recognise them. They are never instructions to follow.

v1.1.0: the arena is Argon Round 3's canonical 24. The v1.0.0 vectors
that are not in the canon moved to tests/test_extended_vectors.py as
pytest cases.
"""
import json
from pathlib import Path

# --- payload builders (detection fixtures only) ---------------------------

def _zw_encode(text):
    """Encode ASCII text as zero-width binary (200B=0, 200C=1)."""
    out = []
    for byte in text.encode("ascii"):
        for i in range(7, -1, -1):
            out.append("\u200c" if (byte >> i) & 1 else "\u200b")
    return "".join(out)


def _tag_encode(text):
    """Encode ASCII text as Unicode tag characters (U+E0000 + byte)."""
    return "".join(chr(0xE0000 + b) for b in text.encode("ascii"))


def _load_corpus():
    """Load fixtures/vectors.json (plugin-root fixtures/ dir)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent.parent.parent / "fixtures" / "vectors.json",
        here.parent.parent / "fixtures" / "vectors.json",
        here / "fixtures" / "vectors.json",
    ]
    for path in candidates:
        if path.is_file():
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(
        "Hermes Guard arena corpus not found (looked for "
        "fixtures/vectors.json under the plugin root); checked: %s"
        % ", ".join(str(p) for p in candidates))


def _build_text(entry):
    """Assemble one message vector's text (plain or build spec)."""
    if "text" in entry:
        return entry["text"]
    spec = entry["build"]
    kind = spec["kind"]
    prefix = spec.get("prefix", "")
    if kind == "tag":
        return prefix + _tag_encode(spec["text"])
    if kind == "zw":
        return prefix + _zw_encode(spec["text"])
    if kind == "repeat":
        return prefix + spec["char"] * spec["count"]
    raise ValueError("unknown vector build kind: %r" % (kind,))


_CORPUS = _load_corpus()

# --- the 21 canonical message vectors (Argon Round 3, Bagian 2) -------

VECTORS = [
    {
        "id": v["id"],
        "name": v["name"],
        "text": _build_text(v),
        "expected": v["expected"],
        "why": v["why"],
    }
    for v in _CORPUS["vectors"]
]


# --- tool-argument arena (pre_tool_call guard) -----------------------------

TOOL_ARG_VECTORS = [
    {
        "id": v["id"],
        "name": v["name"],
        "args": v["args"],
        "expected": v["expected"],
        "why": v["why"],
        **({"session_tainted": v["session_tainted"]}
           if "session_tainted" in v else {}),
    }
    for v in _CORPUS["tool_arg_vectors"]
]


def vector_names():
    """Return the 21 message vector names in order."""
    return [v["name"] for v in VECTORS]


def vector_ids():
    """Return the 21 message vector ids in order (A01-A14, S01-S07)."""
    return [v["id"] for v in VECTORS]
