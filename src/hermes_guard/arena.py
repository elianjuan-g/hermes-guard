"""Hermes Guard — simulation arena runner.

run_simulate() runs both arena sections in memory only and never
touches live telemetry or the quarantine DB:

  Section 1 — message vectors (A01-A14 attacks, S01-S07 near-misses)
               through roots.scan_roots().
  Section 2 — tool-arg vectors (A15, A16, S08 + T01-T04) through
               detector.scan_tool_arguments().

Both the guard_review tool (tools.py) and the CLI (__main__.py) use
this runner, so the counts they report always agree.
"""
import json

from . import detector, roots
from .vectors import VECTORS, TOOL_ARG_VECTORS


def _args_to_text(args):
    """Serialise tool args the way handle_pre_tool_call does.

    ensure_ascii=False is deliberate: the scanner must see the REAL
    characters (a tag/zero-width payload JSON-escaped to \\uXXXX
    would evade decode_tag/decode_zerowidth).
    """
    try:
        return json.dumps(args, sort_keys=True, default=str,
                          ensure_ascii=False)
    except Exception:
        return str(args or "")


def run_simulate():
    """Run the full arena. Returns {"total", "passed", "failed",
    "correct", "vectors", "tool", "arena"}."""
    results = []
    correct = 0
    for v in VECTORS:
        scan = roots.scan_roots(v["text"])
        got = scan["tier"]
        ok = got == v["expected"]
        if ok:
            correct += 1
        results.append({
            "id": v["id"],
            "name": v["name"],
            "expected": v["expected"],
            "got": got,
            "ok": ok,
            "score": scan["score"],
        })

    tool_results = []
    tool_correct = 0
    for v in TOOL_ARG_VECTORS:
        scan = detector.scan_tool_arguments(
            _args_to_text(v["args"]),
            session_tainted=bool(v.get("session_tainted", False)))
        got = scan["tier"]
        ok = got == v["expected"]
        if ok:
            tool_correct += 1
        tool_results.append({
            "id": v["id"],
            "name": v["name"],
            "expected": v["expected"],
            "got": got,
            "ok": ok,
            "score": scan["score"],
        })

    return {
        "arena": "simulation-only (live telemetry untouched)",
        "total": len(VECTORS),
        "passed": correct,
        "failed": len(VECTORS) - correct,
        "correct": correct,
        "vectors": results,
        "tool": {
            "total": len(TOOL_ARG_VECTORS),
            "passed": tool_correct,
            "failed": len(TOOL_ARG_VECTORS) - tool_correct,
            "vectors": tool_results,
        },
    }
