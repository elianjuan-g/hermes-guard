"""Hermes Guard — forensic X-Ray preview + status/HUD renderers.

render_xray_preview() turns a scan result into a short, human-readable
block that shows WHAT was caught and WHERE, without printing the full
original message. All decoded/hidden content is truncated to 160 chars.

render_status_hud() renders the CLI status screen (live posture +
formula components + arena line). render_guard_hud_html() renders the
standalone Obsidian & Gold HTML dashboard (no external deps, no JS).
"""
import html
from datetime import datetime, timezone

from . import detector
from .roots import LAYER_NAMES

PREVIEW_MAX = 160


def render_status_hud(stats, score, recent, arena=None, detail=None):
    """Render the Forensic X-Ray HUD (action=status) from live telemetry.

    stats: dict from storage.get_stats() (real traffic only).
    score: int from storage.posture_score().
    recent: list from storage.list_recent(limit=1) (may be empty).
    arena: optional dict from tools._run_simulate() (in-memory only).
    detail: optional dict from storage.posture_detail() (components of
        the score). When None, posture_detail() is read from the
        default DB.

    The live score and the arena score are shown SEPARATELY: the live
    posture comes from real telemetry only, while the arena result comes
    from an in-memory simulate() run (never stored in live stats).
    """
    total = (stats["blocked"] + stats["quarantined"] + stats["flagged"]
             + stats["passed"])

    if detail is None:
        try:
            from .storage import posture_detail
            detail = posture_detail()
        except Exception:
            detail = {"base": 100, "pending": 0, "degraded": 0,
                      "false_positive": 0, "held": 0,
                      "degraded_layers": [], "released": 0,
                      "intercepted": 0}

    lines = []
    lines.append("HERMES GUARD v1.1.1 — FORENSIC X-RAY HUD")
    lines.append("=" * 48)
    lines.append("POSTURE (live, real traffic only): %d/100" % score)
    lines.append("  Formula: base 100 - pending - degraded - false_positive")
    lines.append("    base 100 = 35 pre_llm_call + 25 pre_tool_call")
    lines.append("               + 20 fail-closed + 10 redaction")
    lines.append("               + 10 ledger verified")
    lines.append("    pending       -%d  (held entries x 5, capped 25)"
                 % detail["pending"])
    lines.append("    degraded      -%d  (degraded layers x 15: %s)"
                 % (detail["degraded"],
                    ", ".join(detail.get("degraded_layers") or []) or "-"))
    lines.append("    false_positive -%d  (released %d / intercepted %d)"
                 % (detail["false_positive"], detail.get("released", 0),
                    detail.get("intercepted", 0)))
    lines.append("  Held entries (unreleased): %d" % detail.get("held", 0))
    lines.append("  Correct blocks never reduce the score.")
    lines.append("")
    lines.append("Defense matrix (L1-L4):")
    lines.append("  L1 invisible   — Unicode smuggling (zero-width, tags, bidi)")
    lines.append("  L2 instruction — hidden-instruction / jailbreak phrasing")
    lines.append("  L3 token       — special tokens + mixed-script homoglyphs")
    lines.append("  L4 encoding    — Base64 deep-inspection: decode + scan "
                 "decoded content")
    lines.append("")
    lines.append("Telemetry (real only — simulation excluded):")
    lines.append("  total=%d  blocked=%d  quarantined=%d  flagged=%d  passed=%d"
                 % (total, stats["blocked"], stats["quarantined"],
                    stats["flagged"], stats["passed"]))
    lines.append("  false_positive=%d  detector_error=%d"
                 % (stats["false_positive"], stats["detector_error"]))
    lines.append("")
    if recent:
        e = recent[0]
        lines.append("Latest intercept:")
        lines.append("  id=%s  tier=%s  released=%s" % (
            e["id"], e["tier"], "yes" if e.get("released") else "no"))
        lines.append("  preview: %r" % e["preview"][:PREVIEW_MAX])
        lines.append("  reasons: %s" % (e["reasons"] or "")[:200])
    else:
        lines.append("Latest intercept: none yet.")
    lines.append("")
    if arena:
        lines.append("Arena (simulation, in-memory only):")
        lines.append("  message vectors: %d/%d correct"
                     % (arena.get("passed", 0), arena.get("total", 0)))
        tool = arena.get("tool") or {}
        lines.append("  tool-arg vectors: %d/%d correct"
                     % (tool.get("passed", 0), tool.get("total", 0)))
        if arena.get("ran_at"):
            lines.append("  (run at %s)" % arena["ran_at"])
        lines.append("  Arena scores are never mixed into the live "
                     "posture above.")
    else:
        lines.append("Arena (simulation, in-memory only): not run yet —")
        lines.append("  guard_review action=simulate")
        lines.append("  to see the 24-vector result. Arena scores are never")
        lines.append("  mixed into the live posture above.")
    lines.append("")
    lines.append("Commands:")
    lines.append("  guard_review action=list            — held messages")
    lines.append("  guard_review action=show id=<id>    — one held message")
    lines.append("  guard_review action=clean_copy id=<id>")
    lines.append("      — cleaned text for manual re-send")
    lines.append("  guard_review action=release id=<id>")
    lines.append("      — mark reviewed, return original for manual re-send")
    lines.append("  guard_review action=delete id=<id>  — remove one entry")
    return "\n".join(lines)


def _bar(label, active, detail=""):
    mark = "[X]" if active else "[ ]"
    line = "  %s %s" % (mark, label)
    if detail:
        line += " — %s" % detail
    return line


def render_xray_preview(text, scan=None):
    """Render a forensic X-Ray preview for one intercepted message.

    text: the original message (never printed in full).
    scan: optional pre-computed scan_roots() result; computed if omitted.

    Returns a multi-line string. The message itself appears only as a
    truncated, sanitised preview (invisible chars shown as counts, not
    rendered). Decoded hidden content is capped at 160 chars.
    """
    from .roots import scan_roots

    if scan is None:
        scan = scan_roots(text)
    if not isinstance(text, str):
        text = str(text or "")

    tier = scan.get("tier", "pass").upper()
    score = scan.get("score", 0)
    layers = scan.get("layers", {})
    reasons = scan.get("reasons", [])
    b64 = scan.get("b64_findings", [])
    inv = detector.invis_counts(text)

    lines = []
    lines.append("X-RAY  tier=%s  score=%d" % (tier, score))
    lines.append("Layers:")
    lines.append(_bar("L1 invisible  (%s)" % LAYER_NAMES["L1"], layers.get("L1", False),
                      ("counts %s" % dict(inv)) if sum(inv.values()) else ""))
    lines.append(_bar("L2 instruction (%s)" % LAYER_NAMES["L2"], layers.get("L2", False)))
    lines.append(_bar("L3 token      (%s)" % LAYER_NAMES["L3"], layers.get("L3", False)))
    lines.append(_bar("L4 encoding   (%s)" % LAYER_NAMES["L4"], layers.get("L4", False),
                      ("%d obfuscated blob(s)" % len(b64)) if b64 else ""))
    if reasons:
        lines.append("Reasons:")
        for r in reasons:
            lines.append("  - %s" % r[:200])
    # Sanitised preview: strip invisible chars, truncate.
    visible = "".join(
        ch for ch in text
        if ch.isprintable() or ch in "\n\r\t"
    )
    preview = visible[:PREVIEW_MAX].replace("\n", " ")
    lines.append("Preview (sanitised, max %d chars):" % PREVIEW_MAX)
    lines.append("  %r" % preview)
    return "\n".join(lines)


# --- standalone HTML dashboard (P0-4) --------------------------------------

def build_status_data(path_override=None):
    """Assemble the status_data dict for the HUD renderers.

    Live telemetry comes from the store (real traffic only); the arena
    is a fresh in-memory simulate() run, labelled with its run time.
    """
    from . import arena, storage
    from datetime import datetime, timezone

    stats = storage.get_stats(path_override)
    score = storage.posture_score(path_override)
    detail = storage.posture_detail(path_override)
    recent = storage.list_recent(limit=1, path_override=path_override)
    sim = arena.run_simulate()
    ran_at = datetime.now(timezone.utc).isoformat()[:19] + "Z"
    sim["ran_at"] = ran_at
    return {
        "version": "1.1.1",
        "score": score,
        "detail": detail,
        "stats": stats,
        "recent": recent,
        "arena": sim,
        "arena_time": ran_at,
        "generated_at": ran_at,
    }


_CSS = """
body{background:#0d0d0f;color:#e8e4d8;font-family:system-ui,-apple-system,
Segoe UI,Roboto,sans-serif;margin:0;padding:24px;line-height:1.5}
h1{color:#e8b64c;font-size:22px;margin:0 0 4px}
h2{color:#e8b64c;font-size:16px;border-bottom:1px solid #3a2f14;
padding-bottom:4px;margin:28px 0 10px}
.sub{color:#9a958a;font-size:13px;margin:0 0 8px}
.card{background:#141417;border:1px solid #2a2a2e;border-radius:10px;
padding:16px 18px;margin:12px 0}
.score{font-size:44px;font-weight:700;color:#e8b64c;line-height:1}
.score small{font-size:16px;color:#9a958a}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #2a2a2e;padding:6px 8px;text-align:left;
vertical-align:top}
th{color:#e8b64c;background:#1a1a1d}
.ok{color:#7dd87d}.bad{color:#e06c6c}
pre{background:#0a0a0c;border:1px solid #2a2a2e;border-radius:6px;
padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.note{color:#9a958a;font-size:12px}
"""

_GOLD = "#e8b64c"


def render_guard_hud_html(status_data):
    """Render the standalone Guard HUD page (Obsidian & Gold).

    status_data: dict with keys version, score, detail, stats, recent,
    arena (optional dict with message + tool sections), arena_time,
    generated_at (optional). All dynamic text is HTML-escaped. No
    external URLs, no JavaScript required.
    """
    version = html.escape(str(status_data.get("version", "1.1.1")))
    score = int(status_data.get("score", 0))
    detail = status_data.get("detail") or {}
    stats = status_data.get("stats") or {}
    recent = status_data.get("recent") or []
    arena = status_data.get("arena")
    generated = html.escape(str(status_data.get(
        "generated_at") or datetime.now(timezone.utc).isoformat()[:19] + "Z"))

    base = detail.get("base", 100)
    pending = detail.get("pending", 0)
    degraded = detail.get("degraded", 0)
    fp = detail.get("false_positive", 0)
    held = detail.get("held", 0)
    degraded_layers = detail.get("degraded_layers") or []
    released = detail.get("released", 0)
    intercepted = detail.get("intercepted", 0)
    total = (stats.get("blocked", 0) + stats.get("quarantined", 0)
             + stats.get("flagged", 0) + stats.get("passed", 0))

    def _arena_rows(section):
        rows = []
        for v in (section or {}).get("vectors", []):
            ok = bool(v.get("ok"))
            rows.append(
                "<tr><td class=\"mono\">%s</td><td>%s</td>"
                "<td class=\"mono\">%s</td><td class=\"mono\">%s</td>"
                "<td class=\"%s\">%s</td></tr>" % (
                    html.escape(str(v.get("id", ""))),
                    html.escape(str(v.get("name", ""))),
                    html.escape(str(v.get("expected", ""))),
                    html.escape(str(v.get("got", ""))),
                    "ok" if ok else "bad", "PASS" if ok else "FAIL"))
        return "\n".join(rows)

    if arena:
        msg = arena.get("vectors") and {"vectors": arena["vectors"]} or {}
        tool = arena.get("tool") or {}
        arena_html = (
            ("<p>Message vectors: <b>%d/%d correct</b> &nbsp;|&nbsp; "
             "Tool-arg vectors: <b>%d/%d correct</b></p>")
            % (arena.get("passed", 0), arena.get("total", 0),
               tool.get("passed", 0), tool.get("total", 0)))
        if arena.get("ran_at"):
            arena_html += (("<p class=\"note\">Run at %s (in-memory only; "
                            "never mixed into the live posture).</p>")
                           % html.escape(str(arena["ran_at"])))
        arena_html += (
            "<table><tr><th>ID</th><th>Vector</th><th>Expected</th>"
            "<th>Got</th><th>Result</th></tr>%s%s</table>"
            % (_arena_rows(msg), _arena_rows(tool)))
    else:
        arena_html = ("<p class=\"note\">Arena not run yet — run "
                      "<span class=\"mono\">guard_review action=simulate</span> "
                      "to fill this section.</p>")

    if recent:
        e = recent[0]
        xray = render_xray_preview(
            e.get("full_text") or e.get("preview") or "")
        latest_html = (
            "<p>id=%s &nbsp; tier=%s &nbsp; released=%s</p>"
            "<pre>%s</pre>"
            % (html.escape(str(e.get("id", ""))),
               html.escape(str(e.get("tier", ""))),
               "yes" if e.get("released") else "no",
               html.escape(xray)))
    else:
        latest_html = "<p class=\"note\">No intercepts yet.</p>"

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Hermes Guard — Forensic X-Ray HUD</title>
<style>%s</style></head>
<body>
<h1>Hermes Guard — Forensic X-Ray HUD</h1>
<p class="sub">Version %s &middot; Generated %s &middot; Local, deterministic,
fail-closed. Simulation is never mixed into live telemetry.</p>

<h2>Live Posture</h2>
<div class="card"><div class="score">%d<small> / 100</small></div>
<p class="note">Formula: base 100 &minus; pending &minus; degraded
&minus; false_positive</p>
<table><tr><th>Component</th><th>Value</th><th>Detail</th></tr>
<tr><td>base</td><td>%d</td><td>35 pre_llm_call + 25 pre_tool_call + 20 fail-closed
+ 10 redaction + 10 ledger verified</td></tr>
<tr><td>pending</td><td>&minus;%d</td><td>held entries %d &times; 5 (capped 25)</td></tr>
<tr><td>degraded</td><td>&minus;%d</td><td>degraded layers &times; 15: %s</td></tr>
<tr><td>false_positive</td><td>&minus;%d</td><td>released %d / intercepted %d</td></tr>
</table></div>

<h2>Arena Benchmark</h2>
<div class="card">%s</div>

<h2>Defense Matrix</h2>
<div class="card"><table>
<tr><th>Layer</th><th>What it catches</th></tr>
<tr><td>L1 invisible</td><td>Unicode smuggling (zero-width, tags, bidi)</td></tr>
<tr><td>L2 instruction</td><td>Hidden-instruction / jailbreak phrasing</td></tr>
<tr><td>L3 token</td><td>Special tokens + mixed-script homoglyphs</td></tr>
<tr><td>L4 encoding</td><td>Base64 deep-inspection: decode + scan decoded content</td></tr>
</table></div>

<h2>Live Telemetry (real traffic only)</h2>
<div class="card"><p>total=%d &nbsp; blocked=%d &nbsp; quarantined=%d
&nbsp; flagged=%d &nbsp; passed=%d &nbsp; false_positive=%d
&nbsp; detector_error=%d &nbsp; held=%d</p></div>

<h2>Latest Intercept — X-Ray</h2>
<div class="card">%s</div>

<p class="note">Hermes Guard v%s &middot; Predator Pattern Store,
hash-chained quarantine ledger, human-corrected signatures.</p>
</body></html>""" % (
        _CSS, version, generated, score, base, pending, held, degraded,
        html.escape(", ".join(degraded_layers) or "-"),
        fp, released, intercepted, arena_html, total,
        stats.get("blocked", 0), stats.get("quarantined", 0),
        stats.get("flagged", 0), stats.get("passed", 0),
        stats.get("false_positive", 0), stats.get("detector_error", 0),
        held, latest_html, version)
