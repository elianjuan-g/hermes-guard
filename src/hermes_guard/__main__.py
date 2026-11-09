"""Hermes Guard — CLI entry point.

Usage:
  python -m hermes_guard status
      Print the Forensic X-Ray HUD (live posture + telemetry).
  python -m hermes_guard scan <file>
      Scan a text file and print the tier/score/reasons.
  python -m hermes_guard simulate
      Run the simulation arena in memory and print the result
      (21 message vectors + 7 tool-arg vectors).
  python -m hermes_guard hud [--out guard-hud.html]
      Write the standalone Obsidian & Gold HTML dashboard from live
      state + a fresh in-memory arena run.
  python -m hermes_guard --help
      This help.
"""
import sys

from . import roots, xray


def _cmd_status():
    data = xray.build_status_data()
    print(xray.render_status_hud(data["stats"], data["score"],
                                 data["recent"], arena=data["arena"],
                                 detail=data["detail"]))


def _cmd_scan(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    result = roots.scan_roots(text)
    print("tier=%s  score=%d" % (result["tier"], result["score"]))
    for layer, active in result["layers"].items():
        print("  %s: %s" % (layer, "TRIGGERED" if active else "clear"))
    for r in result["reasons"]:
        print("  - %s" % r)


def _cmd_simulate():
    from . import arena

    sim = arena.run_simulate()
    for v in sim["vectors"]:
        mark = "OK  " if v["ok"] else "MISS"
        print("  %s %-28s expected=%-11s got=%s"
              % (mark, v["name"], v["expected"], v["got"]))
    print("Arena message vectors (simulation-only): %d/%d correct"
          % (sim["passed"], sim["total"]))
    for v in sim["tool"]["vectors"]:
        mark = "OK  " if v["ok"] else "MISS"
        print("  %s %-28s expected=%-11s got=%s"
              % (mark, v["name"], v["expected"], v["got"]))
    print("Arena tool-arg vectors (simulation-only): %d/%d correct"
          % (sim["tool"]["passed"], sim["tool"]["total"]))


def _cmd_hud(out_path="guard-hud.html"):
    html = xray.render_guard_hud_html(xray.build_status_data())
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("wrote %s (%d bytes)" % (out_path, len(html)))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    cmd = argv[0]
    if cmd == "status":
        _cmd_status()
        return 0
    if cmd == "scan" and len(argv) >= 2:
        _cmd_scan(argv[1])
        return 0
    if cmd == "simulate":
        _cmd_simulate()
        return 0
    if cmd == "hud":
        out = "guard-hud.html"
        if len(argv) >= 3 and argv[1] == "--out":
            out = argv[2]
        _cmd_hud(out)
        return 0
    print("unknown command %r (try --help)" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
