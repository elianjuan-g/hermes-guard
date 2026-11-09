"""Hermes Guard — guard_review tool (7 actions).

This is the plugin's tool surface, registered via the Hermes public
register_tool API. It inspects the quarantine log, runs the simulation
arena, and renders the Forensic X-Ray HUD.

Actions:
  status     — Forensic X-Ray HUD (live posture, L1-L4 matrix, real-only
               telemetry, latest intercept, commands).
  list       — recent quarantine entries (newest first, 160-char previews).
  show       — one entry by id (160-char preview only).
  simulate   — run the simulation arena in memory. Never touches live
               telemetry or the quarantine DB.
  clean_copy — cleaned copy of one entry (invisible chars stripped,
               hidden payloads redacted) for manual re-send.
  release    — mark one entry released and return the original text for
               manual re-send. Counts as a false positive. Also
               suppresses the entry's hidden-instruction pattern, so a
               human-corrected phrase stops being flagged on its own.
  delete     — permanently delete one quarantine entry.

Quarantine release is MANUAL by design: the user reviews an entry with
guard_review, then re-sends it themselves if judged safe. There is no
automatic release, because a hook can only block/inject/pass — it
cannot re-deliver a message on the user's behalf.
"""
import re
from datetime import datetime, timezone

from hermes_guard import detector, roots, storage, xray
from hermes_guard.schemas import ACTIONS, ACTIONS_NEED_ID
from hermes_guard.vectors import VECTORS, TOOL_ARG_VECTORS

PREVIEW_MAX = 160


def _clean_text(text):
    """Strip invisible/smuggled characters and redact decoded payloads.

    Returns text safe to copy-paste for a manual re-send. The original
    wording is preserved; only the smuggled layer is removed.
    """
    if not isinstance(text, str):
        text = str(text or "")
    cleaned = detector.strip_invisible(text)
    # Redact any remaining Base64 blob the L4 layer flags.
    for finding in roots.detect_obfuscated_base64(cleaned):
        blob = finding["blob"]
        cleaned = cleaned.replace(blob, "[REDACTED-BASE64]")
    return cleaned


def _render_status(path_override=None):
    """Render the Forensic X-Ray HUD (action=status).

    The arena is computed on demand (in-memory only) and labelled with
    its run time, so the status screen shows both the live posture and
    the latest simulation result — kept separate, as always.
    """
    data = xray.build_status_data(path_override)
    return xray.render_status_hud(data["stats"], data["score"],
                                  data["recent"], arena=data["arena"],
                                  detail=data["detail"])


def _run_simulate():
    """Run the simulation arena in memory. No live state is touched."""
    from hermes_guard import arena
    return arena.run_simulate()


def render_hud_html(path_override=None):
    """Build the standalone guard-hud.html content from live state.

    The arena section is a fresh in-memory simulate() run, labelled
    with its run time. Live telemetry is never polluted by it.
    """
    return xray.render_guard_hud_html(xray.build_status_data(path_override))


def guard_review(action, id=None, limit=20, path_override=None):
    """The guard_review tool. Returns a dict (or a HUD string for status).

    action: one of status, list, show, simulate, clean_copy, release,
    delete. id is required for show, clean_copy, release, delete.
    path_override: explicit SQLite path (tests only).
    """
    if action not in ACTIONS:
        return {"error": "unknown action %r (expected one of %s)"
                         % (action, ", ".join(ACTIONS))}
    if action in ACTIONS_NEED_ID and not id:
        return {"error": "action=%s requires id" % action}

    if action == "status":
        return {"hud": _render_status(path_override)}

    if action == "simulate":
        return _run_simulate()

    if action == "list":
        return {"entries": storage.list_recent(limit=limit,
                                               path_override=path_override)}

    if action == "show":
        entry = storage.get_entry(id, path_override=path_override)
        if entry is None:
            return {"error": "no quarantine entry with id %r" % id}
        entry.pop("full_text", None)
        return {"entry": entry}

    if action == "clean_copy":
        entry = storage.get_entry(id, path_override=path_override)
        if entry is None:
            return {"error": "no quarantine entry with id %r" % id}
        return {
            "id": entry["id"],
            "tier": entry["tier"],
            "cleaned_text": _clean_text(entry["full_text"]),
            "note": "Copy-paste this text to re-send it manually. "
                    "Invisible characters and obfuscated blobs were removed.",
        }

    if action == "release":
        entry = storage.get_entry(id, path_override=path_override)
        if entry is None:
            return {"error": "no quarantine entry with id %r" % id}
        storage.mark_released(id, path_override=path_override)
        return {
            "id": entry["id"],
            "tier": entry["tier"],
            "released": True,
            "original_text": entry["full_text"],
            "note": "Marked released (counts as a false positive for the "
                    "Posture Score). The entry's hidden-instruction "
                    "pattern, if any, is now suppressed — the same phrase "
                    "alone will no longer quarantine a message. Re-send "
                    "the original text manually if you judge it safe.",
        }

    if action == "delete":
        ok = storage.delete_entry(id, path_override=path_override)
        if not ok:
            return {"error": "no quarantine entry with id %r" % id}
        return {"id": id, "deleted": True}

    return {"error": "unhandled action %r" % action}
