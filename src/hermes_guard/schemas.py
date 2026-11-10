"""Hermes Guard — guard_review tool (JSON schema for plugin.yaml).

Five model actions:
  status     — Forensic X-Ray HUD: live posture, L1-L4 matrix, real-only
               telemetry, latest intercept, commands. No id needed.
  list       — recent quarantine entries (newest first).
  show       — one entry by id (160-char preview only).
  simulate   — run the 24-vector arena in memory. Never touches live
               telemetry or the quarantine DB. Returns per-vector tiers
               plus a summary. No id needed.
  clean_copy — return a cleaned copy of one entry (invisible chars
               stripped, hidden payloads redacted) for manual re-send.

release/delete are NOT model actions (v1.1.2, teknium1 review): they
are owner-only slash commands (/guard-release, /guard-delete), so
injected text in a tool result cannot steer the model into weakening
the guard.
"""

GUARD_REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "enum": ["status", "list", "show", "simulate", "clean_copy"],
            "description": "status: X-Ray HUD. list: recent held messages. "
                           "show: one held message by id. simulate: run the "
                           "24-vector arena in memory. clean_copy: cleaned "
                           "text for manual re-send. release/delete are "
                           "owner-only slash commands, not tool actions.",
        },
        "id": {
            "type": "string",
            "description": "Quarantine entry id (required for show and "
                           "clean_copy).",
        },
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
            "default": 20,
            "description": "Max entries for action=list.",
        },
    },
    "required": ["action"],
    "additionalProperties": False,
}

ACTIONS = ("status", "list", "show", "simulate", "clean_copy")
ACTIONS_NEED_ID = ("show", "clean_copy")
