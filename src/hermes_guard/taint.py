"""Hermes Guard — session taint tracking and call-ID race guard.

Taint: a session becomes TAINTED when one of its inbound messages hits
FLAG or QUARANTINE at pre_llm_call. A tainted session gets stricter
pre_tool_call scrutiny: tool calls that touch protected paths or that
carry decoded hidden payloads are blocked.

Call-ID race guard: the same runtime call — same session, same tool,
same arguments hash — repeated inside a short window is treated as a
retry-storm / replay and hard-blocked. Simulation traffic is exempt
(it never carries a real session id).
"""
import hashlib
import json
import time

# A session stays tainted for 60 minutes after its last taint event.
TAINT_TTL_SECONDS = 3600
# Identical call (session+tool+args-hash) inside this window is a race.
CALLID_RACE_WINDOW_SECONDS = 10


def _args_fingerprint(args):
    """Stable short fingerprint of tool-call arguments."""
    try:
        canonical = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        canonical = str(args)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class TaintTracker:
    """In-memory taint + call-ID state. One instance per plugin process."""

    def __init__(self, taint_ttl=TAINT_TTL_SECONDS,
                 race_window=CALLID_RACE_WINDOW_SECONDS, clock=None):
        self.taint_ttl = taint_ttl
        self.race_window = race_window
        self._clock = clock or time.time
        # session_id -> tainted_until (epoch seconds)
        self._tainted = {}
        # (session_id, tool, args_fp) -> last seen epoch seconds
        self._calls = {}

    def _now(self):
        return self._clock()

    # -- taint ------------------------------------------------------------
    def taint_session(self, session_id):
        """Mark a session tainted (until TTL from now)."""
        if session_id is None:
            return
        self._tainted[session_id] = self._now() + self.taint_ttl

    def is_tainted(self, session_id):
        """True when the session is currently tainted (and not expired)."""
        if session_id is None:
            return False
        until = self._tainted.get(session_id)
        if until is None:
            return False
        if self._now() > until:
            del self._tainted[session_id]
            return False
        return True

    def tainted_sessions(self):
        """List currently-tainted session ids (expired ones pruned)."""
        now = self._now()
        live = []
        for sid, until in list(self._tainted.items()):
            if now > until:
                del self._tainted[sid]
            else:
                live.append(sid)
        return live

    # -- call-ID race ------------------------------------------------------
    def check_call(self, session_id, tool, args):
        """Check one runtime tool call for a race.

        Returns (is_race, fingerprint). is_race is True when the identical
        call (session+tool+args fingerprint) was seen inside the race
        window. The call is recorded either way.
        """
        fp = _args_fingerprint(args)
        key = (session_id, tool, fp)
        now = self._now()
        last = self._calls.get(key)
        self._calls[key] = now
        # Prune stale entries so the table does not grow unboundedly.
        cutoff = now - max(self.race_window, 60)
        for k, v in list(self._calls.items()):
            if v < cutoff:
                del self._calls[k]
        if last is not None and (now - last) < self.race_window:
            return True, fp
        return False, fp
