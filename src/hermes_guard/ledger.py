"""Hermes Guard — SHA-256 chain ledger (audit trail).

Every guard decision (block / quarantine / flag / pass) is appended as
one ledger entry. Each entry stores the SHA-256 hash of the previous
entry, so tampering with any earlier entry breaks the chain and is
detected by verify().

The ledger is append-only and local. It records decisions, not message
content: only the tier, score, layer flags, and a 160-char preview are
stored. Full message text never enters the ledger.
"""
import hashlib
import json
import time

GENESIS_PREV = "0" * 64


def _entry_hash(prev_hash, payload):
    """SHA-256 over prev_hash + canonical JSON of the payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class Ledger:
    """An in-memory hash-chained list of guard decisions.

    For durability the caller persists entries (see storage.record_ledger);
    this class is the chain logic and verification.
    """

    def __init__(self, entries=None):
        self.entries = list(entries or [])

    def __len__(self):
        return len(self.entries)

    @property
    def head_hash(self):
        if not self.entries:
            return GENESIS_PREV
        return self.entries[-1]["hash"]

    def append(self, tier, score, layers, preview="", session_id=None):
        """Append one decision. Returns the new entry dict."""
        payload = {
            "ts": time.time(),
            "tier": tier,
            "score": int(score),
            "layers": dict(layers or {}),
            "preview": (preview or "")[:160],
            "session_id": session_id,
        }
        entry = dict(payload)
        entry["prev"] = self.head_hash
        entry["hash"] = _entry_hash(entry["prev"], payload)
        self.entries.append(entry)
        return entry

    def verify(self):
        """Verify the whole chain. Returns (ok, bad_index_or_None).

        ok is True when every entry's prev matches the previous hash and
        every entry's hash matches its recomputed value.
        """
        prev = GENESIS_PREV
        for i, entry in enumerate(self.entries):
            if entry.get("prev") != prev:
                return False, i
            payload = {k: entry[k] for k in
                       ("ts", "tier", "score", "layers", "preview", "session_id")}
            if _entry_hash(prev, payload) != entry.get("hash"):
                return False, i
            prev = entry["hash"]
        return True, None
