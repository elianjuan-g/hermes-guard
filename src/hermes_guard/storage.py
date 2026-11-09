"""Hermes Guard — durable quarantine + telemetry storage.

Uses the Hermes plugin storage API when running inside Hermes
(`plugins.plugin_storage.plugin_db`), and falls back to a local SQLite
file ONLY when that import is absent (test environment / this VM, which
has no Hermes install). Runtime state is never written into the plugin
directory.

Tables:
  quarantine — held messages (preview capped at 160 chars in output).
  stats      — live telemetry counters (real traffic only; simulation
               never touches these counters).
  ledger     — hash-chained guard decisions (append-only audit trail).
  degraded   — sub-detector layers that raised (for the Posture Score).
  patterns   — Predator signature store: hidden-instruction phrases
               that caused a hold; owners can suppress one via release.

v1.1.0: posture_score() implements the Argon Round 3 plain-text
formula (base components minus pending-quarantine, degraded-layer
and false-positive-ratio penalties). Secrets are redacted before
anything is persisted (redact_secrets).
"""
import json
import os
import re
import sqlite3
import time
import uuid

PLUGIN_NAME = "hermes-guard"

SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    session_id TEXT,
    tier TEXT NOT NULL,
    reasons TEXT NOT NULL,
    preview TEXT NOT NULL,
    full_text TEXT NOT NULL,
    released INTEGER NOT NULL DEFAULT 0,
    pattern TEXT
);
CREATE TABLE IF NOT EXISTS stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    tier TEXT NOT NULL,
    score INTEGER NOT NULL,
    layers TEXT NOT NULL,
    preview TEXT NOT NULL,
    session_id TEXT,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS degraded (
    layer TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS patterns (
    pattern TEXT PRIMARY KEY,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    suppressed INTEGER NOT NULL DEFAULT 0
);
"""

PREVIEW_MAX = 160

# Live-telemetry counter keys. Simulation runs never increment these.
STAT_KEYS = ("blocked", "quarantined", "flagged", "passed",
             "false_positive", "detector_error")


def _fallback_path():
    """Local SQLite path used only when the Hermes storage API is absent."""
    base = os.environ.get("HERMES_GUARD_DATA_DIR") or os.path.join(
        os.path.expanduser("~"), ".local", "share", "hermes-guard"
    )
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, "quarantine.db")


def _migrate(conn):
    """Add columns tables created before v1.1.0 lack (idempotent)."""
    cols = [r[1] for r in
            conn.execute("PRAGMA table_info(quarantine)").fetchall()]
    if "pattern" not in cols:
        conn.execute("ALTER TABLE quarantine ADD COLUMN pattern TEXT")
        conn.commit()


def get_db(path_override=None):
    """Return a SQLite connection with all tables created.

    path_override: explicit file path (used by tests). Otherwise try the
    Hermes plugin_db() first; fall back to a local file only when the
    hermes import is unavailable.
    """
    if path_override is not None:
        conn = sqlite3.connect(path_override)
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        return conn

    try:
        from plugins.plugin_storage import plugin_db  # type: ignore
    except Exception:
        conn = sqlite3.connect(_fallback_path())
        conn.row_factory = sqlite3.Row
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        return conn

    conn = plugin_db(PLUGIN_NAME)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Secret redaction (privacy-by-design: never persist a raw secret)
# ---------------------------------------------------------------------------

_SECRET_RES = [
    # API keys / tokens with recognisable prefixes.
    re.compile(r"sk-[A-Za-z0-9]{8,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"gho_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{10,}"),
    # Private-key blocks.
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
               r".*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
               re.DOTALL),
]
# key = value assignments: keep the key name, redact the value.
_SECRET_KV_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*"
    r"(?:\"[^\"]+\"|'[^']+'|\S+)"
)


def redact_secrets(text):
    """Mask recognisable secrets in *text* with [REDACTED-SECRET].

    Applied to every preview / full text before persistence, so a
    quarantined message can never leak a credential into the log.
    """
    if not isinstance(text, str):
        text = str(text or "")
    out = text
    for rx in _SECRET_RES:
        out = rx.sub("[REDACTED-SECRET]", out)
    out = _SECRET_KV_RE.sub(r"\1=[REDACTED-SECRET]", out)
    return out


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def record_quarantine(session_id, tier, reasons, preview, full_text,
                      pattern=None, path_override=None):
    """Insert one quarantine entry. Returns the new entry id (uuid4 hex).

    preview is truncated to 160 chars here as a second safety net; callers
    should already truncate. Secrets are redacted before storage.
    pattern: the normalised hidden-instruction phrase that caused the
    hold, if any (used by the Predator pattern store).
    """
    entry_id = uuid.uuid4().hex
    conn = get_db(path_override)
    try:
        conn.execute(
            "INSERT INTO quarantine "
            "(id, created_at, session_id, tier, reasons, preview, full_text, "
            "pattern) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry_id,
                time.time(),
                session_id,
                tier,
                "\n".join(reasons) if isinstance(reasons, (list, tuple)) else str(reasons),
                redact_secrets((preview or "")[:PREVIEW_MAX]),
                redact_secrets(full_text or ""),
                pattern,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return entry_id


def list_recent(limit=20, path_override=None):
    """Return recent quarantine entries (newest first) as dicts.

    full_text is never included in list output; preview is capped at 160.
    Released entries are included with released=1.
    """
    if limit is None:
        limit = 20
    limit = max(1, min(int(limit), 100))
    conn = get_db(path_override)
    try:
        rows = conn.execute(
            "SELECT id, created_at, session_id, tier, reasons, preview, "
            "released, pattern FROM quarantine "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["preview"] = (d["preview"] or "")[:PREVIEW_MAX]
        d["released"] = int(d.get("released") or 0)
        out.append(d)
    return out


def get_entry(entry_id, path_override=None):
    """Return one quarantine entry as a dict, or None if not found.

    The full original message is included here (it lives only in the local
    plugin DB); callers must not print it in full — guard_review exposes
    only the 160-char preview, except for release/clean_copy which the
    user explicitly requested.
    """
    conn = get_db(path_override)
    try:
        row = conn.execute(
            "SELECT id, created_at, session_id, tier, reasons, preview, "
            "full_text, released, pattern FROM quarantine WHERE id = ?",
            (entry_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    d = dict(row)
    d["preview"] = (d["preview"] or "")[:PREVIEW_MAX]
    d["released"] = int(d.get("released") or 0)
    return d


def held_count(path_override=None):
    """Number of quarantine entries not yet reviewed (released=0)."""
    conn = get_db(path_override)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM quarantine WHERE released = 0"
        ).fetchone()
    finally:
        conn.close()
    return int(row[0]) if row else 0


def mark_released(entry_id, path_override=None):
    """Mark an entry released (user reviewed and re-sent it manually).

    A release counts as a false positive for the Posture Score: the
    guard held something the user judged safe. The entry's pattern, if
    any, is suppressed in the Predator store so the same phrase alone
    no longer quarantines.
    Returns True when the entry existed.
    """
    conn = get_db(path_override)
    try:
        row = conn.execute(
            "SELECT pattern FROM quarantine WHERE id = ?", (entry_id,)
        ).fetchone()
        cur = conn.execute(
            "UPDATE quarantine SET released = 1 WHERE id = ?", (entry_id,)
        )
        conn.commit()
        changed = cur.rowcount > 0
        if changed:
            bump_stat("false_positive", 1, path_override=path_override, _conn=conn)
            if row and row[0]:
                # Ensure the pattern exists in the store (record_quarantine
                # alone does not insert it), then suppress it.
                conn.execute(
                    "INSERT OR IGNORE INTO patterns (pattern, first_seen,"
                    " last_seen, hits, suppressed) VALUES (?, ?, ?, 0, 0)",
                    (row[0], time.time(), time.time()),
                )
                conn.execute(
                    "UPDATE patterns SET suppressed = 1 WHERE pattern = ?",
                    (row[0],),
                )
            conn.commit()
        return changed
    finally:
        conn.close()


def delete_entry(entry_id, path_override=None):
    """Permanently delete one quarantine entry. Returns True if removed."""
    conn = get_db(path_override)
    try:
        cur = conn.execute(
            "DELETE FROM quarantine WHERE id = ?", (entry_id,)
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Telemetry stats (live traffic only — simulation never calls these)
# ---------------------------------------------------------------------------

def bump_stat(key, delta=1, path_override=None, _conn=None):
    """Increment one live-telemetry counter. No-op for unknown keys."""
    if key not in STAT_KEYS:
        return
    conn = _conn or get_db(path_override)
    try:
        conn.execute(
            "INSERT INTO stats (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = value + ?",
            (key, delta, delta),
        )
        if _conn is None:
            conn.commit()
    finally:
        if _conn is None:
            conn.close()


def get_stats(path_override=None):
    """Return live-telemetry counters as a dict (all keys present)."""
    conn = get_db(path_override)
    try:
        rows = conn.execute("SELECT key, value FROM stats").fetchall()
    finally:
        conn.close()
    out = {k: 0 for k in STAT_KEYS}
    for r in rows:
        if r["key"] in out:
            out[r["key"]] = int(r["value"])
    return out


# ---------------------------------------------------------------------------
# Degraded sub-detector layers
# ---------------------------------------------------------------------------

def record_degraded(layer, path_override=None):
    """Record that sub-detector *layer* raised (count + last_seen)."""
    conn = get_db(path_override)
    try:
        conn.execute(
            "INSERT INTO degraded (layer, count, last_seen) "
            "VALUES (?, 1, ?) "
            "ON CONFLICT(layer) DO UPDATE SET count = count + 1, "
            "last_seen = excluded.last_seen",
            (layer, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def get_degraded_layers(path_override=None):
    """Return degraded layers as [{"layer", "count", "last_seen"}]."""
    conn = get_db(path_override)
    try:
        rows = conn.execute(
            "SELECT layer, count, last_seen FROM degraded ORDER BY layer"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def clear_degraded(path_override=None):
    """Clear all degraded-layer records (e.g. after a fix + re-test)."""
    conn = get_db(path_override)
    try:
        conn.execute("DELETE FROM degraded")
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Predator pattern store (human-corrected signature store)
# ---------------------------------------------------------------------------

def _normalise_pattern(pattern):
    return (pattern or "").strip().lower()


def record_pattern(pattern, path_override=None):
    """Record a hidden-instruction phrase that caused a hold."""
    key = _normalise_pattern(pattern)
    if not key:
        return
    now = time.time()
    conn = get_db(path_override)
    try:
        conn.execute(
            "INSERT INTO patterns "
            "(pattern, first_seen, last_seen, hits, suppressed) "
            "VALUES (?, ?, ?, 1, 0) "
            "ON CONFLICT(pattern) DO UPDATE SET hits = hits + 1, "
            "last_seen = excluded.last_seen",
            (key, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def suppress_pattern(pattern, path_override=None):
    """Suppress a pattern (owner judged it a false positive).

    Returns True when the pattern existed.
    """
    key = _normalise_pattern(pattern)
    if not key:
        return False
    conn = get_db(path_override)
    try:
        cur = conn.execute(
            "UPDATE patterns SET suppressed = 1 WHERE pattern = ?", (key,)
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def is_suppressed(pattern, path_override=None):
    """True when *pattern* is suppressed in the store."""
    key = _normalise_pattern(pattern)
    if not key:
        return False
    conn = get_db(path_override)
    try:
        row = conn.execute(
            "SELECT suppressed FROM patterns WHERE pattern = ?", (key,)
        ).fetchone()
    finally:
        conn.close()
    return bool(row and row[0])


def list_patterns(suppressed_only=False, path_override=None):
    """Return patterns as [{"pattern", "hits", "suppressed", ...}]."""
    conn = get_db(path_override)
    try:
        if suppressed_only:
            rows = conn.execute(
                "SELECT pattern, first_seen, last_seen, hits, suppressed "
                "FROM patterns WHERE suppressed = 1 ORDER BY pattern"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT pattern, first_seen, last_seen, hits, suppressed "
                "FROM patterns ORDER BY pattern"
            ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["suppressed"] = int(d.get("suppressed") or 0)
        out.append(d)
    return out


def suppressed_pattern_set(path_override=None):
    """Return the set of suppressed pattern strings (for scan consult)."""
    return {p["pattern"] for p in list_patterns(suppressed_only=True,
                                                path_override=path_override)}


# ---------------------------------------------------------------------------
# Posture Score — Argon Round 3 plain-text formula (v1.1.0)
# ---------------------------------------------------------------------------

# Base component weights (max 100 when all five are healthy).
BASE_WEIGHTS = {
    "pre_llm_call_active": 35,
    "pre_tool_call_active": 25,
    "fail_closed": 20,
    "redaction_enabled": 10,
    "ledger_verified": 10,
}


def _ledger_ok(path_override=None):
    """Verify the persisted hash chain. Empty ledger counts as OK."""
    from .ledger import Ledger

    entries = load_ledger_entries(path_override)
    if not entries:
        return True
    ok, _bad = Ledger(entries).verify()
    return bool(ok)


def posture_detail(path_override=None, config=None):
    """Compute the Posture Score with its components.

    config: dict of base-component booleans
        (pre_llm_call_active, pre_tool_call_active, fail_closed_on_error,
        redact_secrets). None means "plugin defaults, all healthy" —
        standalone CLI use measures configuration health; the live
        ledger check is always computed from the DB.

        score = base - min(held*5, 25) - degraded*15
                - round(min(15, (released/total)*30))
        base  = sum of the five component weights (max 100)
        held  = quarantine entries not yet reviewed
        total = blocked + quarantined (0 => FP penalty 0)

    Correct blocks, quarantines and flags NEVER reduce the score.
    """
    cfg = dict(config) if isinstance(config, dict) else {}
    base = 0
    components = {}
    components["pre_llm_call_active"] = bool(
        cfg.get("pre_llm_call_active", True))
    components["pre_tool_call_active"] = bool(
        cfg.get("pre_tool_call_active", True))
    components["fail_closed"] = bool(cfg.get("fail_closed_on_error", True))
    components["redaction_enabled"] = bool(cfg.get("redact_secrets", True))
    components["ledger_verified"] = _ledger_ok(path_override)
    for key, weight in BASE_WEIGHTS.items():
        if components[key]:
            base += weight

    stats = get_stats(path_override)
    held = held_count(path_override)
    pending_penalty = min(held * 5, 25)
    degraded_layers = get_degraded_layers(path_override)
    degraded_penalty = len(degraded_layers) * 15
    released = stats["false_positive"]
    total = stats["blocked"] + stats["quarantined"]
    if total <= 0:
        fp_penalty = 0
    else:
        fp_penalty = round(min(15, (released / total) * 30))
    score = max(0, min(100, base - pending_penalty
                       - degraded_penalty - fp_penalty))
    return {
        "score": score,
        "base": base,
        "components": components,
        "held": held,
        # Canonical keys used by the HUD renderers:
        "pending": pending_penalty,
        "degraded": degraded_penalty,
        "false_positive": fp_penalty,
        "intercepted": total,
        # Aliases (same values, kept for readability in tests):
        "pending_penalty": pending_penalty,
        "degraded_layers": [d["layer"] for d in degraded_layers],
        "degraded_penalty": degraded_penalty,
        "released": released,
        "total_interceptions": total,
        "fp_penalty": fp_penalty,
    }


def posture_score(path_override=None, config=None):
    """Posture Score (0-100) from live telemetry + configuration.

    See posture_detail() for the formula. A fresh install with no
    history scores 100. A guard that blocks many real attacks still
    scores 100 — blocking never reduces it.
    """
    return posture_detail(path_override, config)["score"]


# ---------------------------------------------------------------------------
# Ledger persistence
# ---------------------------------------------------------------------------

def record_ledger_entry(entry, path_override=None):
    """Persist one Ledger entry dict. Returns the row id."""
    conn = get_db(path_override)
    try:
        cur = conn.execute(
            "INSERT INTO ledger (ts, tier, score, layers, preview, "
            "session_id, prev, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry["ts"], entry["tier"], entry["score"],
                entry["layers"] if isinstance(entry["layers"], str)
                else json.dumps(entry["layers"], sort_keys=True),
                redact_secrets((entry.get("preview") or "")[:PREVIEW_MAX]),
                entry.get("session_id"),
                entry["prev"], entry["hash"],
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def load_ledger_entries(path_override=None):
    """Load all persisted ledger entries in chain order."""
    conn = get_db(path_override)
    try:
        rows = conn.execute(
            "SELECT ts, tier, score, layers, preview, session_id, prev, hash "
            "FROM ledger ORDER BY seq ASC"
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["layers"] = json.loads(d["layers"])
        except Exception:
            d["layers"] = {}
        out.append(d)
    return out
