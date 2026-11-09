"""Hermes Guard — detector.

Adapted from our own anti-decoded scanner
(~/workspace/gerbang-karantina/anti-decoded.py, md5 19da8867dbd1bc511c9d68f8bfce7727)
plus hidden-instruction / jailbreak-phrasing detection patterns.

DETECTION ONLY. Patterns here describe attacks so they can be recognised;
they are never instructions for wrongdoing and never payloads. Any decoded
hidden content is truncated to 160 characters in every report — it is data
for a human reviewer, never something to execute or follow.

v1.1.0 changes (Argon Round 3):
- strip_invisible() normalises a message before phrase matching, so a
  zero-width split keyword ("ig<ZW>gnore") can no longer evade the
  hidden-instruction patterns (was: FLAG only, now: QUARANTINE).
- scan_tool_arguments() guards pre_tool_call: hidden payloads, RCE /
  subshell patterns, sensitive credential paths, tainted-session
  instruction injection.
- Per-sub-function error isolation: every sub-scan is wrapped in
  try/except; failures are reported in result["degraded"] and never
  crash the scan. A degraded scan escalates to at least FLAG locally;
  the hook layer decides block-vs-flag from config (fail-closed).
- Suppressed-pattern consult: a hidden-instruction phrase the owner
  suppressed via guard_review release no longer quarantines on its own.
"""
import collections
import re

SIZE_FLAG = 150_000
SIZE_BLOCK = 500_000
VS_BLOCK = 1_000
ZW_BLOCK = 1_000
BOMB_LINES_MAX = 5
ZW_FLAG = 1  # any zero-width at all is worth a low flag

# ---------------------------------------------------------------------------
# Invisible / smuggled characters (adapted from anti-decoded.py)
# ---------------------------------------------------------------------------

# Characters stripped before phrase matching (Argon Round 3). Removing
# them rejoins split keywords ("ig<ZW>gnore" -> "ignore") without
# changing the visible wording.
_INVIS_STRIP_RE = re.compile(
    r"[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff"
    r"\U000e0000-\U000e01ef]"
)


def strip_invisible(text):
    """Remove invisible/smuggled characters (zero-width, tags, bidi
    controls, BOM, soft hyphen, variation selectors).

    Used to NORMALISE text before phrase matching only. The original
    text is kept for counting and decoding.
    """
    if not isinstance(text, str):
        text = str(text or "")
    return _INVIS_STRIP_RE.sub("", text)


def invis_counts(text):
    """Count invisible / control characters by class."""
    c = collections.Counter()
    for ch in text:
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            c["tag"] += 1
        elif 0xE0100 <= o <= 0xE01EF:
            c["varsel"] += 1
        elif 0xFE00 <= o <= 0xFE0F:
            c["varsel_fe"] += 1
        elif o in (0x200B, 0x200C, 0x200D):
            c["zerowidth"] += 1
        elif o == 0xFEFF:
            c["bom"] += 1
        elif 0x202A <= o <= 0x202E or 0x2066 <= o <= 0x2069:
            c["bidi"] += 1
        elif o < 32 and ch not in "\n\r\t":
            c["ctrl"] += 1
    return c


def decode_tag(text):
    """Attempt-decode Unicode tag characters (U+E0000..U+E007F) as ASCII.

    Detection only; result is truncated to 160 chars wherever reported.
    Returns "" unless the decoded run looks like real text (>= 6 letters).
    """
    out, run = bytearray(), []
    for ch in text:
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            run.append(o - 0xE0000)
        else:
            if len(run) >= 4:
                out.extend(run)
            run = []
    if len(run) >= 4:
        out.extend(run)
    s = bytes(out).decode("ascii", "replace")
    return s if sum(ch.isalpha() for ch in s) >= 6 else ""


def decode_zerowidth(text):
    """Attempt-decode a three-symbol zero-width channel (200B=0, 200C=1,
    200D=separator) into ASCII. Detection only; truncated to 160 chars
    wherever reported. Returns "" unless >= 6 letters decoded."""
    seq = [ch for ch in text if ord(ch) in (0x200B, 0x200C, 0x200D)]
    if len(seq) < 24:
        return ""
    bits = "".join(
        "0" if ch == "\u200b" else "1" if ch == "\u200c" else "" for ch in seq
    )
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = int(bits[i:i + 8], 2)
        out.append(v if 32 <= v < 127 else 63)
    s = bytes(out).decode("ascii", "replace")
    return s if sum(ch.isalpha() for ch in s) >= 6 else ""


def mixed_script_flag(text):
    """True when one word mixes Latin with Cyrillic or Greek letters
    (homoglyph / look-alike spoofing). Adapted from anti-decoded.py."""
    words = re.findall(r"[A-Za-z\u0400-\u04FF\u0370-\u03FF]{4,}", text)
    for w in words:
        has_lat = any("a" <= ch.lower() <= "z" for ch in w)
        has_other = any(
            0x0400 <= ord(ch) <= 0x04FF or 0x0370 <= ord(ch) <= 0x03FF
            for ch in w
        )
        if has_lat and has_other:
            return True
    return False


# ---------------------------------------------------------------------------
# Hidden-instruction / jailbreak phrasing patterns (detection only)
# ---------------------------------------------------------------------------

_HIDDEN_INSTRUCTION_PATTERNS = [
    # English
    r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
    r"disregard\s+(all\s+)?(your|the|previous|prior)\s+instructions?",
    r"forget\s+(all\s+)?(your|the|previous|prior)\s+instructions?",
    r"override\s+(your|the)\s+(instructions?|system|rules?)",
    r"you\s+are\s+now\s+",
    r"reveal\s+(your|the)\s+(system\s+)?prompt",
    r"show\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
    r"repeat\s+(your|the)\s+(system\s+)?(instructions?|prompt)",
    r"act\s+as\s+if\s+you\s+(have\s+no|were\s+not|are\s+not)",
    r"pretend\s+you\s+(are|have)\s+",
    r"do\s+not\s+(follow|obey)\s+(your|the|any)\s+",
    r"new\s+instructions?:",
    r"system\s*:\s*you\s+are",
    r"<\s*system\s*>",
    # Indonesian
    r"abaikan\s+(semua\s+)?instruksi",
    r"lupakan\s+(semua\s+)?instruksi",
    r"abaikan\s+(semua\s+)?perintah",
    r"kamu\s+sekarang\s+",
    r"tampilkan\s+(prompt|instruksi)\s+sistem",
    r"ungkapkan\s+(prompt|instruksi)\s+sistem",
    r"berpura-puralah\s+",
    r"jangan\s+ikuti\s+instruksi",
    r"instruksi\s+baru\s*:",
]

_HIDDEN_INSTRUCTION_RE = re.compile(
    "|".join("(?:" + p + ")" for p in _HIDDEN_INSTRUCTION_PATTERNS),
    re.IGNORECASE,
)

_SPECIAL_TOKEN_RE = re.compile(r"<\|[^|\n]{1,64}\|>")


def hidden_instruction_match(text):
    """Return the first matching hidden-instruction phrase, or None."""
    m = _HIDDEN_INSTRUCTION_RE.search(text)
    return m.group(0) if m else None


def special_token_match(text):
    """Return the first <|...|> special-token marker, or None."""
    m = _SPECIAL_TOKEN_RE.search(text)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# Tool-argument guard (pre_tool_call) — Argon Round 3, v1.1.0
# ---------------------------------------------------------------------------

# RCE / subshell patterns in tool arguments (detection only).
# Argon's spec patterns, plus Ciel's bare-`rm -rf` hardening: Argon's
# `;\s*rm\s+-[rRfF]+` requires a preceding semicolon, so a bare
# `rm -rf /tmp/x` (the known Manas Aegis RCE-pattern gap) slipped
# through. In tool-argument context a bare `rm -rf` is an execution,
# not a discussion, so it is blocked here.
_TOOL_RCE_RE = re.compile(
    r"(?:\$\([^)]+\)|`[^`]+`|;\s*rm\s+-[rRfF]+|\|\s*(?:sh|bash|zsh)\b"
    r"|>\s*/dev/tcp/|\brm\s+-[^\s]*[rfRF]\b)"
)

# Sensitive credential paths. NOTE (Ciel fix, Round 3): Argon's
# terminator class `(?:$|[/\\]|\s)` assumed bare-path input, but tool
# arguments arrive JSON-serialised, so a quoted path (".ssh/id_rsa")
# ends in `"` and never matched. The terminator now also accepts JSON
# punctuation (`"`, `'`, `,`, `}`, `]`).
_TOOL_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|[/\\])(?:\.env|\.ssh[/\\]id_[a-z0-9_]+|etc[/\\]shadow"
    r"|credentials\.json)(?:$|[/\\]|\s|[\"',}\]])"
)


def rce_pattern_match(text):
    """Return the first RCE/subshell pattern in *text*, or None."""
    if not isinstance(text, str):
        text = str(text or "")
    m = _TOOL_RCE_RE.search(text)
    return m.group(0) if m else None


def scan_tool_arguments(args_text, session_tainted=False):
    """Scan tool-call arguments (pre_tool_call).

    Checks, in order: decoded hidden Unicode payloads, RCE/subshell
    patterns, sensitive credential paths, and (only when the session
    is tainted) hidden-instruction phrasing. Any hit blocks the call.

    Returns {"tier": "block"|"pass", "score": int, "reasons": [str]}.
    """
    if not isinstance(args_text, str):
        args_text = str(args_text)
    reasons = []
    if decode_tag(args_text) or decode_zerowidth(args_text):
        reasons.append("decoded hidden unicode payload in tool arguments")
    rce = rce_pattern_match(args_text)
    if rce:
        reasons.append(
            "dangerous command substitution / RCE pattern in tool "
            "arguments: %s" % rce[:80]
        )
    if _TOOL_SENSITIVE_PATH_RE.search(args_text):
        reasons.append(
            "sensitive credential path access in tool arguments"
        )
    if session_tainted:
        phrase = hidden_instruction_match(strip_invisible(args_text))
        if phrase:
            reasons.append(
                "tainted session attempting instruction injection in "
                "tool arguments: %r" % phrase[:120]
            )
    return {
        "tier": "block" if reasons else "pass",
        "score": 100 if reasons else 0,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def _safe(fn, layer, degraded, default):
    """Run one sub-scan; on exception record the layer as degraded and
    return *default* instead of crashing the scan."""
    try:
        return fn()
    except Exception:
        degraded.append(layer)
        return default


def scan_text(text, suppressed_patterns=None):
    """Scan one inbound message.

    Returns {"tier": "block"|"quarantine"|"flag"|"pass",
             "score": int, "reasons": [str],
             "degraded": [layer names that raised],
             "matched_phrase": str|None (hidden-instruction phrase found),
             "phrase_suppressed": bool}.

    Tier rules:
      block       — high-confidence attack: decoded hidden payload, massive
                    invisible-char counts (>= 1000), context-bomb shape
                    (> 150000 bytes in <= 5 lines), huge size (>= 500000).
      quarantine  — suspicious, hold: mixed-script homoglyph, special-token
                    markers <|...|>, moderate invisible chars, hidden-
                    instruction phrasing.
      flag        — low: small invisible-char counts, large size, or a
                    degraded sub-scan (at least FLAG locally; the hook
                    layer decides block-vs-flag from config).
      pass        — clean.

    Phrase matching runs on strip_invisible() output, so zero-width
    split keywords cannot evade it. Bidi controls are counted in
    invis_counts and quarantine at total invisible >= 10; there is NO
    `bidi >= 1` rule (a single bidi/isolate char is legitimate in RTL
    text — Argon Round 3's literal `>= 1` was rejected, see DECISIONS.md).

    suppressed_patterns: an optional set of normalised (lowercased,
    stripped) hidden-instruction phrases the owner suppressed via
    guard_review release. A suppressed phrase alone does not
    quarantine; every other trigger still fires.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    reasons = []
    score = 0
    tier = "pass"
    degraded = []
    suppressed = suppressed_patterns or set()

    norm = strip_invisible(text)
    inv = _safe(lambda: invis_counts(text), "invis_counts", degraded,
                collections.Counter())
    hidden_tag = _safe(lambda: decode_tag(text), "decode_tag", degraded, "")
    hidden_zw = _safe(lambda: decode_zerowidth(text), "decode_zerowidth",
                      degraded, "")
    size = len(text.encode("utf-8", "replace"))
    lines = text.count("\n") + 1

    # --- block tier -------------------------------------------------------
    if hidden_tag:
        tier = "block"
        score += 100
        reasons.append(
            "decoded hidden tag payload: %r" % hidden_tag[:160]
        )
    if hidden_zw:
        tier = "block"
        score += 100
        reasons.append(
            "decoded hidden zero-width payload: %r" % hidden_zw[:160]
        )
    vs_total = inv.get("varsel", 0) + inv.get("varsel_fe", 0)
    if vs_total >= VS_BLOCK:
        tier = "block"
        score += 80
        reasons.append(
            "massive variation-selector load: %d chars" % vs_total
        )
    if inv.get("zerowidth", 0) >= ZW_BLOCK:
        tier = "block"
        score += 80
        reasons.append(
            "massive zero-width load: %d chars" % inv["zerowidth"]
        )
    if size >= SIZE_BLOCK:
        tier = "block"
        score += 60
        reasons.append("size %d bytes >= block threshold %d" % (size, SIZE_BLOCK))
    elif lines <= BOMB_LINES_MAX and size > SIZE_FLAG:
        tier = "block"
        score += 60
        reasons.append(
            "context-bomb shape: %d bytes in %d lines" % (size, lines)
        )

    # --- quarantine tier --------------------------------------------------
    mixed = _safe(lambda: mixed_script_flag(text), "mixed_script",
                  degraded, False)
    token = _safe(lambda: special_token_match(norm), "special_token",
                  degraded, None)
    phrase = _safe(lambda: hidden_instruction_match(norm),
                   "hidden_instruction", degraded, None)
    phrase_suppressed = bool(
        phrase and phrase.strip().lower() in suppressed
    )
    if tier != "block":
        if mixed:
            tier = "quarantine"
            score += 40
            reasons.append(
                "mixed Latin + Cyrillic/Greek script in one word "
                "(possible homoglyph)"
            )
        if token:
            tier = "quarantine"
            score += 40
            reasons.append("special-token marker found: %s" % token[:80])
        if phrase and not phrase_suppressed:
            tier = "quarantine"
            score += 50
            reasons.append(
                "hidden-instruction phrasing: %r" % phrase[:120]
            )
        inv_total = sum(inv.values())
        if inv_total >= 10:
            tier = "quarantine"
            score += 30
            reasons.append(
                "moderate invisible characters: %s" % dict(inv)
            )

    # --- flag tier --------------------------------------------------------
    if tier == "pass":
        inv_total = sum(inv.values())
        if inv_total > 0:
            tier = "flag"
            score += 10
            reasons.append(
                "small invisible-character count: %s" % dict(inv)
            )
        if size > SIZE_FLAG:
            tier = "flag"
            score += 10
            reasons.append("large size: %d bytes" % size)

    # --- degraded: never crash, never pass silently -----------------------
    if degraded:
        if tier == "pass":
            tier = "flag"
            score += 10
        reasons.append(
            "detector degraded (sub-scan failed): %s" % ", ".join(degraded)
        )

    return {
        "tier": tier,
        "score": score,
        "reasons": reasons,
        "degraded": degraded,
        "matched_phrase": phrase,
        "phrase_suppressed": phrase_suppressed,
    }
