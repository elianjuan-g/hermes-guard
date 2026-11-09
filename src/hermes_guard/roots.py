"""Hermes Guard — roots (defense layers L1-L4).

L1 "invisible" — Unicode smuggling: zero-width, tags, variation
   selectors, bidi overrides, BOM, control chars.
L2 "instruction" — hidden-instruction / jailbreak phrasing (EN + ID).
L3 "token" — special-token markers <|...|> and mixed-script homoglyphs.
L4 "encoding" — Base64 smuggling: a Base64 blob whose DECODED content
   matches a threat pattern (hidden instruction, special token, RCE).

L1-L3 reuse detector.py. L4 is new here.

v1.1.0 (Argon Round 3) — the L4 rule changed fundamentally. The old
rule judged the ENTROPY of the decoded bytes (>= 3.2), which produced
two real false positives, both measured on v1.0.0:
  * a Base64 config blob (JSON, no spaces) decoded to H=4.20 and was
    quarantined, because looks_like_natural_language() required spaces;
  * the ordinary word "internationalization" (20 Base64-alphabet chars)
    decoded to H=3.64 and was quarantined.
The new rule never punishes decoded content for being English (or
JSON, or any readable text). It only flags a blob when the decoded
text itself matches a threat pattern. Binary (non-printable) decodes
are data, not instructions, and are ignored — the old "opaque blob"
flagging is gone, with the behaviour change documented in tests.md.
A token-entropy gate (>= 4.0) keeps ordinary long words out of the
candidate set: "internationalization" measures 2.95, real Base64
tokens measure 5.0+.
"""
import base64
import collections
import math
import re

from . import detector

LAYER_NAMES = {
    "L1": "invisible",
    "L2": "instruction",
    "L3": "token",
    "L4": "encoding",
}

# A Base64 candidate: at least 20 chars from the Base64 alphabet,
# optionally padded. Word-boundary aware so we don't match fragments
# of longer words. (Argon's text says >= 20; its code regex said
# {24,} — 20 is used, see DECISIONS.md Track 2.)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")

# Token-entropy gate (Argon's text value; its code said 3.8 — both
# separate the measured cases, 4.0 is the more conservative choice).
TOKEN_ENTROPY_MIN = 4.0
MIN_DECODED_LEN = 8
PRINTABLE_MIN = 0.75


def shannon_entropy(data):
    """Shannon entropy (bits per byte) of a bytes object."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _token_entropy(s):
    """Shannon entropy (bits per char) of a Base64 token string."""
    if not s:
        return 0.0
    return shannon_entropy(s.encode("ascii", "replace"))


def scan_base64_smuggling(text):
    """Decode Base64 candidates and scan the DECODED text for threats.

    Returns the first threat reason string, or None. Readable decoded
    text that matches no threat pattern is NEVER flagged (0 false
    positives on natural language, config JSON, or ordinary words).
    """
    if not isinstance(text, str):
        text = str(text)
    for m in _B64_RE.finditer(text):
        token = m.group(0)
        if len(token) % 4 != 0 or _token_entropy(token) < TOKEN_ENTROPY_MIN:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except Exception:
            continue
        if len(decoded) < MIN_DECODED_LEN:
            continue
        printable = sum(
            1 for ch in decoded if ch.isprintable() or ch in "\n\r\t"
        )
        if printable / max(1, len(decoded)) < PRINTABLE_MIN:
            # Binary data (image bytes, hashes): not an instruction.
            continue
        norm = detector.strip_invisible(decoded)
        phrase = detector.hidden_instruction_match(norm)
        if phrase:
            return (
                "base64-smuggled instruction payload (%r)" % phrase[:80]
            )
        sp_tok = detector.special_token_match(norm)
        if sp_tok:
            return "base64-smuggled special token (%s)" % sp_tok[:60]
        rce = detector.rce_pattern_match(norm)
        if rce:
            return "base64-smuggled RCE pattern (%s)" % rce[:60]
    return None


def detect_obfuscated_base64(text):
    """Find Base64 blobs whose decoded text matches a threat pattern.

    Returns a list of dicts: {"blob": str, "decoded_preview": str,
    "entropy": float (token entropy), "kind": str, "reason": str}.
    Empty list means none found.
    """
    if not isinstance(text, str):
        text = str(text)
    findings = []
    for m in _B64_RE.finditer(text):
        token = m.group(0)
        if len(token) % 4 != 0 or _token_entropy(token) < TOKEN_ENTROPY_MIN:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
            decoded = raw.decode("utf-8", errors="strict")
        except Exception:
            continue
        if len(decoded) < MIN_DECODED_LEN:
            continue
        printable = sum(
            1 for ch in decoded if ch.isprintable() or ch in "\n\r\t"
        )
        if printable / max(1, len(decoded)) < PRINTABLE_MIN:
            continue
        norm = detector.strip_invisible(decoded)
        phrase = detector.hidden_instruction_match(norm)
        if phrase:
            findings.append({
                "blob": token[:80],
                "decoded_preview": decoded[:160],
                "entropy": round(_token_entropy(token), 2),
                "kind": "instruction",
                "reason": "base64-smuggled instruction payload: %r"
                          % phrase[:80],
            })
            continue
        sp_tok = detector.special_token_match(norm)
        if sp_tok:
            findings.append({
                "blob": token[:80],
                "decoded_preview": decoded[:160],
                "entropy": round(_token_entropy(token), 2),
                "kind": "special_token",
                "reason": "base64-smuggled special token: %s" % sp_tok[:60],
            })
            continue
        rce = detector.rce_pattern_match(norm)
        if rce:
            findings.append({
                "blob": token[:80],
                "decoded_preview": decoded[:160],
                "entropy": round(_token_entropy(token), 2),
                "kind": "rce",
                "reason": "base64-smuggled RCE pattern: %s" % rce[:60],
            })
    return findings


def scan_roots(text, suppressed_patterns=None):
    """Scan one message through all four layers.

    Returns the detector.scan_text() result dict, extended with:
      "layers": {"L1": bool, "L2": bool, "L3": bool, "L4": bool}
      "b64_findings": [detect_obfuscated_base64() results]

    L4 findings upgrade the tier to "block": a Base64 blob that decodes
    to a hidden instruction / special token / RCE pattern is a
    high-confidence attack, the same as a decoded tag or zero-width
    payload (v1.0.0 only quarantined it).
    """
    result = detector.scan_text(text, suppressed_patterns=suppressed_patterns)
    if not isinstance(text, str):
        text = str(text or "")

    degraded = list(result.get("degraded") or [])
    norm = detector.strip_invisible(text)
    try:
        inv = detector.invis_counts(text)
    except Exception:
        inv = collections.Counter()
        degraded.append("invis_counts")
    try:
        l2 = detector.hidden_instruction_match(norm) is not None
    except Exception:
        l2 = False
        degraded.append("hidden_instruction")
    try:
        l3 = (
            detector.special_token_match(norm) is not None
            or detector.mixed_script_flag(text)
        )
    except Exception:
        l3 = False
        degraded.append("special_token")
    layers = {
        "L1": sum(inv.values()) > 0,
        "L2": l2,
        "L3": l3,
        "L4": False,
    }
    try:
        b64 = detect_obfuscated_base64(text)
    except Exception:
        b64 = []
        degraded.append("base64_scan")
    layers["L4"] = len(b64) > 0

    if b64:
        # Decoded-threat Base64 is a high-confidence attack: BLOCK.
        result["tier"] = "block"
        for f in b64:
            result["score"] += 100
            result["reasons"].append(
                "L4 Base64 smuggling: %s" % f["reason"]
            )
    if degraded and "degraded" in result:
        # Merge root-level degradations, keeping scan_text's list first.
        merged = list(result["degraded"])
        for d in degraded:
            if d not in merged:
                merged.append(d)
        result["degraded"] = merged
        if result["tier"] == "pass":
            result["tier"] = "flag"
            result["score"] += 10
            result["reasons"].append(
                "detector degraded (sub-scan failed): %s" % ", ".join(merged)
            )
    result["layers"] = layers
    result["b64_findings"] = b64
    return result
