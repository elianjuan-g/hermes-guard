# Hermes Guard

> A defensive security plugin for Hermes Agent — it scans every inbound message before the model sees it, and blocks hidden prompt-injection attempts at the gate.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hermes](https://img.shields.io/badge/Hermes-%3E%3D0.21.5-blue)](https://github.com/NousResearch/hermes-agent)

Repository: https://github.com/elianjuan-g/hermes-guard

Version: **1.1.1**

## What it does

Hermes Guard sits between the user and the model. Before any inbound message reaches the language model, a `pre_llm_call` hook scans it locally for smuggled instructions:

- **Unicode smuggling** — zero-width characters, homoglyphs, and bidirectional override controls used to hide text from humans while the model can still read it.
- **Hidden instructions** — directives embedded in a message that try to make the model act against the user's intent.
- **Common jailbreak patterns** — known phrasings used to override system instructions.
- **Obfuscated Base64** — a Base64 blob that decodes to a hidden instruction, a special token, or an RCE pattern. Base64 that decodes to ordinary text (English, Indonesian, JSON config) is explicitly NOT flagged.

A second hook, `pre_tool_call`, guards risky tool calls. It blocks on: a call-ID race (the identical call repeated inside the race window), RCE/subshell patterns (including a bare `rm -rf`), sensitive credential paths (`~/.ssh/id_*`, `.env`, `/etc/shadow`, `credentials.json`), decoded hidden Unicode payloads in arguments, and — only in a tainted session — hidden-instruction phrasing. Ordinary tool calls pass through untouched.

Nothing about this plugin requires the model to judge the threat. Detection is deterministic, local, and runs before any model call happens.

## The four layers (L1–L4)

| Layer | Name | What it catches |
|---|---|---|
| L1 | invisible | Zero-width chars, Unicode tags, variation selectors, bidi overrides, BOM, control chars. |
| L2 | instruction | Hidden-instruction / jailbreak phrasing (English + Indonesian). Phrase matching runs on an invisible-stripped copy, so a zero-width split keyword ("ig<ZW>gnore") cannot evade it. |
| L3 | token | Special-token markers `<\|...\|>` and mixed-script homoglyphs. |
| L4 | encoding | Base64 deep-inspection: a candidate token (≥20 chars, token entropy ≥4.0) is decoded (validate=True, ≥75% printable) and the decoded content is scanned for hidden instructions, special tokens, and RCE patterns. A blob that decodes to non-printable binary is data, not an instruction, and is ignored. |

## The three tiers

| Tier | When | What happens |
|---|---|---|
| **BLOCK** | High-confidence attack detected | The turn is vetoed before any model call. No model call is made, so the attack costs nothing and reaches nothing. |
| **QUARANTINE** | Suspicious, but not conclusive | The turn is also vetoed, and the message is held in a local quarantine log for human review via the `guard_review` tool. If you judge it safe, you re-send it manually. |
| **FLAG** | Low suspicion | The message passes through, with a short warning note injected so the model treats the suspicious content as data, not instructions. |

A detector exception fails closed by default (`fail_closed_on_error: true`): the turn is blocked, the degraded layer is recorded, and the error is logged. Set it to `false` in the plugin config to pass with a warning instead. A degraded sub-scan escalates to at least FLAG locally; the hook decides block-vs-flag from this config.

## Posture Score

The HUD shows a live Posture Score (0–100) computed from real telemetry only:

```
score = base − pending − degraded − false_positive
base  = 35 (pre_llm_call) + 25 (pre_tool_call) + 20 (fail-closed)
        + 10 (redaction) + 10 (ledger verified)
pending       = min(held entries × 5, 25)
degraded      = degraded layers × 15
false_positive = round(min(15, (released / total interceptions) × 30))
```

The ledger-verified component is always computed live from the stored hash chain (an empty ledger counts as verified). Correct blocks, quarantines, and flags **never** reduce the score — a guard that blocks many real attacks still scores 100. A fresh install scores 100.

The simulation arena score is shown separately and never mixed into the live posture.

## Predator Pattern Store

When a hidden-instruction phrase causes a hold, the phrase is recorded in a local pattern store. Releasing the entry (`guard_review release`) suppresses that pattern: the same phrase **alone** no longer quarantines a message — a human corrected it. The suppression is narrow: a suppressed phrase combined with any other trigger (a special token, a decoded payload, an invisible load) still quarantines.

## How it works

1. **Hooks only, no core overrides.** The plugin registers through the public `register_*` APIs only: `pre_llm_call` and `pre_tool_call`. It does not modify Hermes core. The entry point is `register(ctx)` in `src/hermes_guard/hooks.py`, re-exported by the root `__init__.py` beside `plugin.yaml` (required by the Hermes validator's loadable check).
2. **Local-only scanning.** All detection runs on the machine, in the plugin process. No network calls are made, and no data leaves the machine. Python standard library + SQLite only.
3. **Zero model calls on block.** A blocked or quarantined turn never reaches the model, so an attack cannot consume model time or influence a reply.
4. **Quarantine, not deletion.** Held messages are stored locally in the plugin data directory (`plugin_db`), so they survive updates and remain available for review. Previews shown by the review tool are truncated to 160 characters; the full original is never printed.
5. **Secret redaction.** API keys, tokens, and private-key blocks are masked to `[REDACTED-SECRET]` before anything is persisted (quarantine preview/full text, ledger preview).
6. **Session taint.** A session that hits FLAG/QUARANTINE becomes tainted for 60 minutes; its tool calls get stricter scrutiny.
7. **Call-ID race guard.** The identical tool call (same session, tool, arguments) repeated within 10 seconds is blocked as a retry-storm/replay.
8. **Hash-chained ledger.** Every guard decision is appended to a SHA-256 chain, so tampering with the audit trail is detectable.

## The guard_review tool

`guard_review` inspects the quarantine log, runs the simulation arena, and renders the HUD.

| Action | Description |
|---|---|
| `status` | Forensic X-Ray HUD: live posture, L1–L4 matrix, real-only telemetry, latest intercept, commands. |
| `list` | Recent held messages (newest first, 160-char previews). |
| `show` | One held message by id (160-char preview only). |
| `simulate` | Run the simulation arena in memory (21 message vectors + 7 tool-arg vectors). Never touches live telemetry or the quarantine DB. |
| `clean_copy` | Cleaned copy of one entry (invisible chars stripped, obfuscated blobs redacted) for manual re-send. |
| `release` | Mark one entry released and return the original text for manual re-send. Counts as a false positive; also suppresses the entry's pattern. |
| `delete` | Permanently delete one quarantine entry. |

Quarantine release is **manual by design**: a hook can only block/inject/pass — it cannot re-deliver a message on the user's behalf. You review an entry with `guard_review`, then re-send it yourself if you judge it safe.

## CLI

```bash
python -m hermes_guard status       # Forensic X-Ray HUD
python -m hermes_guard scan <file>  # Scan a text file
python -m hermes_guard simulate     # Simulation arena (in-memory)
python -m hermes_guard hud          # Write guard-hud.html (standalone dashboard)
```

Preview the dashboard: [`docs/guard-hud-sample.html`](docs/guard-hud-sample.html) — a fresh-install render (empty state, Posture 100/100, arena 21/21 + 7/7 from an in-memory run).

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

152 tests, all passing (see `docs/BENCHMARK.md`). The 24 canonical simulation vectors (21 message + 3 tool-arg) are listed in `tests.md` and defined as data in `fixtures/vectors.json` (loaded by `src/hermes_guard/vectors.py`); the v1.0.0 extra vectors run as pytest cases in `tests/test_extended_vectors.py`.

## v1.1.1 changes (Phase 3 — PC verification)

Phase 3 on the real Hermes 0.21.5 found four things v1.1.0 got wrong; all fixed here, corpus byte-identical (verified by diff):

- `requires_hermes` lowered `>=0.23.0` → `>=0.21.5`: the hook APIs (`register_hook`, `pre_llm_call`, `pre_tool_call`) exist in 0.21.5; the floor was an untested assumption. Verified live by `hermes plugins validate` + `doctor` + `list` on 0.21.5.
- `register()` now tries the `>= 0.23` keyword-style `register_tool(parameters=...)` first and falls back to the 0.21.5 positional style `(name, toolset, schema, handler)` on `TypeError`. The new-style path is per the documented API, not live-verified (no 0.23 install available).
- `config_schema` rewritten to the flat `#64165` format (`key -> {type, default, description}`): the JSON-Schema style was silently skipped by the loader and failed validation.
- Top-level `provides_tools` / `provides_hooks` added: the loader and validator read only top-level keys; the `capabilities:` nesting was invisible to both.
- Arena corpus moved from Python literals (`vectors.py`) to `fixtures/vectors.json` (data, not code): the plugin's own detection corpus tripped the install-time security scanner as `dangerous` (5 criticals). In `fixtures/` the corpus is inert test data by the scanner's own rule — strings unchanged, nothing obfuscated.

## v1.1.0 changes (Argon Round 3)

- Hook entry point (`register()` + `hooks.py`) — the v1.0.0 manifest declared the hooks but the code did not exist yet. Now real.
- Base64 safe-scan rewrite (decode + scan content, not decoded entropy) — fixes two measured false positives (Base64 config JSON, the word "internationalization") and one miss (zero-width split keyword).
- `pre_tool_call` now guards RCE/subshell patterns, sensitive credential paths, and tainted-session instruction injection — not only decoded payloads.
- Per-sub-scan error isolation + degraded tracking; new Posture formula; Predator Pattern Store; secret redaction; standalone `guard-hud.html`; CI workflow; `skills/guard/SKILL.md`.
- Behaviour change: a Base64 blob decoding to non-printable binary is now ignored (data, not instruction).
- Note: the Argon Round 3 sprint table claimed `plugin.yaml`, `tools.py`, and `tests` did not exist yet — they did (v1.0.0). Only the hooks, pattern store, redaction, CI, and skill were new in v1.1.0.

## Install

```bash
hermes plugins install elianjuan-g/hermes-guard
hermes plugins enable hermes-guard
```

## Configuration (`plugin.yaml` config_schema)

| Key | Default | Meaning |
|---|---|---|
| `fail_closed_on_error` | `true` | Block the turn when the detector raises. |
| `quarantine_mode` | `block_and_manual_resend` | Held messages are blocked; user re-sends manually. (`cleaned_resend` returns a cleaned copy via `clean_copy`.) |
| `callid_race_window_s` | `10` | Seconds for the call-ID race window. |
| `taint_ttl_minutes` | `60` | Minutes a session stays tainted. |
| `redact_secrets` | `true` | Mask secrets as `[REDACTED-SECRET]` before persistence. |

## Requirements

- Hermes Agent `>= 0.21.5` (the `pre_llm_call` and `pre_tool_call` hooks are available in 0.21.5 — verified live in Phase 3; the `register_tool` keyword style needs >= 0.23, with a positional fallback for 0.21.5).
- Python `>= 3.11`. Standard library + SQLite only; no runtime dependencies.

## Disclosure

- **No network calls.** The plugin makes no outbound requests of any kind.
- **No credentials.** It does not need, read, or store any credential, token, or secret.
- **No data leaves the machine.** Scanning is local; quarantine records are stored in the local plugin data directory.
- **No core overrides.** Only the public `register_*` APIs are used.
- **No self-updater.** The plugin never updates itself or downloads anything.
- **Quarantine "release" is manual.** A held message is released only by re-sending it yourself after reviewing it with `guard_review`. There is no automatic release.

## Known issues

- Quarantine release is manual re-send (see Disclosure). There is no one-click release.
- Talking *about* jailbreak phrases — for example, quoting one to discuss it — can be flagged, because the scanner sees the pattern, not the intent.
- Detection is pattern-based and deterministic; novel obfuscation that matches no pattern will pass. The arena measures coverage against known vectors only.
- Very short Base64 tokens (<20 chars, or token entropy <4.0) are skipped by design to avoid false positives on ordinary words — a short token carrying a threat would need a longer carrier to be caught by L4.
- Live Hermes hook wiring is verified on Hermes 0.21.5 (Phase 3: `validate` 13/13, `doctor`, `plugins list`, live hook-fire test). The `register_tool` keyword style (>= 0.23) is per the documented API, not live-verified — no 0.23 install was available.

## License

MIT. See `LICENSE`.
