<div align="center">

![Hermes Guard banner](docs/assets/hermes-guard-banner.svg)

# Hermes Guard

[Repository](https://github.com/elianjuan-g/hermes-guard) · [Catalog PR #151899](https://github.com/NousResearch/hermes-agent/pull/151899)

[![Docs](https://img.shields.io/badge/docs-README-blue?style=flat)](https://github.com/elianjuan-g/hermes-guard#readme)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat)](LICENSE)
![Version](https://img.shields.io/badge/version-v1.1.2-e8b64c?style=flat)
![Tests](https://img.shields.io/badge/tests-152%2F152-brightgreen?style=flat)
![Hermes](https://img.shields.io/badge/Hermes-%3E%3D0.21.5-orange?style=flat)
![Local](https://img.shields.io/badge/local-100%25-blue?style=flat)

</div>

**Hermes Guard is a fail-closed prompt-injection guard for Hermes Agent: before any inbound message reaches the model, a `pre_llm_call` hook scans it locally across four layers — invisible characters, hidden instructions, special tokens, and Base64 deep-inspection — and a `pre_tool_call` hook guards risky tool calls. Held messages go to a local quarantine log for human review. Nothing leaves the machine, no model call is spent on a blocked turn, and no network call is ever made.**

> **Scope — what this plugin is and is not**
>
> Hermes Guard is a deterministic, pattern-based guardrail. It catches
> known prompt-injection shapes — 24 canonical vectors in the simulation
> arena. It is **not** standalone security, **not** a model, and **not** a
> guarantee: novel obfuscation that matches no pattern will pass. It never
> judges a threat with a model call, and it never sends data anywhere.

## Features

| | |
|---|---|
| **24 canonical vectors** | 21 message vectors (A01–A14 attacks, S01–S07 near-misses) + 3 tool-argument vectors (A15, A16, S08), plus 4 extra tool-arg checks (T01–T04). Arena: **21/21 message + 7/7 tool-arg**. See [Simulation arena](#simulation-arena) and [`tests.md`](tests.md). |
| **Four layers (L1–L4)** | Invisible characters, hidden-instruction phrasing, special tokens, and Base64 deep-inspection. Each layer is a separate sub-scan with its own degraded tracking. See [The four layers](#the-four-layers-l1l4). |
| **Three tiers** | **BLOCK** (high-confidence attack), **QUARANTINE** (suspicious, held for human review), **FLAG** (low suspicion, passes with a warning). A blocked or quarantined turn never reaches the model. |
| **Fail-closed by default** | A detector exception blocks the turn (`fail_closed_on_error: true`) and records the degraded layer. Set it to `false` only if you accept fail-open behaviour. |
| **Posture Score** | One number, 0–100, from live telemetry only: base 100 (35 + 25 + 20 + 10 + 10) minus pending, degraded, and false-positive penalties. Correct blocks **never** reduce the score. A fresh install scores 100. See [Posture Score](#posture-score). |
| **Simulation arena** | The 24 canonical vectors run in memory against the same detection path, without touching live telemetry or the quarantine DB. Results are shown separately from the live posture. |
| **Hash-chained ledger** | Every guard decision is appended to a local SHA-256 chain, so tampering with the audit trail is detectable. The ledger-verified component of the Posture Score is computed live from the stored chain. |
| **Predator Pattern Store** | When a held phrase is released by a human, the pattern is suppressed — the same phrase **alone** no longer quarantines. Suppression is narrow: the phrase combined with any other trigger still quarantines. |
| **Session taint + race guard** | A session that hits FLAG/QUARANTINE is tainted for 60 minutes and gets stricter tool-call scrutiny. The identical tool call repeated inside 10 seconds is blocked as a retry-storm/replay. |
| **Secret redaction** | API keys, tokens, and private-key blocks are masked to `[REDACTED-SECRET]` before anything is persisted (quarantine previews, full text, ledger entries). |
| **Forensic X-Ray HUD** | Live posture, L1–L4 matrix, real-only telemetry, latest intercept, and commands — as a standalone page. See a fresh-install render: [`docs/guard-hud-sample.html`](docs/guard-hud-sample.html). |
| **100% local** | Python standard library + SQLite only. No network calls, no model calls for detection, no credentials read, no telemetry out, no self-updater, no core overrides. |

## Contents

- [Quick Start](#quick-start)
- [How it works](#how-it-works)
- [The four layers (L1–L4)](#the-four-layers-l1l4)
- [The three tiers](#the-three-tiers)
- [Posture Score](#posture-score)
- [Predator Pattern Store](#predator-pattern-store)
- [Simulation arena](#simulation-arena)
- [The guard_review tool](#the-guard_review-tool)
- [CLI](#cli)
- [Configuration](#configuration-pluginyaml-config_schema)
- [Testing](#testing)
- [Disclosure](#disclosure)
- [Known issues](#known-issues)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

```bash
hermes plugins install elianjuan-g/hermes-guard
hermes plugins enable hermes-guard
```

Verify the install (verified live on Hermes 0.21.5 in Phase 3):

```bash
hermes plugins validate ~/.hermes/plugins/hermes-guard   # 13/13 checks
hermes plugins doctor hermes-guard                          # OK
hermes plugins list                                         # hermes-guard, enabled, 1.1.2
```

Then start a Hermes session as usual. The hooks run automatically:
every inbound message is scanned before the model sees it, and every
runtime tool call is scanned before it runs. Check the live state with:

```bash
python -m hermes_guard status       # Forensic X-Ray HUD
```

## How it works

1. **Hooks only, no core overrides.** The plugin registers through the public `register_*` APIs only: `pre_llm_call` and `pre_tool_call`. It does not modify Hermes core. The entry point is `register(ctx)` in `src/hermes_guard/hooks.py`, re-exported by the root `__init__.py` beside `plugin.yaml` (required by the Hermes validator's loadable check).
2. **Local-only scanning.** All detection runs on the machine, in the plugin process. No network calls are made, and no data leaves the machine. Python standard library + SQLite only.
3. **Zero model calls on block.** A blocked or quarantined turn never reaches the model, so an attack cannot consume model time or influence a reply.
4. **Quarantine, not deletion.** Held messages are stored locally in the plugin data directory (`plugin_db`), so they survive updates and remain available for review. Previews shown by the review tool are truncated to 160 characters; the full original is never printed.
5. **Secret redaction.** API keys, tokens, and private-key blocks are masked to `[REDACTED-SECRET]` before anything is persisted (quarantine preview/full text, ledger preview).
6. **Session taint.** A session that hits FLAG/QUARANTINE becomes tainted for 60 minutes; its tool calls get stricter scrutiny.
7. **Call-ID race guard.** The identical tool call (same session, tool, arguments) repeated within 10 seconds is blocked as a retry-storm/replay.
8. **Hash-chained ledger.** Every guard decision is appended to a SHA-256 chain, so tampering with the audit trail is detectable.

## The four layers (L1–L4)

| Layer | Name | What it catches |
|---|---|---|
| L1 | invisible | Zero-width chars, Unicode tags, variation selectors, bidi overrides, BOM, control chars. |
| L2 | instruction | Hidden-instruction / jailbreak phrasing (English + Indonesian). Phrase matching runs on an invisible-stripped copy, so a zero-width split keyword ("ig<ZW>gnore") cannot evade it. |
| L3 | token | Special-token markers `<\|...\|>` and mixed-script homoglyphs. |
| L4 | encoding | Base64 deep-inspection: a candidate token (≥20 chars, token entropy ≥4.0) is decoded (validate=True, ≥75% printable) and the decoded content is scanned for hidden instructions, special tokens, and RCE patterns. A blob that decodes to non-printable binary is data, not an instruction, and is ignored. |

Each layer is a separate sub-scan. A sub-scan that raises is isolated:
the other layers still run, the degraded layer is recorded, and the
turn is handled by the fail-closed setting (see below).

## The three tiers

| Tier | When | What happens |
|---|---|---|
| **BLOCK** | High-confidence attack detected | The turn is vetoed before any model call. No model call is made, so the attack costs nothing and reaches nothing. |
| **QUARANTINE** | Suspicious, but not conclusive | The turn is also vetoed, and the message is held in a local quarantine log for human review via the `guard_review` tool. If you judge it safe, you re-send it manually. |
| **FLAG** | Low suspicion | The message passes through, with a short warning note injected so the model treats the suspicious content as data, not instructions. |

A detector exception fails closed by default (`fail_closed_on_error: true`): the turn is blocked, the degraded layer is recorded, and the error is logged. Set it to `false` in the plugin config to pass with a warning instead. A degraded sub-scan escalates to at least FLAG locally; the hook decides block-vs-flag from this config.

Quarantine release is **manual by design**: a hook can only block/inject/pass — it cannot re-deliver a message on the user's behalf. You review an entry with `guard_review`, then re-send it yourself if you judge it safe.

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

Worked example (verified by tests in `tests/test_benchmark.py`): base 100, 1 held entry, 0 degraded layers, 0 released of 6 interceptions → **95**. More cases: 5 held entries → 75 (pending cap 25); 1 degraded layer → 85; released 1 of 1 → 85 (FP penalty 15); floor 0, never negative.

The simulation arena score is shown separately and never mixed into the live posture.

## Predator Pattern Store

When a hidden-instruction phrase causes a hold, the phrase is recorded in a local pattern store. Releasing the entry (`guard_review release`) suppresses that pattern: the same phrase **alone** no longer quarantines a message — a human corrected it. The suppression is narrow: a suppressed phrase combined with any other trigger (a special token, a decoded payload, an invisible load) still quarantines.

## Simulation arena

`guard_review action=simulate` runs the arena in memory only. Live telemetry and the quarantine DB are never touched. Every vector must match its expected tier.

| Section | Vectors | Result |
|---|---|---|
| Message vectors | 21 (A01–A14 attacks, S01–S07 near-misses) | **21/21 correct** |
| Tool-arg vectors | 7 (A15, A16, S08 + T01–T04) | **7/7 correct** |

Tier breakdown of the 21 message vectors: block 6, quarantine 8, flag 0, pass 7. The full list with reasons is in [`tests.md`](tests.md); the vectors are defined as data in `fixtures/vectors.json`. Numbers are measured, not estimated — see [`docs/BENCHMARK.md`](docs/BENCHMARK.md) for the test suite, arena, and scan-latency measurements.

## The guard_review tool

`guard_review` inspects the quarantine log, runs the simulation arena, and renders the HUD.

| Action | Description |
|---|---|
| `status` | Forensic X-Ray HUD: live posture, L1–L4 matrix, real-only telemetry, latest intercept, commands. |
| `list` | Recent held messages (newest first, 160-char previews). |
| `show` | One held message by id (160-char preview only). |
| `simulate` | Run the simulation arena in memory (21 message vectors + 7 tool-arg vectors). Never touches live telemetry or the quarantine DB. |
| `clean_copy` | Cleaned copy of one entry (invisible chars stripped, obfuscated blobs redacted) for manual re-send. |
| `release` | Owner-only — NOT a model action. Use the `/guard-release <id>` slash command in session. |
| `delete` | Owner-only — NOT a model action. Use the `/guard-delete <id>` slash command in session. |

## CLI

```bash
python -m hermes_guard status       # Forensic X-Ray HUD
python -m hermes_guard scan <file>  # Scan a text file
python -m hermes_guard simulate     # Simulation arena (in-memory)
python -m hermes_guard hud          # Write guard-hud.html (standalone dashboard)
```

Preview the dashboard: [`docs/guard-hud-sample.html`](docs/guard-hud-sample.html) — a fresh-install render (empty state, Posture 100/100, arena 21/21 + 7/7 from an in-memory run).

## Configuration (`plugin.yaml` config_schema)

| Key | Default | Meaning |
|---|---|---|
| `fail_closed_on_error` | `true` | Block the turn when the detector raises. |
| `quarantine_mode` | `block_and_manual_resend` | Held messages are blocked; user re-sends manually. (`cleaned_resend` returns a cleaned copy via `clean_copy`.) |
| `callid_race_window_s` | `10` | Seconds for the call-ID race window. |
| `taint_ttl_minutes` | `60` | Minutes a session stays tainted. |
| `redact_secrets` | `true` | Mask secrets as `[REDACTED-SECRET]` before persistence. |

## Testing

```bash
pip install pytest
python -m pytest tests/ -q
```

**168 tests, all passing** (see [`docs/BENCHMARK.md`](docs/BENCHMARK.md)). The 24 canonical simulation vectors (21 message + 3 tool-arg) are listed in [`tests.md`](tests.md) and defined as data in `fixtures/vectors.json` (loaded by `src/hermes_guard/vectors.py`); the v1.0.0 extra vectors run as pytest cases in `tests/test_extended_vectors.py`.

## Disclosure

- **No network calls.** The plugin makes no outbound requests of any kind.
- **No credentials.** It does not need, read, or store any credential, token, or secret.
- **No data leaves the machine.** Scanning is local; quarantine records are stored in the local plugin data directory.
- **No core overrides.** Only the public `register_*` APIs are used.
- **No self-updater.** The plugin never updates itself or downloads anything.
- **Quarantine "release" is manual.** A held message is released only by re-sending it yourself after reviewing it with `guard_review`. There is no automatic release.

## Known issues

- Quarantine release is manual re-send (see Disclosure). There is no one-click release. `release`/`delete` are owner-only slash commands (`/guard-release <id>`, `/guard-delete <id>`); the model tool cannot call them.
- Subshell patterns (`$(...)`, backticks) are checked only for command-running tools (`terminal`, `execute_code`, `shell`) and are bounded to 512 chars: a subshell longer than 512 chars is not matched, and backticks / `$(...)` in `write_file` / `read` / `note` content (Markdown, shell scripts) are not blocked. `rm -rf`, pipe-to-shell and `/dev/tcp` still block for every tool.
- Talking *about* jailbreak phrases — for example, quoting one to discuss it — can be flagged, because the scanner sees the pattern, not the intent.
- Detection is pattern-based and deterministic; novel obfuscation that matches no pattern will pass. The arena measures coverage against known vectors only.
- Very short Base64 tokens (<20 chars, or token entropy <4.0) are skipped by design to avoid false positives on ordinary words — a short token carrying a threat would need a longer carrier to be caught by L4.
- Live Hermes hook wiring is verified on Hermes 0.21.5 (Phase 3: `validate` 13/13, `doctor`, `plugins list`, live hook-fire test; v1.1.2 re-verified the same way). `register()` uses ONE `register_tool(name, toolset, schema, handler)` call — the single form that matches the 0.21.5 signature and current Hermes alike; the old `parameters=` keyword call matched no signature.

## Requirements

- Hermes Agent `>= 0.21.5` (the `pre_llm_call` and `pre_tool_call` hooks are available in 0.21.5 — verified live in Phase 3 and re-verified in v1.1.2; `register_tool` is called once with `(name, toolset, schema, handler)`, the form that matches 0.21.5 and current Hermes).
- Python `>= 3.11`. Standard library + SQLite only; no runtime dependencies.

## v1.1.2 changes (teknium1 review — 5 fixes)

Maintainer review on PR #151899 (`ccb0f52`, CHANGES_REQUESTED) found five things that were broken in real Hermes even though the unit tests were green. All five fixed here, corpus byte-identical:

1. **`pre_llm_call` now scans real turns.** The hook took `messages=None`, but Hermes 0.21.5 calls it with `user_message` + `conversation_history` — so `messages` was always `None` and the hook returned early on every real turn. New signature `pre_llm_call_hook(user_message=None, conversation_history=None, session_id="default", **kwargs)`, scanning `user_message` as a string or a content-parts list. New tests call the hook with exactly the core kwargs (`session_id, task_id, turn_id, user_message, conversation_history, is_first_turn, model, platform, parent_session_id, sender_id` — verified against live `agent/turn_context.py:_collect_pre_llm_call_context`).
2. **`tools.py` moved into the package.** The handler is now `tool_guard_review(args, **kwargs)` reading `args.get("action")` / `"id"` / `"limit"` (core calls handlers as `handler(args_dict, **kwargs)`), and `tools.py` lives at `src/hermes_guard/tools.py` behind a relative import — `import tools` inside Hermes used to bind Hermes's own `tools` package and raise on every call.
3. **One `register_tool` call.** The old `parameters=` keyword call matched no `register_tool` signature, and the fallback passed a bare JSON Schema, so the model saw `guard_review` with no parameters. Now a single `ctx.register_tool(name="guard_review", toolset="hermes_guard", schema={"name": ..., "description": ..., "parameters": GUARD_REVIEW_SCHEMA}, handler=tool_guard_review)` — the one form matching the 0.21.5 signature (`hermes_cli/plugins.py:456`) and current Hermes alike.
4. **Release/delete are owner-only slash commands.** `release` and `delete` left the model tool (`/guard-release <id>`, `/guard-delete <id>` via `ctx.register_command`, verified live on 0.21.5) — injected text in a tool result can no longer steer the model into weakening the guard. The reviewer's other option — `pre_tool_call` returning `{"action": "approve"}` — does exist on 0.21.5 (`plugins.py` `_dispatch_pre_tool_call_hooks` → `request_tool_approval`, fail-closed on gate error/deny); it was not chosen because it still leaves release/delete model-callable behind a per-attempt approval prompt, while `register_command` removes the capability from the model entirely. The model tool refuses `release`/`delete` with an owner-only error.
5. **Subshell patterns bounded + scoped.** `\$\([^)]+\)` / `` `[^`]+` `` were quadratic on unclosed runs (2 s on a 120 KB `write_file` body) — now `\$\([^)]{1,512}\)` / `` `[^`\n]{1,512}` ``, and the check applies only to command-running tools (`terminal`, `execute_code`, `shell`). Markdown and shell-script writes containing backticks or `$(...)` are no longer blocked; `rm -rf`, pipe-to-shell and `/dev/tcp` still block for every tool. The 120 KB unclosed-`$(` case now scans in well under 1 s (measured in tests).

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: read the README first (especially the four layers and the "Scope" section), make small focused changes, include tests when you change detection behaviour, and never write a security claim without pointing at the code + the test that proves it.

## License

MIT — see [LICENSE](LICENSE).

---

*Hermes Guard is an independent community plugin. It is not affiliated with, endorsed by, or connected to Nous Research or the Hermes Agent project. "Hermes Agent" is a project by Nous Research; this plugin only integrates with it through its public plugin API.*
