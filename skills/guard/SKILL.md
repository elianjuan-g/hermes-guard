# Hermes Guard — Skill

Defensive prompt-injection guard for Hermes Agent. Local, deterministic,
fail-closed. No network, no model calls, no external dependencies
(Python stdlib + SQLite only).

## What it does

Every inbound message is scanned by `pre_llm_call` before the model
sees it; every runtime tool call is scanned by `pre_tool_call`. A hook
can only block / inject context / pass — there is no hold-and-deliver,
so BLOCK and QUARANTINE both veto the turn and differ in the record
(tier + reasons) and in the block message. A held message is released
MANUALLY: the user reviews it with `guard_review` and re-sends it
themselves if judged safe.

## The 7 guard_review actions

- `status` — Forensic X-Ray HUD: live posture, L1–L4 matrix, real-only
  telemetry, latest intercept, commands.
- `list` — recent quarantine entries (newest first, 160-char previews).
- `show id=<id>` — one entry by id (preview only).
- `simulate` — the simulation arena, in memory: 21 message vectors
  (A01–A14 attacks, S01–S07 near-misses) + 7 tool-arg vectors
  (A15, A16, S08 + T01–T04). Never touches live telemetry or the
  quarantine DB.
- `clean_copy id=<id>` — cleaned text for manual re-send (invisible
  chars stripped, obfuscated blobs redacted).
- `release id=<id>` — mark reviewed, return the original text for
  manual re-send. Counts as a false positive. Also suppresses the
  entry's hidden-instruction pattern, so the same phrase alone stops
  quarantining (the Predator Pattern Store).
- `delete id=<id>` — permanently remove one entry.

## Hooks

- `pre_llm_call` — scans the last user message (L1 invisible, L2
  instruction, L3 token, L4 Base64 deep-inspection). Block/quarantine
  → record + ledger + stats + session taint. Flag → taint + warning
  context injected. Pass → counted.
- `pre_tool_call` — blocks on call-ID race (identical call inside the
  race window), RCE/subshell patterns (including bare `rm -rf`),
  sensitive credential paths, decoded hidden Unicode payloads, and —
  only in a tainted session — hidden-instruction phrasing in args.

## Fail-closed

Any detector exception, or a degraded sub-scan, blocks the turn when
`fail_closed_on_error` is true (default) and records the degraded
layer. Set it to false only if you accept fail-open behaviour.

## Posture Score (live, real traffic only)

`base 100 − pending − degraded − false_positive`, where base = 35
(pre_llm_call) + 25 (pre_tool_call) + 20 (fail-closed) + 10 (redaction)
+ 10 (ledger verified); pending = min(held×5, 25); degraded =
degraded layers×15; false_positive = round(min(15,
(released/total)×30)). Correct blocks never reduce the score.
Simulation is never mixed into it.

## Run it

```bash
python -m pytest -q                 # full suite (151 tests)
python -m hermes_guard status       # live HUD
python -m hermes_guard simulate     # arena (in-memory)
python -m hermes_guard scan <file>  # scan one text file
python -m hermes_guard hud          # write guard-hud.html
```

Secrets (API keys, tokens, private-key blocks) are redacted to
`[REDACTED-SECRET]` before anything is persisted.
