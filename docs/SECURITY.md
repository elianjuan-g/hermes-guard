# Security policy — Hermes Guard

## What this plugin is

Hermes Guard is a defensive prompt-injection guard for Hermes Agent. It
scans inbound messages locally (deterministic patterns, no model calls)
and blocks or quarantines hidden prompt-injection attempts before the
model sees them. It is a guardrail/telemetry plugin, not a standalone
security defence. Use it in test environments and opt in knowingly.

## What it does NOT do

- It does not make outbound network calls.
- It does not read, store, or need any credential, token, or secret.
- It does not modify Hermes core (public `register_*` APIs only).
- It does not update itself or download anything.
- It does not automatically release quarantined messages. Release is a
  manual user decision (review with `guard_review`, then re-send
  yourself).

## Detection data

The detector contains patterns that *describe* attacks so they can be
recognised (hidden-instruction phrases, invisible-character classes,
Base64 shapes). Those patterns are detection signatures, not payloads
and not instructions. Decoded hidden content is truncated to 160
characters everywhere it is shown. Never execute, follow, or re-send
decoded content without human review.

## Reporting a vulnerability

If you find a bypass or a vulnerability in Hermes Guard, please open an
issue at https://github.com/elianjuan-g/hermes-guard with:

- the input that bypasses detection (or a minimal reproduction),
- the tier you expected vs the tier you got,
- the plugin version (`plugin.yaml`).

Do not include credentials, tokens, or private data in the report.

## Known limitations

- Talking *about* jailbreak phrases — for example, quoting one to
  discuss it — can be flagged, because the scanner sees the pattern,
  not the intent.
- Detection is pattern-based and deterministic; novel obfuscation that
  matches no pattern will pass. The 24-vector arena (`guard_review
  action=simulate`) measures coverage against known vectors only.
- A detector exception fails closed (blocks the turn) by default
  (`fail_closed_on_error: true`). If that is too strict for your
  environment, set it to `false` in the plugin config — the turn will
  then pass with a warning injected instead.
