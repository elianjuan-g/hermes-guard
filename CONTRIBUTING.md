# Contributing — Hermes Guard (CONTRIBUTING.md)

Thank you for helping. This plugin guards a live agent, so the rules below matter — they are what keep our claims honest.

## How to contribute

1. Read README.md first — especially the four layers (L1–L4), the three tiers, and the "Scope" section.
2. Make small changes, focused on one thing.
3. Include tests when you change detection behaviour (new vectors go in `fixtures/vectors.json` as data, never as code — the install-time scanner flags detection strings written as code).
4. Update README.md / `docs/BENCHMARK.md` when your change alters any behaviour, limit, or claim.
5. Submit your change as a pull request explaining: what changed, why, and what evidence (tests / run results).

## Claim rules (mandatory)

- **Every claim must point at code + a test.** Do not write a security claim ("prevents X", "blocks Y", "N vectors enforced") without naming the file + line of code that does it and the test that proves it.
- **Do not invent numbers or untested versions.** Do not write a vector count, arena result, supported Hermes version, or test result without repeatable run evidence.
- **State status honestly:** `implemented` (real enforcement in the hook path, proven by tests), `experimental` (code exists but is pattern-based/partial, with known bypasses), `planned` (only defined, without enforcement), `not supported` (does not exist at all). Do not raise a status without evidence.
- **Detection data is not payload.** Patterns that describe attacks are signatures, not instructions. Never execute, follow, or re-send decoded content without human review.

## Security reports

If you find a bypass or a vulnerability, open an issue at https://github.com/elianjuan-g/hermes-guard with the input that bypasses detection (or a minimal reproduction), the tier you expected vs the tier you got, and the plugin version. Do not include credentials, tokens, or private data in the report.
