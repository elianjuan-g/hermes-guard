# Benchmark — Hermes Guard v1.1.2

Measured on this VM (Python 3.12.3, 2026-11-09). All numbers are real
measurements, not estimates. Reproduce with:

```bash
python -m pytest tests/ -q
python -m hermes_guard simulate
```

## Test suite

| Metric | Value |
|---|---|
| Test files | 10 (`test_roots`, `test_xray`, `test_ledger`, `test_taint`, `test_benchmark`, `test_detector_tools`, `test_hooks`, `test_extended_vectors`, `test_storage_v11`, `test_hud_html`) |
| Tests | 152 |
| Passed | 152 |
| Failed | 0 |
| Suite time | ~3.8 s |

## Simulation arena (Argon Round 3 canon)

| Metric | Value |
|---|---|
| Message vectors | 21/21 correct (A01–A14 attacks, S01–S07 near-misses) |
| Tool-arg vectors | 7/7 correct (A15, A16, S08 + T01–T04) |
| Arena time (one run) | ~0.18 s |
| Live telemetry touched | none (verified by test) |

Tier breakdown of the 21 message vectors: block 6, quarantine 8,
flag 0, pass 7. The full list is in `tests.md`; the vectors are
defined as data in `fixtures/vectors.json`.

## Scan latency

| Input | Time per scan |
|---|---|
| Typical clean message (~60 chars) | ~0.07 ms |
| Median arena vector | ~0.12 ms |
| Slowest arena vector (A05, 160 KB context bomb) | ~184 ms |

Latency is measured in-process (regex + counting only, no model calls,
no network). The A05 cost is the 160 KB payload itself (UTF-8 encode +
regex over the full text); ordinary messages stay well under 1 ms.

## Posture Score

Formula (live telemetry only, Argon Round 3):

```
score = base − pending − degraded − false_positive
base  = 35 (pre_llm_call) + 25 (pre_tool_call) + 20 (fail-closed)
        + 10 (redaction) + 10 (ledger verified)
pending       = min(held entries × 5, 25)
degraded      = degraded layers × 15
false_positive = round(min(15, (released / total interceptions) × 30))
```

Verified by tests in `tests/test_benchmark.py`:

- Fresh install: 100.
- 50 blocks + 50 quarantines + 50 flags + 50 passes: still 100 (correct
  blocks never reduce the score).
- 1 held entry: 95. 5 held entries: 75 (pending cap 25).
- 1 degraded layer: 85. 2 degraded layers: 70.
- Released 1 of 6 interceptions: 95 (FP penalty 5). Released 1 of 1: 85
  (FP penalty 15).
- Argon's worked example (base 100, held 1, degraded 0, released 0/6):
  95.
- Floor: 0, never negative.

## What is NOT benchmarked

- No comparison against other plugins (llm-antidote, blackbox, etc.).
  Any such comparison would need the same vectors run against each
  plugin under identical conditions.
- No WASM/Rust component exists in v1.1.2 (Python-only by design; WASM
  stays P2), so no cross-language speed claim is made.
- No production traffic data. The arena measures known vectors only;
  novel obfuscation that matches no pattern will pass.
