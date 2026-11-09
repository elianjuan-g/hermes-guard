# Hermes Guard — simulation arena (Argon Round 3 canon)

`guard_review action=simulate` runs the arena in memory only. Live
telemetry and the quarantine DB are never touched. Every vector must
match its expected tier (see `tests/test_benchmark.py`).

The canon is Argon Round 3's **24**: 21 message vectors (A01–A14
attacks, S01–S07 near-misses) run through `scan_roots()`, plus 3
tool-argument vectors (A15, A16, S08) run through
`scan_tool_arguments()`. Four extra tool-arg checks (T01–T04, Ciel
hardening) run in the same section, so the arena reports **21/21
message + 7/7 tool-arg**.

## Section 1 — message vectors (21)

| ID | Name | Expected | Why |
|---|---|---|---|
| A01 | `unicode_tag_smuggling` | block | Unicode tag channel decodes to a hidden instruction. |
| A02 | `zerowidth_binary_channel` | block | Zero-width binary channel decodes to hidden text. |
| A03 | `massive_variation_selector` | block | Massive variation-selector load (1050 chars). |
| A04 | `massive_zerowidth_flood` | block | Massive zero-width load (1024 chars). |
| A05 | `context_bomb_single_line` | block | Context-bomb shape: 160000 bytes in 1 line. |
| A06 | `base64_smuggled_override` | block | Base64 decodes to a hidden instruction. |
| A07 | `zw_split_keyword_bypass` | quarantine | Hidden-instruction phrasing after invisible-strip normalisation. |
| A08 | `english_direct_override` | quarantine | Hidden-instruction phrasing (English). |
| A09 | `indonesian_direct_override` | quarantine | Hidden-instruction phrasing (Indonesian). |
| A10 | `system_prompt_extraction` | quarantine | Hidden-instruction phrasing (prompt leaking). |
| A11 | `special_token_chatml_injection` | quarantine | Special-token marker found. |
| A12 | `cyrillic_homoglyph_spoof` | quarantine | One word mixes Latin + Cyrillic (homoglyph). |
| A13 | `bidi_rtl_override_trap` | quarantine | Bidi control override / moderate invisible chars. |
| A14 | `persona_hijack_dan_style` | quarantine | Hidden-instruction phrasing (role hijack). |
| S01 | `normal_daily_summary` | pass | Ordinary daily sentence. |
| S02 | `benign_word_ignore_usage` | pass | "ignore" + "instructions" in a legitimate work context. |
| S03 | `benign_indonesian_command` | pass | "instruksi" + "sistem" in an ordinary technical question. |
| S04 | `benign_cyrillic_separate_words` | pass | Real Cyrillic words, separate from English words. |
| S05 | `benign_base64_config_blob` | pass | Base64 decodes to ordinary JSON config — must NOT flag. |
| S06 | `benign_code_discussion` | pass | Ordinary HTML tags and comparisons, no special tokens. |
| S07 | `benign_prompt_engineering_chat` | pass | "system" and "prompt" used separately, business context. |

Tier counts (message section): block 6, quarantine 8, pass 7.

## Section 2 — tool-argument vectors (7)

| ID | Name | Expected | Why |
|---|---|---|---|
| A15 | `tool_arg_rce_subshell` | block | Dangerous command substitution / RCE pattern. |
| A16 | `tool_arg_sensitive_path` | block | Sensitive credential path access. |
| S08 | `benign_tool_call_argument` | pass | Ordinary tool call reading a project file. |
| T01 | `tool_arg_bare_rm_rf` | block | Bare `rm -rf` is an execution, not a discussion (Ciel hardening beyond Argon's spec). |
| T02 | `tool_arg_tainted_instruction` | block | Tainted session attempting instruction injection. |
| T03 | `tool_arg_untainted_instruction_note` | pass | Same note in an untainted session: the instruction check only applies to tainted sessions. |
| T04 | `tool_arg_clean_ls` | pass | Ordinary read-only tool call. |

## Extended vectors (v1.0.0 extras, pytest only)

These lived in the v1.0.0 arena; the canon is now Argon's 24, so they
run as plain pytest cases in `tests/test_extended_vectors.py`:

| Name | Expected | Why |
|---|---|---|
| `huge-size` | block | 200000 bytes in 1 line. |
| `small-invisible` | flag | Small invisible-character count (1). |
| `large-size-many-lines` | flag | Size > 150000 bytes but spread over many lines. |
| `bom-char` | flag | Single BOM character. |
| `clean-emoji` | pass | Ordinary message with emoji. |
| `code-with-base64` | pass | Code containing Base64 that decodes to English. |
| `url-with-base64-param` | pass | URL with a Base64 parameter decoding to a URL. |
| `jailbreak-you-are-now` | quarantine | Jailbreak phrasing "you are now". |
| `jailbreak-reveal-prompt` | quarantine | Jailbreak phrasing "reveal your system prompt". |
| `obfuscated-base64-random-bytes` | **pass** | **Behaviour change (v1.1.0):** random bytes decode to non-printable binary — data, not an instruction. Opaque-blob flagging removed. |
| `base64-english-fp-check` | pass | Base64 decodes to plain English — must NOT be flagged (FP guard). |
| `variation-selector U+FE00 1200x` | block | Variation-selector load >= 1000 chars. |

The vectors live as data in `fixtures/vectors.json` (loaded by
`src/hermes_guard/vectors.py`; programmatic payloads A01–A05 carry a
small "build" spec). These are detection fixtures: they describe
attacks so the guard can recognise them. They are never
instructions to follow.
