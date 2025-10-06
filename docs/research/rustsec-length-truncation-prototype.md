# RustSec length truncation prototype (Oct 2025)

## Background

RustSec advisories [RUSTSEC-2024-0363](https://rustsec.org/advisories/RUSTSEC-2024-0363.html) and [RUSTSEC-2024-0365](https://rustsec.org/advisories/RUSTSEC-2024-0365.html) describe issues where large payload lengths are truncated to 32-bit values before being serialized onto the PostgreSQL wire protocol. Backlog entry 105 targets this pattern so Rust-cola can alert when downcasts introduce command smuggling opportunities.

## Prototype goals

- Identify MIR assignments where size-like values flow into narrow integer casts (`as i32`, `as u32`, etc.).
- Reuse the shared `MirDataflow` helper to propagate taint from `len`/`length`/`payload_*` values across temporaries.
- Validate the approach with isolated unit tests before wiring a full rule.

## Implementation snapshot

- Added `detect_truncating_len_casts` in `mir-extractor/src/prototypes.rs`.
- Seeds taint from `debug` statements with names containing `len`, `length`, `size`, or `payload`, and from assignments that call `.len()`/`length` helpers.
- Propagates taint through MIR assignments via the existing dataflow helper.
- Flags casts whose RHS contains both `IntToInt` and a narrow target (`as i32`, `as u16`, etc.) when fed by tainted sources.
- Covered by new unit tests under `prototypes::tests`.

## Current coverage

- Detects direct `as i32`/`as u32` conversions of tainted length values, even when they flow through intermediate temporaries.
- Ignores widening casts (e.g., `as i64`), reducing false positives for safe promotions.
- Runs as part of `cargo test -p mir-extractor`, keeping feedback tight.

## Limitations & open questions

- Only matches explicit `as` casts; conversions using `try_into`, `clamp`, or manual byte-splitting are currently invisible.
- Keyword-based seeding may miss bespoke field names (e.g., `frame_bytes`). We may need configuration or richer semantic cues.
- The prototype does not yet reason about protocol writers—future work should correlate the cast with serialization sinks.

## Next steps

1. Expand detection to cover `.try_into()` + `.unwrap()` style narrowing conversions.
2. Track whether the narrowed value reaches network write helpers (`BufMut::put_u32`, etc.).
3. Integrate into a real rule with SARIF metadata and tunable severity once signal quality is confirmed.

## Artifacts

- `mir-extractor/src/prototypes.rs` — `detect_truncating_len_casts` implementation and helpers.
- Unit tests in `mir-extractor/src/prototypes.rs` (`detects_truncating_len_cast`, `ignores_wide_len_cast`).
- Verified with `cargo test -p mir-extractor`.
