# RustSec Content-Length DoS prototype (Oct 2025)

## Background

RustSec advisory [RUSTSEC-2025-0015](https://rustsec.org/advisories/RUSTSEC-2025-0015.html) describes a denial-of-service condition in the `web-push` crate where untrusted `Content-Length` headers are used to preallocate buffers. Backlog entry 107 proposes a future Rust-cola rule that would flag similar patterns.

## Prototype goals

- Verify that MIR text provides enough signal to taint-track values sourced from HTTP `Content-Length` headers.
- Demonstrate that taint can be propagated across temporary variables and conversions before reaching allocation sinks such as `Vec::with_capacity`.
- Exercise the plumbing in unit tests so we can iterate quickly without compiling full crates.

## Implementation snapshot

- Added a lightweight MIR assignment parser (`MirDataflow`) that collects `_n = ...` statements and extracts their operand dependencies. The helper performs fixed-point propagation of tainted variables.
- Built `detect_content_length_allocations` on top of the helper. It now seeds taint when the defining expression references `content_length` invocations, lowercase header literals, or typed helpers such as `HeaderName::from_static("content-length")`, `HeaderValue::from_static`, and their `from_bytes(b"content-length")` equivalents. `CONTENT_LENGTH` constants count as sources as well.
- Captured the functionality in unit tests inside `mir-extractor` so the proof-of-concept runs during `cargo test`.

## Current coverage

- Detects flows where `Response::content_length`, header string literals, typed constants (`CONTENT_LENGTH`), or helper constructors (`HeaderName::from_static`, `HeaderValue::from_static`, `from_bytes(b"content-length")`) feed directly or indirectly into `Vec::with_capacity`.
- Propagates through multiple assignment hops and survives conversions such as copies or moves.
- Handles tuple destructuring (`(_1, _2) = ...`) and Option projections (`(_5.0: Option<_>)`) so taint survives common unwrapping patterns.
- Recognizes upper-bound guards such as `core::cmp::min`, `.clamp(...)`, and `assert!(len <= MAX)` so guarded allocations are suppressed.
- Flags both `Vec::with_capacity` and `Vec::reserve*` call sites (case-insensitive match).

## Limitations & open questions

- Source detection still relies on textual heuristics, even though we now match common typed helpers. We should eventually bind directly to semantic paths so aliases or reexports do not slip through.
- Complex aggregation (e.g., storing lengths inside structs or slices) can still hide taint from the current parser.
- Guard detection ignores custom helper functions that enforce bounds; we should surface a way to configure trusted clamps.

## Next steps

1. Wrap the detector in a production rule with SARIF metadata and configurability.
2. Allow rulepacks or configuration to specify additional trusted guard helpers.
3. Leverage the shared dataflow helper for backlog items 105 (length truncation casts) and 106 (Tokio broadcast `!Sync` payloads).

## Artifacts

- `mir-extractor/src/dataflow.rs` — new MIR assignment parser with taint propagation.
- `mir-extractor/src/prototypes.rs` — content-length detector built on the parser.
- Unit tests covering the helper and detector run via `cargo test -p mir-extractor`.
