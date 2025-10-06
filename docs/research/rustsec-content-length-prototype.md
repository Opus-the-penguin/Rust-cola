# RustSec Content-Length DoS prototype (Oct 2025)

## Background

RustSec advisory [RUSTSEC-2025-0015](https://rustsec.org/advisories/RUSTSEC-2025-0015.html) describes a denial-of-service condition in the `web-push` crate where untrusted `Content-Length` headers are used to preallocate buffers. Backlog entry 107 proposes a future Rust-cola rule that would flag similar patterns.

## Prototype goals

- Verify that MIR text provides enough signal to taint-track values sourced from HTTP `Content-Length` headers.
- Demonstrate that taint can be propagated across temporary variables and conversions before reaching allocation sinks such as `Vec::with_capacity`.
- Exercise the plumbing in unit tests so we can iterate quickly without compiling full crates.

## Implementation snapshot

- Added a lightweight MIR assignment parser (`MirDataflow`) that collects `_n = ...` statements and extracts their operand dependencies. The helper performs fixed-point propagation of tainted variables.
- Built `detect_content_length_allocations` on top of the helper. It marks variables as tainted when their defining expression references `content_length` invocations or `"content-length"` literals, then scans for `with_capacity` / `reserve*` calls whose argument variables are tainted.
- Captured the functionality in unit tests inside `mir-extractor` so the proof-of-concept runs during `cargo test`.

## Current coverage

- Detects simple flows where `Response::content_length` or a header lookup feeds directly or indirectly into `Vec::with_capacity`.
- Propagates through multiple assignment hops and survives conversions such as copies or moves.
- Handles tuple destructuring (`(_1, _2) = ...`) and Option projections (`(_5.0: Option<_>)`) so taint survives common unwrapping patterns.
- Flags both `Vec::with_capacity` and `Vec::reserve*` call sites (case-insensitive match).

## Limitations & open questions

- The parser ignores tuple assignments and field projections that appear in more complex MIR (e.g., tuple returns from `Option::transpose`). We may need to extend it for real-world crates.
- False negatives remain possible when the tainted value is wrapped in helper structs or stored in aggregates we currently skip.
- The heuristic marks allocations even if a clamp (e.g., `min`) is present. A production rule should recognize effective upper bounds and drop those matches.
- Sources only trigger on string matches; we should generalize to typed paths (e.g., `http::header::CONTENT_LENGTH` constants).

## Next steps

1. Model range guards (asserts, `min`, `clamp`) to filter safe allocations.
2. Wrap the detector in a production rule with SARIF metadata and configurability.
3. Reuse the enhanced parser for backlog items 105 (length truncation casts) and 106 (Tokio broadcast `!Sync` payloads); add dedicated prototypes.

## Artifacts

- `mir-extractor/src/dataflow.rs` — new MIR assignment parser with taint propagation.
- `mir-extractor/src/prototypes.rs` — content-length detector built on the parser.
- Unit tests covering the helper and detector run via `cargo test -p mir-extractor`.
