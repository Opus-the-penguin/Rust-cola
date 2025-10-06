# RustSec tokio broadcast `!Sync` prototype (Oct 2025)

## Background

RustSec advisory [RUSTSEC-2025-0023](https://rustsec.org/advisories/RUSTSEC-2025-0023.html) explains that `tokio::sync::broadcast` requires `T: Clone` but not `T: Sync`, allowing unsound clones of types like `Rc` or `RefCell` to cross thread boundaries. Backlog entry 106 tracks a prospective Rust-cola rule to highlight dangerous payload types.

## Prototype goals

- Heuristically spot `tokio::sync::broadcast::channel` usages where the generic payload is a well-known `!Sync` type (e.g., `std::rc::Rc`, `std::cell::RefCell`).
- Provide fast-running unit tests that exercise the detection without compiling larger crates.
- Explore whether MIR text preserves enough type information to drive a future rule.

## Implementation snapshot

- Added `detect_broadcast_unsync_payloads` in `mir-extractor/src/prototypes.rs`.
- Scans MIR lines for `tokio::sync::broadcast::channel` or `broadcast::Sender` instantiations whose generic arguments include `Rc`, `RefCell`, or `Cell`.
- Emits findings with the offending line for downstream diagnostics.
- Backed by unit tests inside `prototypes::tests`.

## Current coverage

- Flags channels instantiated with obvious single-thread-only types (`std::rc::Rc`, `std::cell::RefCell`, `core::cell::Cell`).
- Leaves `Arc<T>` and other clearly `Sync` payloads untouched, keeping noise low.
- Runs automatically via `cargo test -p mir-extractor`.

## Limitations & open questions

- The detector only understands a small, hard-coded set of `!Sync` markers. Real-world code may wrap `Rc` deeper inside aliases or smart pointers.
- Custom wrapper APIs that forward broadcast senders are not yet analyzed.
- No attempt is made to confirm the channel crosses threads; the heuristic simply surfaces suspicious payload types.

## Next steps

1. Expand the marker list (or read from configuration) so teams can flag project-specific `!Sync` types.
2. Tie findings to actual send/recv sites to confirm cross-thread usage.
3. Promote the detector into a full rule with SARIF metadata once configurability and false-positive controls are in place.

## Artifacts

- `mir-extractor/src/prototypes.rs` — `detect_broadcast_unsync_payloads` implementation.
- Unit tests in `mir-extractor/src/prototypes.rs` (`detects_broadcast_rc_payload`, `ignores_broadcast_arc_payload`).
- Validated with `cargo test -p mir-extractor`.
