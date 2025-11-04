# HIR Extraction Pipeline Plan

## Goals

- Unlock advanced analyses that require richer type and semantic information than MIR alone (aliasing models, trait bounds, async borrow lifetimes) while maintaining parity with CodeQL and other enterprise-grade rule sets.
- Replace the shell-based `cargo +nightly rustc -Zunpretty=mir` flow with an in-process `rustc_interface` driver that can materialize both MIR and HIR (and selected `TyCtxt` data) in a single invocation.
- Preserve existing ergonomics of `cargo-cola`/`mir-extractor` CLIs and caching while gradually introducing HIR-backed rules.
- Maintain reasonable extraction latency (<1.2x current MIR-only runs for medium crates) and keep cache invalidation transparent to users.

## Success Criteria

1. **Artifact completeness** – For every crate analyzed, we can persist a structured HIR snapshot that includes:
   - Crate-level items (modules, use statements, impl blocks, traits, enums/structs).
   - Function/item signatures with full generics and where-clauses.
   - Trait implementations with resolved `Self`/type parameters.
   - Type aliases, lifetimes, and region/variance metadata necessary for aliasing analyses.
   - Mappings from HIR item IDs to existing MIR functions and source spans.
2. **Rule enablement** – Prototype at least one advanced rule that demonstrably needs HIR (e.g., unsafe aliasing or trait-bound enforcement) behind a feature flag by the end of Phase 3.
3. **Tooling parity** – `cargo-cola` continues to work without new flags; users can opt into HIR exports via `--hir-json`/`--hir-cache` or a config toggle.
4. **CI readiness** – New code path is covered by unit/integration tests plus a GitHub Action matrix job that exercises the in-process extractor on `examples/simple` and one real-world crate.

## Architectural Overview

### Driver Strategy

- Embed a new `hir_driver` module inside `mir-extractor` that wraps `rustc_interface::interface::run_compiler`.
- Configure the driver using metadata from `cargo_metadata` (already in use) to assemble the correct crate graph, target triple, and feature set.
- Request both MIR and HIR through the same `TyCtxt`: invoke `tcx.hir()` for item traversal, `tcx.all_local_trait_impls(())` for impl discovery, and `tcx.instance_mir(InstanceDef::Item(def_id))` for MIR bodies when needed.
- Capture incremental queries behind a `Collector` struct that records:
  - `HirItem` nodes serialized into an intermediate, borrow-independent data model.
  - Type resolution snippets (e.g., `Ty<'tcx>` pretty-printed using `rustc_middle::ty::Ty::to_string()` with `TrimmedDefPaths` for stability).
  - Trait/where-clause obligations via `tcx.predicates_of(def_id)` and normalization helpers.
- Guard against nightly compiler drift by pinning a rustc version in `rust-toolchain.toml` and adding compile-time assertions for known query APIs.

### Data Model Additions

- Introduce `hir.rs` module with serializable structs:
  ```rust
  pub struct HirCrate { /* root metadata */ }
  pub struct HirItem { pub kind: HirItemKind, pub span: SourceSpan, ... }
  pub enum HirItemKind { Function(HirFunction), Trait(HirTrait), Impl(HirImpl), Struct(HirStruct), Enum(HirEnum), TypeAlias(HirTypeAlias), Use(HirUse), Mod(HirMod), Const(HirConst) }
  pub struct HirFunction { pub name: String, pub generics: Generics, pub where_clauses: Vec<Predicate>, pub asyncness: bool, pub safety: Safety, pub abi: String, pub mir_def_id: Option<String>, ... }
  // and supporting Generics, Predicate, PathSegment, TypeExpr, LifetimeExpr definitions
  ```
- Extend the existing `CacheEnvelope` with an optional `hir` payload and version bump to `CACHE_VERSION = 2`.
- Add JSON writers alongside MIR: `write_hir_json(&Path, &HirCrate)` and analogous Serde types.

### CLI & API Surface

- `mir-extractor` CLI gains flags:
  - `--hir-json <path>` (default `out/mir/hir.json`).
  - `--hir-cache=[true|false]` to opt out of persistence while iterating.
  - Hidden `--hir-only` for development (skips MIR, useful for benchmarking).
- `cargo-cola` proxy simply forwards new flags; defaults keep HIR enabled but writing JSON only when requested to avoid disk bloat.
- Within library APIs, expose `extract_with_cache_extended` returning `(MirPackage, Option<HirCrate>, CacheStatus)` while keeping `extract_with_cache` as a backward-compatible wrapper (HIR disabled unless requested).

## Implementation Phases

| Phase | Scope | Deliverables | Validation |
|-------|-------|--------------|------------|
| **0 – Spike** | Build a standalone binary (behind `cfg(feature = "hir-spike")`) that runs `rustc_interface` on `examples/simple`, dumps HIR/MIR summaries to stdout. Document required components (`rustup component add rustc-dev llvm-tools-preview`). | Prototype binary + notes in `docs/research/hir-extraction-plan.md`. | Manual run of spike, sanity-check counts (items, functions). |
| **1 – Core Driver** | Integrate driver into `mir-extractor` with feature flag `hir_driver`. Parse CLI flag, capture HIR for single-crate (no workspaces yet), emit `hir.json`. | `hir_driver.rs` module, basic data structs, `cargo test -p mir-extractor -- --ignored hir_smoke` covering sample crate. | Unit tests verifying serialization, integration test reading `examples/simple`. |
| **2 – Data Model Completeness** | Flesh out generics, predicates, path formatting, item relationships. Link HIR items to MIR functions (via `LocalDefId` → `DefPathHash`). Update cache schema and CLI wiring. | Extended `HirItem` hierarchy, cache version bump, migration logic for stale cache entries. | Regression tests ensuring `hir.json` round-trips, cache hit/miss scenarios. |
| **3 – Workspace & Dependency Support** | Handle multi-crate workspaces, dependency HIR gating (emit for local crates; optionally gather for deps via `tcx.extern_mod_stmt_cnum`). Ensure incremental caching works per crate fingerprint. | Workspace integration tests using `examples/workspace`. | `cargo test` workspace run hitting new code paths. |
| **4 – Rule Integration** | Publish first HIR-backed rule prototype (e.g., `UnsafeAliasOverlapRule` checking aliasing invariants) under `--experimental-hir-rules`. Add metrics logging comparing MIR-only vs MIR+HIR runtime. | Rule implementation + documentation; CI job enabling HIR path. | Benchmarks demonstrating <1.2x slowdown on `examples/simple` and <1.5x on medium crate (e.g., `examples/tokio-demo`). |
| **5 – Hardening** | Polish error handling, add crash telemetry, document nightly update playbook, and expose configuration knobs. | Docs updates (`README`, `docs/security-rule-backlog.md` cross-link), stability guide. | GitHub Action gating on HIR extraction success. |

## Key Design Considerations

- **Nightly churn** – `rustc_interface` APIs can break; mitigate with pinned toolchain, CI canary job against latest nightly, and `rust-version` check before extraction.
- **Binary size** – Linking against compiler crates increases binary size significantly. Plan to compile `mir-extractor` with `rustc_private` only when the `hir_driver` feature is enabled, producing two binaries: lightweight default, and full analyzer for CI/power users.
- **Cache invalidation** – HIR schema changes should increment `CACHE_VERSION` and optionally auto-prune stale entries on startup. Provide `--clear-cache` guidance.
- **Resource usage** – Collecting full HIR may consume >2GB RAM on large crates. Offer knobs to skip bodies (`HirItem.body_source` optional) and only store metadata required by rules. Consider streaming serialization to disk.
- **Security/compliance** – Ensure we respect `RUSTC_WRAPPER`/`RUSTFLAGS` envs; reuse cargo fingerprinting to avoid double builds. Document licensing implications of re-packaging compiler internals.

## External Dependencies & Tooling

- Require `rustc-dev` and `llvm-tools-preview` components for the toolchain (`rustup component add rustc-dev llvm-tools-preview`). Update developer setup docs and CI workflows accordingly.
- Evaluate `rust-project.json` generation for editor integration; may reuse `cargo metadata` outputs.
- Optionally leverage crates like `rustc_tools_util` for version gating helpers.

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Nightly API breakage causes build failures | Pin toolchain; add CI job to track upstream changes; wrap driver behind feature flag with graceful fallback to shell-based MIR extraction. |
| Performance regressions | Benchmark with `cargo bench` harness; add metrics logging for extraction duration and memory usage; allow disabling HIR via CLI flag. |
| Cache bloat from serialized HIR | Compress cache files (gzip) or chunk by crate; add size guard rails.
| Complexity of serializing `Ty<'tcx>` | Use `Ty::to_string()` with stable formatting; consider storing `DefPathHash` references for canonicalization. |
| Trait obligation explosion | Limit predicate capture to those relevant to exported items; defer full inference until needed by rules. |

## Immediate Next Steps

1. Add `docs/research/hir-extraction-plan.md` (this file) to track decisions and updates.
2. Create `hir_driver` feature flag scaffold with no-op implementation returning `None` (ensures build wiring and feature gating are ready).
3. Schedule a spike pairing session to prototype `rustc_interface` invocation (Phase 0) and capture lessons learned.
4. Update developer onboarding docs with required toolchain components ahead of Phase 1.

## Phase 0 Spike Notes (2025-10-07)

- **Prerequisites:**
  - `rustup component add rustc-dev llvm-tools-preview`
  - Nightly toolchain (already required by the project).
- **Build command:**
  ```powershell
  cargo run -p mir-extractor --bin hir-spike --features hir-driver -- examples/simple
  ```
- **What it does:** Launches an in-process `rustc_interface` session against the `examples/simple` crate, prints total HIR items, and enumerates fn-like bodies with their MIR local/block counts. Output lives in `examples/simple/target/hir-spike/` (metadata artifact only).
- **Next validation:** Point the spike at a second crate with basic dependencies to assess additional rustc arguments we may need before Phase 1.

## Phase 0 Follow-up (2025-10-09)

- **Toolchain pin:** Added `rust-toolchain.toml` pinning to `nightly-2025-09-30` and declaring the `rustc-dev` / `llvm-tools-preview` components. CI and developers now share a consistent compiler surface for `rustc_interface` queries.
- **Spike verification:** Re-ran `cargo run -p mir-extractor --bin hir-spike --features hir-driver -- examples/simple` after pinning to confirm the prototype still emits HIR/MIR counts. Keep sample console transcripts under `examples/simple/target/hir-spike/` when tracking regressions.
- **Wrapper wiring:** Validated `hir-driver-wrapper` executes via the `MIR_COLA_HIR_WRAPPER` env var and honors passthroughs for `--version`. Future phases can assume the wrapper path is resolved automatically when the feature flag is enabled.

## Phase 0 Limitations (2025-10-09 PM)

- **Binary-only crates:** Attempting `cargo run -p mir-extractor --bin hir-spike --features hir-driver -- cargo-cola` fails because the spike currently assumes a library target at `src/lib.rs`. We need to either detect binary entry points or rely on cargo metadata to determine the primary target before moving to Phase 1.
- **External dependencies:** Pointing the spike at `mir-extractor` surfaces dozens of missing `--extern` flags; compiling rich crates requires cargo to drive dependency resolution. The next driver iteration must reuse `cargo rustc` metadata (or invoke `cargo check` to prebuild deps) so we can feed the proper search paths into `rustc_interface`.

## Phase 0 Metadata Capture (2025-10-10)

- **Cargo-mediated target discovery:** `hir-spike` now shells out to `cargo metadata` and replays the matching target's `cargo rustc` invocation through a self-wrapper. This lets us capture the exact rustc command line, including every `--extern`, `--crate-type`, and feature flag, without maintaining bespoke target heuristics.
- **Wrapper flow:** The binary re-executes itself as `RUSTC_WRAPPER`, writing the intercepted rustc arguments into a temp JSON file before handing control back to the real compiler. The primary process then loads that JSON to spin up `rustc_interface` with parity arguments.
- **Validation run:** Running `cargo run -p mir-extractor --bin hir-spike --features hir-driver -- mir-extractor` now completes the metadata/argument capture and kicks off the in-process compiler session. Compilation proceeds until the compiler hits a known nightly ICE inside `Rule::metadata`; all pre-ICE logging confirms we drive `rustc_interface` with the same crate graph as cargo.
- **Follow-up:** Track the upstream ICE (rust-lang/rust#125163) and rerun once a patched nightly lands. In parallel, add a guard that captures and reports ICEs without treating them as regressions for the metadata plumbing work.

## Phase 1 Kick-off Checklist (Planned)

- **Nightly recovery watch:** Monitor rust-lang/rust#125163 and rerun the metadata capture sanity check as soon as the nightly fix posts. Once the ICE clears, capture a golden run on `mir-extractor` and stash the rustc arguments as fixtures for regression tests.
- **Data model scaffolding:** Land the `hir.rs` module with the minimal `HirCrate`, `HirItem`, and `HirItemKind::Function` structs, plus serde derives. Use the current MIR structures as a style reference and keep the schema versioned even before it’s populated.
- **Collector prototype:** Add a `hir_driver` module that exercises `rustc_interface::run_compiler` using the captured `rustc` argument JSON. Start by walking `tcx.hir().items()` and collecting fn signatures only; persist them to an in-memory vector to test serialization.
- **CLI wiring (feature-gated):** Introduce `--hir-json` and `--hir-only` flags to `mir-extractor` behind `cfg(feature = "hir-driver")`. Default behavior should stay MIR-only until HIR extraction is explicitly requested.
- **Integration test harness:** Create `tests/hir_smoke.rs` (ignored by default) that runs the new driver against `examples/simple`, asserting the JSON contains at least one function entry. Use the captured rustc args to avoid rebuilding deps during the test.
- **CodeQL alignment:** Once Phase 1 code lands, update the CodeQL workflow to include a feature-disabled build (`--no-default-features`) and a feature-enabled smoke run so the database sees both code paths.

## Resilience Update (2025-10-09 PM)

- **ICE detection & logging:** `capture_hir` now collects `cargo rustc` stdout/stderr and classifies internal compiler errors. When an ICE occurs, the CLI keeps running, emits a structured log prefix (`rust-cola: rustc ICE while capturing HIR`), and surfaces the first diagnostic line plus a truncated stderr tail. This allows downstream workflows to continue while we wait for nightly fixes.
- **Smoke test behavior:** The HIR smoke test short-circuits when the extractor reports an ICE, so CI logs capture the failure context without treating missing `hir.json` as a hard assertion error.
- **Linker work:** Replaced the temporary `.cargo/config.toml` shim with a `build.rs` in `mir-extractor/` that auto-injects `-Cprefer-dynamic` plus macOS linker hints whenever the `hir-driver` feature is enabled. This unblocks the ignored HIR smoke test on Apple silicon without touching other targets. If future toolchains regress, re-introducing a scoped `.cargo/config.toml` with matching flags remains a viable fallback.

---

_Last updated: 2025-10-09_
