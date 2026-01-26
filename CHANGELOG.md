# Changelog

All notable changes to Rust-COLA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-01-25

### 🎯 False Positive Reduction Release

This patch release significantly reduces false positives discovered during real-world analysis of large Rust codebases (InfluxDB OSS). Expected reduction: ~90% fewer noisy findings.

### Added

#### RUSTCOLA087 (SQL Injection) Improvements
- **SQL execution sink requirement**: Now requires actual SQL execution functions (`execute()`, `query()`, `sqlx::query`, etc.) to be present before flagging SQL injection. This prevents false positives from string building without execution.
- **Non-SQL context filtering**: Added detection of log messages, error contexts, and CLI help text containing SQL keywords. Patterns like `error!("Failed to update table")` are now correctly filtered out.
- **New constants**: `SQL_EXECUTION_SINKS` (19 patterns) and `NON_SQL_CONTEXTS` (25 patterns) for precise filtering.

#### RUSTCOLA024 (Unbounded Allocation) Improvements  
- **HTTP-layer guard patterns**: Added 15+ new guard markers to `PrototypeOptions` for HTTP request size limiting:
  - `max_request_bytes`, `max_request_size`, `max_body_size`, `max_http_request_size`
  - `body_limit`, `DefaultBodyLimit`, `RequestBodyLimit`, `ContentLengthLimit`
  - Generic patterns: `MAX_SIZE`, `MAX_LEN`, `SIZE_LIMIT`, `max_capacity`

#### Test Code Exclusion
- **`--exclude-tests` flag** (default: true): Automatically excludes findings from test code
- **`--exclude-examples` flag** (default: true): Excludes findings from example code
- **`--exclude-benches` flag** (default: true): Excludes findings from benchmark code
- **`MirFunction::is_test_code()`**: New method detecting test code via:
  - Path patterns (`/tests/`, `_test.rs`, `/examples/`, `/benches/`)
  - Function name patterns (`::tests::`, `test_`, `::mock_`)
  - Test attributes (`#[test]`, `#[cfg(test)]`, `#[tokio::test]`)

#### CodeContext Classification (Audit Trail Preservation)
- **`CodeContext` enum**: New classification for findings (`Production`, `Test`, `Example`, `Benchmark`, `Generated`)
- **Finding extensions**: Added `code_context` and `filter_reason` fields to `Finding` struct
- **Full audit trail in SARIF**: Raw SARIF now contains ALL findings with `codeContext` property, regardless of exclusion flags
- **SARIF suppressions**: Non-production findings include SARIF-compliant `suppressions` array with justification
- **Terminal summary stats**: Shows breakdown by code context when filtering (e.g., "production: 12, test: 847 (filtered)")
- **LLM prompt integration**: Context hints now use `CodeContext` field for accurate classification

### Changed
- `SqlInjectionRule::evaluate()` now applies dual-layer filtering (sink + context)
- `PrototypeOptions::guard_markers` expanded from 9 to 24+ patterns
- Finding filtering now happens after profile filtering in cargo-cola

### Fixed
- False positives in InfluxDB analysis:
  - RUSTCOLA087: 47 → <5 (log messages like "Unexpected error deleting table from catalog")
  - RUSTCOLA024: Better guard detection for HTTP-layer size limits
  - Test code: ~1,700 findings automatically excluded

### Documentation
- Added `docs/v1.0.1-rules-patch.md` with detailed implementation specifications

---

## [Unreleased - Post 1.0.1]

### Added
- **Guard Detection Enhancement**: New Step 0.5 in LLM prompt with rule-specific guard detection guidance
  - `GuardHints` struct and `get_guard_hints_for_rule()` function for rule-specific patterns
  - Dynamically generated guard patterns table based on finding types in scan
  - Per-finding "🔍 Guard Check" hints with patterns to search and false positive criteria
  - Coverage for: RUSTCOLA024/203 (allocation), RUSTCOLA001/003/004/100-102 (injection), RUSTCOLA204 (overflow), RUSTCOLA012/200/201 (crypto), RUSTCOLA005 (TLS), RUSTCOLA301 (mutex await), RUSTCOLA300/302 (blocking async), RUSTCOLA021 (content-length), RUSTCOLA090 (unbounded read), RUSTCOLA086 (path traversal)
- **Roadmap Considerations**: New `docs/ROADMAP_CONSIDERATIONS.md` working document for enhancement ideas
- **User Guide**: Comprehensive `docs/USER_GUIDE.md` covering theory of operation, LLM integration, CI/CD, configuration, suppression, and troubleshooting
- **Save Instructions**: LLM prompt now includes instructions for saving the generated report

### Changed
- **LLM Prompt Overhaul**: Redesigned `llm-prompt.md` generation for enterprise-ready security reports:
  - Added Step 0: Source Verification (MANDATORY) with verification checklist
  - Added Step 0.5: Guard Detection with rule-specific patterns and false positive criteria
  - Added aggressive pruning instructions with automatic false positive criteria (test code, examples, constants, dead code)
  - Added reachability classification (EXPOSED, INDIRECT, AUTHENTICATED, INTERNAL, CONFIG-DRIVEN) with severity modifiers
  - Added mandatory authentication verification checklist
  - Added impact taxonomy (RCE, AUTH, MEM, INJ, PRIV, DATA, PATH, SSRF, DOS, INFO, QUAL)
  - Replaced raw CVSS with contextual severity model: `Final = Base + Reachability + Context`
  - Added remediation section requiring compilable code fixes with effort estimates
  - Added enterprise output format with executive summary, risk matrix, and remediation roadmap
  - Added Step 6: Output Verification
  - Added final verification checklist with guard pattern check requirement
- **Documentation Update**: Updated `docs/prompts/llm-prompt-reference.md` to reflect current prompt structure
- Renamed `docs/prompts/security-report-template.md` → `llm-prompt-reference.md` with code-is-authoritative note

### Removed
- Removed `docs/V1X_ROADMAP.md` (work transferred to separate project)
- Removed internal development docs (`docs/archive/`)
- Removed prototype research files (hir-extraction-plan, rustsec prototypes)
- Removed unused `.github/codeql/` configuration (CodeQL not currently enabled)

## [1.0.0] - 2025-12-24

### 🎉 First Stable Release

cargo-cola v1.0.0 is the first production-ready release of the Rust security static analyzer.

### Highlights
- **126 security rules** covering memory safety, concurrency, injection, cryptography, FFI, and more
- **Interprocedural taint tracking** for SQL injection, SSRF, path traversal, and command injection
- **LLM-assisted analysis** workflow with structured prompts for AI-powered security review
- **SARIF 2.1.0 output** with code snippets for IDE and CI integration
- **CVSS-like exploitability scoring** for finding prioritization
- **Configurable rule profiles** (strict/balanced/permissive) for different use cases

### Performance
Benchmarks on Apple M1:
| Crate Size | Analysis Time | Memory |
|------------|---------------|--------|
| ~400 LOC | 1.6s | ~100MB |
| ~6K LOC | 18s | ~460MB |

### Since v0.9.11
- Added performance benchmarks to README
- Finalized documentation for v1.0 release

## [0.9.11] - 2025-12-24

### Fixed
- **LLM Prompt Integrity**: Fixed bug where `raw-findings.json` and `llm-prompt.md` could have inconsistent finding counts. Findings are now consistently formatted between output files.

### Changed
- **RUSTCOLA039 Precision**: Hardcoded crypto key rule now skips URL paths (values containing `/` that look like API endpoints rather than secrets). Eliminates false positives on constants like `/api/v3/configure/token/admin`.

- **RUSTCOLA200 Precision**: Use-after-free rule now skips function call patterns (lines containing `->` in MIR). Method calls like `PartialEq::eq(move _3)` consume references rather than returning them, eliminating false positives on safe closure patterns.

- **RUSTCOLA088 Precision**: SSRF rule now distinguishes between incoming request parsing (safe) and outbound request making (risky):
  - Removed `http::Request`, `hyper::Request` from sinks (these are incoming request types)
  - Removed generic `Request`, `Form`, `Query`, `Json`, `Path` from untrusted sources
  - Added specific framework extractors: `axum::extract::Query`, `actix_web::web::Path`, etc.
  - Maintained recall on actual SSRF patterns (`reqwest::get`, `Client::post`, etc.)

### Metrics
- **Precision improvement**: 33% false positive reduction on real-world production crate (influxdb3_server)
- **Findings reduced**: 165 → 111 (54 fewer false positives)
- **Recall maintained**: All test cases still pass, no true positives lost

## [0.9.10] - 2025-12-22

### Changed
- **Unified Rule Architecture**: Migrated all 8 advanced rules from `mir-advanced-rules` crate to `mir-extractor`.
  - New rule IDs: RUSTCOLA200-207 (replacing ADV001-ADV009)
  - RUSTCOLA200: DanglingPointerUseAfterFreeRule (use-after-free detection)
  - RUSTCOLA201: InsecureBinaryDeserializationRule (bincode/postcard/etc.)
  - RUSTCOLA202: RegexBacktrackingDosRule (ReDoS patterns)
  - RUSTCOLA203: UncontrolledAllocationSizeRule (allocation DoS)
  - RUSTCOLA204: IntegerOverflowRule (arithmetic overflow)
  - RUSTCOLA205: TemplateInjectionRule (template engines)
  - RUSTCOLA206: UnsafeSendAcrossAsyncBoundaryRule (async Send safety)
  - RUSTCOLA207: AwaitSpanGuardRule (tracing span guards across await)
  - ADV002 was duplicate of RUSTCOLA091 (not migrated)

### Removed
- **`mir-advanced-rules` crate**: Removed from workspace (dead code after migration)
- **`advanced-rules` feature flag**: No longer needed in cargo-cola
- **Dual-trait architecture**: All rules now use unified `Rule` trait

### Added
- New modules in `mir-extractor/src/rules/`:
  - `advanced_memory.rs` - Deep memory dataflow analysis (RUSTCOLA200)
  - `advanced_utils.rs` - Shared utilities for advanced rules
  - `advanced_input.rs` - Input validation rules (RUSTCOLA201-204)
  - `advanced_async.rs` - Async/web security rules (RUSTCOLA205-207)

## [0.9.9] - 2025-12-22

### Added
- **CVSS-like Exploitability Scoring**: Findings now include exploitability metrics based on CVSS 3.1 factors.
  - New enums: `AttackVector` (Network/Adjacent/Local/Physical), `AttackComplexity` (Low/High), `PrivilegesRequired` (None/Low/High), `UserInteraction` (None/Required)
  - New `Exploitability` struct with `score()` method (computes 0.0-10.0)
  - `cvss_vector()` method returns CVSS-style string (e.g., "AV:N/AC:L/PR:N/UI:N")
  - All 118 `RuleMetadata` and 75 `Finding` struct literals updated with `exploitability` field

- **Rule Profiles**: Filter findings by confidence+severity thresholds via configuration.
  - New `RuleProfile` enum: `strict` (all), `balanced` (default), `permissive` (CI-friendly)
  - Configurable via `profile: balanced` in `cargo-cola.yaml`
  - `strict`: All findings, no filtering
  - `balanced`: Exclude low-confidence + low-severity combo
  - `permissive`: Only high-confidence OR high/critical severity

### Changed
- Updated `examples/cargo-cola.yaml` with `profile` documentation

## [0.9.8] - 2025-12-22

### Added
- **Code Snippets in SARIF Output**: SARIF findings now include source code snippets for easier review.
  - New `extract_snippet()` helper function to read source files and extract lines around a span
  - SARIF `region` objects now include `snippet.text` when span data is available
  - New test `sarif_report_includes_code_snippet` validates snippet extraction

### Fixed
- **Span Data in 7 Function-Based Rules**: Updated rules to properly populate span data (was `span: None`):
  - `code_quality.rs`: Crate-wide allow, misordered assert, try io result, local refcell, unnecessary borrow_mut
  - `ffi.rs`: Constructor/destructor std calls
  - `input.rs`: Infinite iterator

## [0.9.7] - 2025-12-22

### Added
- **Configuration File Support**: Analysis limits are now configurable via YAML configuration file instead of requiring source code changes.
  - New `--config <path>` CLI argument to specify configuration file
  - Example configuration at `examples/cargo-cola.yaml`
  - IPA limits configurable: `max_path_depth`, `max_flows_per_source`, `max_visited`, `max_total_flows`, `max_functions_for_ipa`
- **`IpaConfig` Struct**: New public configuration struct in `mir_extractor::interprocedural::IpaConfig` with `Default` implementation
- **`InterProceduralAnalysis::with_config()`**: New constructor accepting custom configuration
- **`RuleEngine::set_ipa_config()`**: Method to configure IPA limits on the rule engine

### Changed
- **README Consolidated**: Combined "Interprocedural Analysis" and "Limitations" sections into unified documentation with configuration examples
- **Hardcoded limits removed**: IPA depth limits now come from configuration, not source code constants

### Dependencies
- Added `serde_yaml` to cargo-cola for configuration file parsing

## [0.9.6] - 2025-12-20

### Fixed
- **OOM Root Cause Identified and Fixed**: Resolved the memory explosion (60GB+) when analyzing large codebases like InfluxDB. Root cause was exponential path exploration in inter-procedural analysis due to `visited.remove()` combined with no depth limits.

### Changed
- **Inter-procedural Analysis Algorithm**: Removed `visited.remove()` from `find_paths_from_source()`. Each function is now visited exactly once per source exploration, changing complexity from O(branches^depth) to O(n).
- **Configurable Analysis Limits**: Added well-documented, configurable limits to prevent memory exhaustion on extreme codebases while maintaining thorough analysis for typical vulnerabilities.

### Added
- **Analysis Limits** (configurable in `interprocedural.rs`):
  - `MAX_PATH_DEPTH = 8`: Maximum call chain depth from source to sink
  - `MAX_FLOWS_PER_SOURCE = 200`: Maximum taint flows per source function
  - `MAX_VISITED = 1000`: Maximum functions visited per exploration
  - `MAX_TOTAL_FLOWS = 5000`: Maximum total inter-procedural flows
- **Flow Caching**: Inter-procedural flows are now computed once and cached, avoiding redundant computation across rules.
- **CFG Complexity Guards**: Functions with >500 basic blocks or >100 branches skip exhaustive path enumeration (use summary-based analysis instead).
- **README Limitations Section**: Documents the analysis limits, potential for false negatives in extreme cases, and how to increase limits on high-memory machines.

### Technical
- Successful full scan of InfluxDB: 24 crates, 11,178 functions, 2,619 findings, ~150MB peak memory (was 60GB+ crash)
- Most real vulnerabilities have call chain depth < 5, so MAX_PATH_DEPTH=8 is generous
- Limits are safety valves for edge cases; typical analysis doesn't hit them

## [0.9.5] - 2025-12-18

### Fixed
- **ADV001 False Positive Reduction**: ADV001 (pointer escapes) no longer flags derive macro generated code. Previously, 100% of ADV001 findings on derive macros were false positives, accounting for ~60% of all findings on real-world crates like InfluxDB.

### Added
- `is_derive_macro_function()`: Detects `<impl at file:LINE:COL: LINE:COL>::method` patterns
- `is_safe_trait_method()`: Detects safe trait implementations (PartialEq, Hash, Debug, Clone, etc.)
- `should_skip_adv001()`: Combined filter for ADV001 false positive reduction
- 13 unit tests for the new FP filtering logic

### Technical
- Safe trait methods whitelist: eq, ne, partial_cmp, cmp, hash, fmt, clone, clone_from, default
- Trait patterns detected: PartialEq, PartialOrd, Ord, Eq, Hash, Hasher, Debug, Display, Clone, Default

## [0.9.4] - 2025-12-18

### Changed
- **Reverted Arbitrary Limits**: Removed restrictive thresholds that were causing false negatives by skipping analysis on large crates. Analysis limits are now set to permissive values (MAX_FUNCTIONS: 10000, MAX_PATHS: 1000, MAX_DEPTH: 50, MAX_BLOCKS: 500).

### Added
- **V1 Sprint Backlog**: Added memory profiling investigation as P0 priority item. The goal is to fix memory issues without sacrificing coverage.

### Technical
- Memory optimization for large crates is now tracked as a proper engineering task rather than addressed with arbitrary skip thresholds.

## [0.9.3] - 2025-12-17

### Changed
- **Shared InterProcedural Analysis**: Refactored IPA engine to create a single shared analysis instance per crate instead of 5 separate instances (one per injection rule). This reduces memory usage by ~5x for interprocedural analysis.
- **Rule Trait Signature**: Updated `Rule::evaluate()` to accept optional `&InterProceduralAnalysis` parameter, enabling shared analysis across all rules.
- **Batched Parameter Analysis**: Path-sensitive analysis now processes all function parameters in a single pass instead of N separate analyses per function.

### Fixed
- **OOM on Large Crates**: Resolved out-of-memory issues when scanning crates with 1000+ functions by sharing interprocedural analysis infrastructure.

### Technical
- Updated all 120 Rule implementations to use new signature
- RuleEngine now creates shared InterProceduralAnalysis once and passes to all rules
- Successful full scan of InfluxDB: 24 crates, 11,178 functions, 2,621 findings

## [0.9.2] - 2025-12-16

### Changed
- Improved standalone report for offline/disconnected use
- Removed all emojis and special characters for better terminal portability
- Added P0/P1/P2 remediation priority classification
- Added CWE IDs and confidence levels to finding details
- Added fix suggestions when available
- Simplified LLM integration section in standalone report
- Added exploitability analysis framework to LLM prompt template

## [0.9.1] - 2025-12-16

### Changed
- Simplified LLM prompt template for clarity and brevity
- Removed emojis, decorative symbols, and unnecessary formatting from generated prompts
- Template reduced from 278 to 106 lines
- Plain factual language throughout
- Evidence-based false positive requirements preserved

## [0.8.8] - 2025-12-14

### Added
- **Phase 3 Complete**: Framework-aware sanitization recognition for precision improvements.
  - **Actix-web**: `web::Json`, `web::Path`, `web::Query`, `web::Form`, `web::Data` validators
  - **Axum**: `extract::Json`, `extract::Path`, `extract::Query`, `extract::Form`, `extract::State`
  - **Rocket**: `FromForm`, `FromParam`, `FromData`, `FromFormField` validators
  - **HTML escaping**: `html_escape`, `encode_safe`, `askama`, `tera`, `maud`
  - **SQL escaping**: `sql_escape`, `bind`, `quote_literal`, `escape_string`
  - **URL encoding**: `url_encode`, `percent_encode`, `form_urlencoded`
  - **Validation**: `Regex::is_match`, `validator::Validate`, `garde::Validate`, `serde_valid`

### Changed
- **Sanitizer Recognition**: Expanded from 4 patterns to 70+ patterns for reduced false positives.
- **Phase 3 Status**: All precision & recall improvements complete (3.1 field-sensitive, 3.2 recursion, 3.3 sanitization).

### Technical
- **Test Count**: 237 tests (was 181), all passing.
- Added 10 new sanitizer tests in `path_sensitive.rs` for framework coverage validation.

## [0.8.7] - 2025-12-14

### Added
- **Phase 2 Complete**: Implemented final 4 Phase 2 rules for WASM, memory safety, and interior mutability.
  - `RUSTCOLA126` (WasmHostFunctionTrustRule): Detects untrusted data from WASM host functions without validation.
  - `RUSTCOLA127` (WasmCapabilityLeakRule): Detects overly permissive capabilities leaked to WASM guests.
  - `RUSTCOLA128` (UnsafeCellAliasingRule): Detects potential UnsafeCell aliasing violations with multiple mutable refs.
  - `RUSTCOLA129` (LazyInitPanicPoisonRule): Detects panic-prone code in OnceLock/Lazy initialization.

### Changed
- **Rule Count**: 115 unique RUSTCOLA rules + 9 ADV advanced rules = 124 total.
- **Memory rules**: Now contains 23 rules (was 21).
- **FFI rules**: Now contains 11 rules (was 9).

### Technical
- **Test Count**: 181 tests (was 173), all passing.
- New test file: `mir-extractor/tests/test_new_rules_v087.rs` with 8 unit tests.

## [0.8.6] - 2025-12-14

### Added
- **Phase 2 High-Priority Rules Complete**: Implemented 4 new rules for async correctness and panic safety.
  - `RUSTCOLA122` (AsyncDropCorrectnessRule): Detects Drop impl on types with async fields (JoinHandle, Future, Task). Resource leak risk.
  - `RUSTCOLA123` (UnwrapInHotPathRule): Detects `unwrap()`/`expect()` in loops, iterators, and hot paths. Crash risk.
  - `RUSTCOLA124` (PanicInDropImplRule): Detects panic-prone code (`unwrap`, `panic!`, `assert`) in Drop implementations. Double-panic risk.
  - `RUSTCOLA125` (SpawnedTaskPanicRule): Detects spawned tasks without JoinHandle or panic handling. Silent failure risk.

### Changed
- **Rule Count**: 111 unique RUSTCOLA rules + 9 ADV advanced rules = 120 total.
- **concurrency.rs**: Now contains 21 rules (was 18).
- **code_quality.rs**: Now contains 9 rules (was 8).

### Enhanced
- `RUSTCOLA096` (RawPointerEscapeRule): Enhanced with `unsafe { &*ptr }` outliving pointee pattern detection.
  - Added `is_unsafe_deref()` for common unsafe dereference patterns.
  - Added `is_outliving_pattern()` for struct field storage, global storage, and callback patterns.
  - Expanded local cast detection with 7+ new patterns.

### Technical
- **Test Count**: 173 tests (was 165), all passing.
- New test file: `mir-extractor/tests/test_new_rules_v086.rs` with 8 unit tests for RUSTCOLA122-125.

## [0.8.5] - 2025-12-14

### Added
- **Test Coverage for v0.8.4 Rules**: Added comprehensive test suite for the 5 new rules.
  - New test file: `mir-extractor/tests/test_new_rules_v084.rs` with 10 unit tests.
  - Example projects for each rule with vulnerable and safe patterns:
    - `examples/returned-ref-to-local/` - RUSTCOLA118 test cases
    - `examples/closure-escaping-refs/` - RUSTCOLA119 test cases
    - `examples/self-referential-struct/` - RUSTCOLA120 test cases
    - `examples/executor-starvation/` - RUSTCOLA121 test cases
    - `examples/wasm-linear-memory-oob/` - RUSTCOLA103 test cases

### Technical
- **Test Count**: 165 tests (was 146), all passing.

## [0.8.4] - 2025-12-14

### Added
- **Phase 2 Rules - Lifetime/Borrow & Async Correctness**: Implemented 5 new rules.
  - `RUSTCOLA103` (WasmLinearMemoryOobRule): Detects unchecked pointer operations in WASM exports that may cause out-of-bounds memory access.
  - `RUSTCOLA118` (ReturnedRefToLocalRule): Detects patterns where functions return references to local variables in unsafe code. UAF risk.
  - `RUSTCOLA119` (ClosureEscapingRefsRule): Detects non-move closures passed to spawn functions that may capture escaping references.
  - `RUSTCOLA120` (SelfReferentialStructRule): Detects self-referential struct creation patterns without proper Pin usage. UAF risk.
  - `RUSTCOLA121` (ExecutorStarvationRule): Detects CPU-bound operations in async functions that may starve the executor.

### Changed
- **Rule Count**: 107 unique RUSTCOLA rules + 9 ADV advanced rules = 116 total.
- **memory.rs**: Now contains 21 rules (was 19).
- **concurrency.rs**: Now contains 18 rules (was 16).
- **ffi.rs**: Now contains 9 rules (was 8).

### Technical
- All 146 tests pass.

## [0.8.3] - 2025-12-14

### Added
- **Phase 2 Rules - Interior Mutability & Variance**: Implemented 3 new rules.
  - `RUSTCOLA100` (OnceCellTocTouRule): Detects TOCTOU race conditions with OnceCell/OnceLock (get().is_none() followed by get_or_init()). Use get_or_init() directly.
  - `RUSTCOLA101` (VarianceTransmuteUnsoundRule): Detects transmutes violating variance rules (&T→&mut T, *const T→*mut T, invariant types). UB risk.
  - `RUSTCOLA117` (PanicWhileHoldingLockRule): Detects panic-prone operations (unwrap, expect, assert) while holding MutexGuard/RwLockGuard. Mutex poisoning risk.

### Changed
- **Rule Count**: 102 unique RUSTCOLA rules + 9 ADV advanced rules = 111 total.
- **concurrency.rs**: Now contains 16 rules (was 15).
- **memory.rs**: Now contains 19 rules (was 18).

### Technical
- All 146 tests pass.

## [0.8.2] - 2025-12-14

### Added
- **Phase 2 Rules - FFI & Supply Chain**: Implemented 3 new rules.
  - `RUSTCOLA102` (ProcMacroSideEffectsRule): Detects suspicious patterns (fs, network, process) in proc-macro crates. Supply chain attack vector.
  - `RUSTCOLA107` (EmbeddedInterpreterUsageRule): Detects embedded interpreters (pyo3, rlua, v8, wasmer, wasmtime). Code injection surface.
  - `RUSTCOLA116` (PanicInFfiBoundaryRule): Detects panic-prone code (unwrap, expect, assert, indexing) in extern "C" functions. UB risk.

### Changed
- **Rule Count**: Total rules increased from 110 to 113.
- **ffi.rs**: Now contains 8 rules (was 6).
- **supply_chain.rs**: Now contains 4 rules (was 3).

### Technical
- All 146 tests pass.

## [0.8.1] - 2025-12-14

### Added
- **Phase 2 Rules - Async/Await & Concurrency Correctness**: Implemented 6 new rules from Tokio/InfluxDB research.
  - `RUSTCOLA106` (UncheckedTimestampMultiplicationRule): Detects unchecked multiplication in timestamp conversions (seconds→nanos, etc.) that can overflow.
  - `RUSTCOLA109` (AsyncSignalUnsafeInHandlerRule): Detects async-signal-unsafe operations (println!, format!, heap allocation, locking) inside signal handlers.
  - `RUSTCOLA111` (MissingSyncBoundOnCloneRule): Detects Clone+Send without Sync bound in channel-like concurrent structures. Based on RUSTSEC-2025-0023.
  - `RUSTCOLA112` (PinContractViolationRule): Detects Pin contract violations through unsplit/reconstruction patterns. Based on RUSTSEC-2023-0005.
  - `RUSTCOLA113` (OneshotRaceAfterCloseRule): Detects race conditions with oneshot channel close(). Based on RUSTSEC-2021-0124.
  - `RUSTCOLA115` (NonCancellationSafeSelectRule): Detects non-cancellation-safe futures in `select!` macros.
- **Examples**: Added `examples/non-cancellation-safe-select/` and `examples/missing-sync-bound-clone/`.

### Changed
- **Rule Count**: Total rules increased from 102 to 110.
- **concurrency.rs**: Now contains 15 rules (was 9).
- **input.rs**: Now contains 11 rules (was 10).
- **README.md**: Updated description to be more precise ("difficult to find" vs "invisible").
- **SECURITY.md**: Removed outdated "Supported Versions" table.

### Technical
- Real-world research completed on tokio-rs/tokio identifying 5 vulnerability patterns.
- Real-world research completed on InfluxDB identifying 7 vulnerability patterns.
- All 146 tests pass.

## [0.8.0] - 2025-12-14

(Version skipped - bumped directly to 0.8.1)

## [0.7.5] - 2025-12-14

### Changed
- **Phase 1.3 Complete**: Migrated remaining 11 security rules from `lib.rs` to modular structure.
  - `rules/memory.rs`: Added 8 rules - StaticMutGlobalRule (RUSTCOLA025), TransmuteLifetimeChangeRule (RUSTCOLA095), RawPointerEscapeRule (RUSTCOLA096), VecSetLenMisuseRule (RUSTCOLA038), LengthTruncationCastRule (RUSTCOLA022), MaybeUninitAssumeInitDataflowRule (RUSTCOLA078), SliceElementSizeMismatchRule (RUSTCOLA082), SliceFromRawPartsRule (RUSTCOLA083).
  - `rules/web.rs`: Added ContentLengthAllocationRule (RUSTCOLA021).
  - `rules/resource.rs`: Added UnboundedAllocationRule (RUSTCOLA024).
  - `rules/input.rs`: Added SerdeLengthMismatchRule (RUSTCOLA081).
- **Duplicate Cleanup**: Removed AllocatorMismatchRule (duplicate of AllocatorMismatchFfiRule in ffi.rs).
- **Codebase Reduction**: `lib.rs` reduced from 8,253 to 5,542 lines (33% reduction; 68% total since start).
- **Utility Consolidation**: Moved `filter_entry` helper to `rules/utils.rs`.

### Technical
- Only infrastructure rules remain in `lib.rs`: SuppressionRule, DeclarativeRule.
- All 146 tests pass.
- memory.rs now contains 18 rules (was 10).

## [0.7.1] - 2025-12-14

### Added
- **Shared Utilities Module**: Created `rules/utils.rs` with reusable string literal handling utilities.
  - `StringLiteralState`: State machine for tracking string literal boundaries across lines.
  - `strip_string_literals()`: Replaces string content with spaces while preserving line length.
  - `collect_sanitized_matches()`: Helper for pattern matching that ignores string literal content.
  - 5 unit tests for utility functions.

### Changed
- **Rule Migration**: Migrated 8 additional rules from `lib.rs` to modular structure.
  - `rules/concurrency.rs`: Added `UnsafeSendSyncBoundsRule` (RUSTCOLA015).
  - `rules/ffi.rs`: Added `FfiBufferLeakRule` (RUSTCOLA016).
  - `rules/code_quality.rs`: Added `OverscopedAllowRule` (RUSTCOLA072), `CommentedOutCodeRule` (RUSTCOLA092).
  - Previously migrated: `UnderscoreLockGuardRule`, `BroadcastUnsyncPayloadRule`, `PanicInDropRule`, `UnwrapInPollRule`.
- **Codebase Reduction**: `lib.rs` reduced from ~22,936 to ~21,236 lines (~1,700 lines removed).

### Technical
- Total rule modules: 10 categories + 1 utils module.
- Test count increased from 138 to 143 (utils tests included).
- Updated `PRODUCTION_RELEASE_PLAN.md` with Phase 1.2 progress notes.

## [0.7.0] - 2025-12-14

### Fixed
- **Test Suite**: Fixed all 6 failing tests, achieving 100% test pass rate (138/138).
  - `test_field_sensitive_helpers`: Fixed field parser to support simple dot notation (`_3.0`) in addition to MIR-style (`(_1.0: Type)`).
  - `detects_command_sink` / `full_taint_analysis`: Updated test MIR to use realistic `Command::arg::<&str>` syntax matching actual MIR output.
  - `allocator_mismatch_rule_detects_mixed_allocators`: Provided mock MIR functions with proper allocation/deallocation patterns.
  - `builtin_security_rules_fire`: Updated to use current rule IDs (RUSTCOLA073, RUSTCOLA078) after module migration.
  - `untrusted_env_rule_detects_env_call`: Added complete taint flow (source → sink) to match upgraded taint analysis behavior.

### Changed
- **Field-Sensitive Parsing**: Enhanced `contains_field_access()` and `parse_field_access()` to recognize both:
  - MIR-style: `(_1.0: Type)`
  - Simple dot notation: `_3.0`, `_1.2`
- **Taint Analysis Tests**: Aligned test cases with realistic MIR syntax including generic type parameters.

### Technical
- Production Release Plan documented in `docs/PRODUCTION_RELEASE_PLAN.md`.
- All version numbers synchronized across workspace (cargo-cola, mir-extractor, mir-advanced-rules).

## [0.6.1] - 2025-12-14

### Fixed
- **SARIF Output**: Fixed GitHub Code Scanning error "artifact location cannot be parsed to a file path".
  - `artifactLocation.uri` now always points to a file, not a directory.
  - When span is unavailable, `artifact_uri_for` extracts path from location-style function names (e.g., `build.rs:15`).
  - Falls back to `src/lib.rs` or `src/main.rs` instead of crate root directory.

## [0.6.0] - 2025-12-14

### Changed
- **Rules Migration Complete**: Migrated additional rules to modular structure.
  - `rules/web.rs`: Created with TlsVerificationDisabledRule (RUSTCOLA084), AwsS3UnscopedAccessRule (RUSTCOLA085), plus existing TLS/CORS/cookie rules.
  - `rules/supply_chain.rs`: Created with RustsecUnsoundDependencyRule, YankedCrateRule, CargoAuditableMetadataRule.
  - `rules/resource.rs`: Added HardcodedHomePathRule (RUSTCOLA014), BuildScriptNetworkRule (RUSTCOLA097).
  - `rules/ffi.rs`: Added CtorDtorStdApiRule (RUSTCOLA059).
  - `rules/memory.rs`: Upgraded with sophisticated string literal stripping and self-analysis skip logic.

### Technical
- 10 categorized rule modules now active (crypto, memory, concurrency, ffi, input, resource, code_quality, injection, web, supply_chain).
- 29 complex dataflow/source-level rules remain in lib.rs (require taint tracking, syn parsing).

## [0.5.2] - 2025-12-13

### Changed
- **CI Fix**: Made `mir-advanced-rules` an optional feature (`advanced-rules`) to resolve CI hangs.
  - Default feature enabled for normal builds (includes ADV001-ADV009 rules).
  - CI builds with `--no-default-features` to exclude advanced-rules crate compilation.
  - Wrapped all advanced-rules code with `#[cfg(feature = "advanced-rules")]`.
- **Rule Migration Progress**: Continued modular refactoring of security rules.
  - `rules/input.rs`: 9 input validation rules migrated (CleartextEnvVar, EnvVarLiteral, InvisibleUnicode, UntrimmedStdin, InfiniteIterator, DivisionByUntrusted, InsecureYamlDeserialization, UnboundedRead, InsecureJsonTomlDeserialization).
  - `rules/resource.rs`: 8 resource management rules migrated (SpawnedChildNoWait, PermissionsSetReadonlyFalse, WorldWritableMode, OpenOptionsMissingTruncate, UnixPermissionsNotOctal, OpenOptionsInconsistentFlags, AbsolutePathInJoin, CtorDtorStdApi).
  - `rules/code_quality.rs`: 6 code quality rules migrated (CrateWideAllow, MisorderedAssertEq, TryIoResult, LocalRefCell, UnnecessaryBorrowMut, DeadStoreArray).
  - Total: 49 rules now in modular structure (crypto: 8, memory: 10, concurrency: 4, ffi: 4, input: 9, resource: 8, code_quality: 6).

### Technical
- Added `INPUT_SOURCE_PATTERNS` constant to `rules/input.rs` for shared taint source detection.
- Updated `rules/mod.rs` to export all new rule modules.

## [0.5.1] - 2025-12-13

### Changed
- **Rule Migration Progress**: Continued modular refactoring of security rules.
  - `rules/concurrency.rs`: 4 concurrency rules migrated (NonThreadSafeTest, BlockingSleepInAsync, BlockingOpsInAsync, MutexGuardAcrossAwait).
  - `rules/ffi.rs`: 4 FFI safety rules migrated (AllocatorMismatchFfi, UnsafeFfiPointerReturn, PackedFieldReference, UnsafeCStringPointer).
  - Total: 26 rules now in modular structure (crypto: 8, memory: 10, concurrency: 4, ffi: 4).
- **CI Improvements**: Temporarily excluded `mir-advanced-rules` from cola-ci.yml self-analysis to resolve hanging builds.

### Technical
- Added `filter_entry` helper to `rules/mod.rs` for consistent directory traversal filtering.
- Updated module exports in `rules/mod.rs` for new rule structs.

## [0.5.0] - 2025-12-13

### Changed
- **Major Refactoring**: Restructured codebase for maintainability and modularity.
  - Created `mir-extractor/src/rules/` module hierarchy with categorized rule files.
  - `rules/crypto.rs`: 8 cryptographic rules (MD5, SHA1, weak hashing, hardcoded keys, timing attacks, weak ciphers, predictable randomness).
  - `rules/memory.rs`: 10 memory safety rules (transmute, uninit, set_len, raw pointers, null pointer transmute, ZST arithmetic).
  - `rules/injection.rs`, `rules/concurrency.rs`, `rules/ffi.rs`, `rules/input.rs`, `rules/resource.rs`, `rules/code_quality.rs`: Module structure for ongoing rule migration.
- **CI Improvements**: Added 30-minute timeout and excluded `mir-extractor` (28k LOC) from self-analysis to prevent CI hangs.

### Technical
- Reduced `lib.rs` from 23k LOC monolith toward modular architecture.
- Added shared helper functions in `rules/mod.rs` for pattern matching and string processing.
- Preserved backward compatibility - existing rules continue to function during incremental migration.

## [0.3.1] - 2025-12-13

### Changed
- **Version Standardization**: Unified version numbers across all crates (cargo-cola, mir-extractor, mir-advanced-rules) to 0.3.1.
- **CI/CD Improvements**: Optimized `cola-ci.yml` workflow to use pre-built binary, eliminating double compilation.
- **CodeQL Configuration**: Simplified path exclusions with blanket `examples/**` pattern.

### Removed
- **Legacy Examples**: Deleted obsolete `examples/hir-typeck-repro/` and `examples/parse-pattern-test/` directories.
- **Generated Artifacts**: Cleaned up stale MIR dump files from `examples/suppression-test/mir_dump/`.

## [0.3.0] - 2025-12-13

### Added
- **YAML Suppression**: Added support for suppressing findings via YAML configuration files (loaded with `--rulepack`), allowing suppressions without modifying source code.

## [0.2.3] - 2025-12-12

### Fixed
- **CI/CD Stability**: Removed excessive debug logging that was causing CI build failures.
- **Code Cleanup**: Fixed numerous unused code warnings in `mir-extractor` to ensure clean builds.

### Documentation
- **User Guide**: Added `docs/USER_GUIDE.md` with concise instructions on features like False Positive Suppression.

## [0.2.2] - 2025-12-12

### Added
- **False Positive Suppression**: Added support for `// rust-cola:ignore RuleID` comments to suppress findings. This works by matching the finding's location with the ignore comment on the same or previous line.
- **MIR Span Extraction**: Improved MIR extraction to include source code spans (`-Zmir-include-spans`), enabling accurate mapping of findings to source lines for suppression and reporting.

### Fixed
- **macOS Dynamic Linking**: Resolved `dyld` library path issues when running with the `hir-driver` feature on macOS.

## [0.2.1] - 2025-12-12

### Added
- **Mutable Reference Propagation**: Implemented Phase 3.5.2. The analyzer now correctly tracks taint when a function modifies its arguments (e.g., `dest.push_str(tainted_src)`).
- **ParamToParam Propagation**: Added support for generating and handling `ParamToParam` rules in function summaries, enabling detection of taint flow between function parameters.
- **Standard Library Heuristics**: Added explicit taint propagation models for `String::push_str`, `Vec::push`, and `Vec::append` to handle these common patterns without requiring MIR for std.

### Changed
- **Analysis Engine**: Updated `PathAnalysisResult` to track `final_taint` states of variables at the end of function execution.

## [0.2.0] - 2025-12-12

### Added
- **Async Taint Propagation**: Major improvement to taint analysis (Phase 3.6). Now correctly tracks data flow through `async` functions and generators by resolving state machine aliases. This enables accurate security analysis for async-heavy frameworks like Tokio, Axum, and Actix.
- **ADV009**: Integer Overflow Rule - Detects untrusted input flowing to arithmetic operations without overflow protection.

### Changed
- **Analysis Engine**: Enhanced `path_sensitive.rs` with alias tracking for MIR generator lowering.

## [0.1.1] - 2025-12-12

### Added
- **Inter-procedural Taint Propagation**: Implemented Phase 3.3, enabling taint tracking across function boundaries using function summaries.
- **ADV008**: Uncontrolled Allocation Size Rule (Advanced Dataflow) - Detects untrusted input flowing to allocation APIs without bounds checking.
- **cargo-audit Integration**: New `--with-audit` flag to include dependency vulnerability scanning in reports.
- **LLM Workflow Improvements**: Added `--output-for-llm` alias and enhanced LLM prompt with rigorous false negative prevention guidelines.

### Changed
- **Documentation**: Updated README with correct rule count (102 rules), manual LLM workflow instructions, and updated options table.
- **Rule Count**: Corrected rule count to include 93 core rules + 9 advanced rules.

---

## [0.1.0] - 2025-12-08

First versioned release of Rust-cola, an LLM-integrated static application security testing (SAST) tool for Rust.

### Highlights
- **87 security rules** across memory safety, cryptography, injection, concurrency, and FFI
- **Three-tier analysis architecture**: MIR heuristics (85 rules), source analysis (2 rules), HIR semantic analysis
- **Inter-procedural taint analysis** tracking data flow across function boundaries
- **LLM integration** for intelligent false positive filtering and remediation suggestions
- **SARIF output** for CI/CD integration

### Security Rules by Category
- **Memory Safety**: Box::into_raw leaks, transmute misuse, Vec::set_len, MaybeUninit::assume_init, slice::from_raw_parts
- **Cryptography**: MD5/SHA-1/RIPEMD/CRC detection, weak ciphers (DES/RC4), hardcoded keys, predictable randomness
- **Injection**: SQL injection, path traversal, command injection, regex injection, YAML/JSON/TOML deserialization
- **Network**: SSRF detection, disabled TLS verification, HTTP URLs, unscoped AWS S3 access
- **Concurrency**: Unsafe Send/Sync, mutex guards, panic in Drop, unwrap in Poll
- **FFI**: Allocator mismatches, dangling CString pointers, blocking calls in async

### New Rules (December 2025)
- **RUSTCOLA091**: Insecure JSON/TOML deserialization - 100% recall (10/10)
- **RUSTCOLA090**: Unbounded read_to_end - Memory exhaustion via unlimited reads
- **RUSTCOLA089**: YAML deserialization attacks - Billion laughs, deep nesting
- **RUSTCOLA088**: Server-Side Request Forgery (SSRF) - 100% recall (12/12)
- **RUSTCOLA087**: SQL injection - 100% recall (10/10)
- **RUSTCOLA086**: Path traversal - 100% recall (10/10)

### LLM Integration
- `--llm-report` flag for AI-assisted analysis
- Supports OpenAI, Anthropic Claude, and Ollama
- False positive filtering, CVSS estimates, attack scenarios, code fixes
- `--report` for standalone human-readable reports without LLM

### Output Formats
- JSON findings (default)
- SARIF for GitHub Code Scanning and CI/CD
- LLM-enhanced reports with remediation guidance

---

## [Unreleased]

_No changes yet._

## [0.1.1] - 2025-12-10

### Highlights
- **103 security rules** across memory safety, cryptography, injection, concurrency, and FFI (up from 87 in 0.1.0).
- **Six new advanced MIR rules** (ADV002–ADV007) covering unsafe JSON/TOML and binary deserialization, regex catastrophic backtracking, template injection, async `Send` violations, and span guards held across awaits.
- **30 regression tests** in `mir-advanced-rules`, ensuring coverage for the new analyzers alongside existing flows.

### Added

#### Advanced Rules
- **ADV002 – Insecure JSON/TOML deserialization**: Tracks untrusted sources flowing into `serde_json::from_*` and `toml::from_*` sinks, exempting flows with explicit size checks. Shipped with dedicated MIR analyzer and regression coverage for env-based, constant, and sanitized scenarios.
- **ADV003 – Insecure binary deserialization**: Flags tainted data reaching `bincode::deserialize*` and `postcard::from_bytes*` sinks while recognizing length guards. Includes postcard socket coverage and len-check sanitization tests.
- **ADV004 – Regex denial-of-service**: Detects catastrophic backtracking patterns (nested quantifiers, dot-star loops) compiled via `regex::Regex::new`, with regression tests for `(a+)+` and `(.*)+` cases.
- **ADV005 – Template injection**: Taints environment/request-derived strings through response builders (`warp::reply::html`, `axum::response::Html`) and flags flows lacking HTML escaping, while permitting sanitizers like `html_escape::encode_safe` and constant bodies.
- **ADV006 – Unsafe Send across async boundaries**: Tracks non-Send allocations (Rc/RefCell) flowing into multi-threaded async executors such as `tokio::spawn` / `async_std::task::spawn`, emitting findings when captured values are not sanitized by `Arc` or confined to `spawn_local`.
- **ADV007 – Span guard awaiting**: Flags tracing span guards that remain live across `.await`, ensuring instrumentation scopes end before suspension points while permitting guards dropped prior to awaiting.

#### Testing
- Expanded `mir-advanced-rules` unit suite to **30 tests**, adding coverage for regex DoS, template injection, async Send boundary, and span guard await flows alongside the new JSON/TOML and binary cases (all passing).

#### Documentation
- Updated `README.md` to reflect **103 shipped rules** and highlight unsafe JSON/TOML/binary deserialization, regex DoS, template injection, async Send boundary, and span guard await detection.
- Annotated `advanced_rule_implementation_plan.md` with completion notes for Rules 43–49.
- Marked Rules 43–49 as shipped in `docs/security-rule-backlog.md` (ADV002 – ADV007 entries).

### Added - November 12, 2025

#### New Security Rules (3)
- **RUSTCOLA042**: Cookie without Secure attribute - Detects cookies created without the Secure flag, allowing transmission over unencrypted HTTP (High severity)
- **RUSTCOLA043**: Overly permissive CORS wildcard - Detects CORS configurations allowing any origin (*), enabling CSRF attacks (High severity)
- **RUSTCOLA044**: Observable timing discrepancy in secret comparison - Detects non-constant-time comparisons of passwords, tokens, and HMACs vulnerable to timing attacks (High severity)

**Total Rules: 48** (up from 45)

#### Documentation
- Added `docs/research/rule-detection-levels.md` - Comprehensive taxonomy of detection sophistication levels (Heuristic → Path-Sensitive)
- Updated `docs/real-world-testing-influxdb.md` with Phase 3.3 validation results:
  - Analyzed `influxdb3_processing_engine` (Python processing engine)
  - Found 69 total findings including 43 critical lock guard bugs (RUSTCOLA030)
  - Documented systematic concurrency bug in production InfluxDB code

#### Testing & Validation
- Added `examples/security-rules-demo/` with test cases for new rules
- Validated new rules: 4/4 detections (1 CORS wildcard, 3 timing attacks)
- Zero false positives on safe code patterns
- Real-world validation on InfluxDB production codebase

### Changed - November 12, 2025
- Enhanced real-world testing documentation with detailed lock guard bug analysis
- Expanded Phase 3 validation to include Python processing engine crate

---

## Phase 3.3 - November 11, 2025

### Added - Inter-Procedural Taint Tracking

#### Core Features
- **Inter-procedural dataflow analysis** - Tracks taint across function boundaries
- **Bidirectional exploration** - Backward from sinks, forward verification
- **Multi-hop flow detection** - Detects vulnerabilities spanning 3+ function calls
- **Function summaries** - Caches source/sink/propagation information

#### Performance Improvements
- RUSTCOLA006 (Command Injection) upgraded to inter-procedural analysis
- **Detection Rate**: 100% recall (11/11 vulnerable flows detected)
- **False Positive Rate**: 15.4% (2/13 safe flows flagged)
- **Flow Depth**: Successfully detects 3-level call chains

### Documentation
- Added `docs/phase3-interprocedural-results.md` - Complete Phase 3.3 validation
- Created `docs/research/hir-extraction-plan.md` - HIR integration roadmap
- Updated all Phase 3 progress tracking documents

### Commits
- `895781c` - Phase 3.3: Inter-procedural taint tracking foundation
- `23c0e8e` - Add test cases for multi-hop vulnerabilities
- `7a891bf` - Implement backward exploration from sinks
- `c5d42a9` - Add forward verification pass
- `fca4b14` - Phase 3.3 complete: 100% recall, 15.4% FP rate

---

## Phase 3.2 - November 10, 2025

### Added - Real-World Validation

#### InfluxDB Analysis (influxdb3_authz)
- First production codebase analysis: InfluxDB v3.7.0-nightly
- **Results**: Zero RUSTCOLA006 findings (no command injection vulnerabilities)
- **False Positive Rate**: 0% (no spurious warnings on production code)
- **Analysis Time**: 13 minutes for 427 LOC + dependencies
- **Validation**: Confirms Phase 2 sanitization detection works on real code

#### Toolchain Improvements
- Fixed forced nightly version compatibility issues
- Now respects target project's `rust-toolchain.toml` and `rustup override`
- Works seamlessly with any Rust project regardless of toolchain version

### Documentation
- Created `docs/real-world-testing-influxdb.md` - Complete analysis report
- Documented toolchain compatibility fixes
- Added lessons learned from production analysis

---

## Phase 2 - November 8-9, 2025

### Added - Advanced Sanitization Detection

#### Dataflow Analysis
- Control-flow-aware sanitization tracking
- Loop-based sanitization detection
- Early return pattern recognition
- Escape function detection (Path::canonicalize, shellwords::split, etc.)

#### Performance Improvements
- RUSTCOLA006 (Command Injection):
  - **Before**: 95% false positive rate (19/20 findings were false alarms)
  - **After**: 43% false positive rate (9/21 findings)
  - **Improvement**: 52 percentage point FP reduction

#### Test Coverage
- Added `cargo-cola/tests/cli.rs` - End-to-end CLI testing
- 4 test cases covering vulnerable and safe patterns
- Validation of sanitization detection accuracy

### Documentation
- Created `docs/phase2-cfg-sanitization-results.md` - Complete Phase 2 summary
- Added architecture diagrams for dataflow analysis
- Documented all sanitization patterns detected

### Commits
- `e40c22d` - Phase 2 complete: CFG-based sanitization detection
- Multiple commits implementing loop detection, early returns, escape functions

---

## Phase 1 - November 2025 (Initial Implementation)

### Added - Foundation

#### Core Infrastructure
- MIR (Mid-level Intermediate Representation) extraction via rustc
- Basic taint tracking for command injection (RUSTCOLA006)
- 45 security rules (RUSTCOLA001-045):
  - Memory safety (Box::into_raw, transmute, Vec::set_len, etc.)
  - Unsafe operations (mem::uninitialized, NonNull::new_unchecked)
  - Cryptographic issues (MD5, SHA1, hardcoded keys)
  - TLS/Certificate validation bypasses
  - File system security (world-writable permissions, hardcoded paths)
  - Concurrency bugs (static mut, underscore lock guards, mem::forget guards)
  - Async runtime issues (blocking sleep in async)
  - RustSec-inspired rules (Content-Length DoS, Broadcast !Sync, etc.)

#### CLI Tool
- `cargo-cola` - Cargo subcommand for security analysis
- MIR extraction with caching
- JSON and SARIF output formats
- Rulepack support (YAML-based custom rules)

#### Analysis Engine
- Rule engine with 48 built-in security rules
- Declarative rule support via YAML rulepacks
- Finding deduplication and severity classification
- Source span tracking for precise error locations

### Documentation
- README.md with quickstart guide
- Rule documentation for all 48 rules
- Architecture overview

---

## [0.1.0] - Initial Release (Conceptual)

### Added
- Project structure
- Basic Rust security analysis framework
- MIR-based analysis foundation

---

## Legend

- **Added**: New features, rules, or capabilities
- **Changed**: Modifications to existing functionality
- **Deprecated**: Features marked for removal
- **Removed**: Deleted features
- **Fixed**: Bug fixes
- **Security**: Security-related changes

---

**Note**: This changelog was created retrospectively on November 12, 2025 to track the evolution of Rust-COLA through its development phases. Earlier commits may not have been documented in real-time.
