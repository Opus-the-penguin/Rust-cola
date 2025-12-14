# Rust-cola Production Release Plan

**Date:** December 14, 2025  
**Current Version:** 0.7.1  
**Target Version:** 1.0.0  
**Status:** Phase 1.2 Nearing Completion

This document outlines the roadmap to achieve a production-ready release of Rust-cola. Completing these phases will yield a **Release Candidate (RC)** suitable for general availability.

---

## Executive Summary

Rust-cola v0.7.1 has reached significant maturity with 102 security rules and a three-tier analysis architecture. To achieve production readiness, we must:

1. **Stabilize** - Fix failing tests and complete architectural refactoring
2. **Close Gaps** - Implement Rust-specific vulnerability detection (async, lifetimes, panic safety)
3. **Improve Quality** - Enhance precision/recall through field-sensitive analysis
4. **Deliver Value** - Ensure excellent first-run experience with rich outputs

---

## Current State (v0.7.1)

| Metric | Value |
|--------|-------|
| **Total Rules** | 102 |
| **Test Status** | 143 passed, 0 failed ✅ |
| **Core Codebase** | ~21K LOC (mir-extractor/lib.rs) |
| **Rule Modules** | 10 categories + utils |

### Three-Tier Architecture

| Tier | Type | Count | Description |
|------|------|-------|-------------|
| **Tier 1** | MIR Heuristics | 93 | Fast pattern-matching on compiler IR |
| **Tier 2** | Source Analysis | 2 | AST-based checks (commented code, attributes) |
| **Tier 3** | Advanced Dataflow | 7 | Inter-procedural taint tracking, CFG-sensitive |

### Rule Distribution

**Organized Modules (76 rules):**

| Module | Rules | Coverage |
|--------|-------|----------|
| `crypto.rs` | 8 | MD5, SHA1, hardcoded keys, timing, weak ciphers, PRNG |
| `memory.rs` | 10 | Transmute, uninit, set_len, raw pointers, Box::into_raw |
| `concurrency.rs` | 9 | Mutex guards, async blocking, Send/Sync, lock guards, panic safety |
| `ffi.rs` | 6 | Allocator mismatch, CString, packed fields, repr(C), buffer leaks |
| `input.rs` | 9 | Env vars, stdin, unicode, deserialization, division |
| `resource.rs` | 9 | File permissions, open options, iterators, paths |
| `code_quality.rs` | 8 | Dead stores, assertions, crate-wide allow, RefCell, commented code |
| `web.rs` | 10 | TLS, CORS, cookies, passwords, logging, AWS S3 |
| `supply_chain.rs` | 3 | RUSTSEC, yanked crates, auditable |
| `injection.rs` | 5 | Command, SQL, path traversal, SSRF |
| `utils.rs` | - | Shared utilities (strip_string_literals, StringLiteralState) |

**Complex Rules in lib.rs:** ~20 rules (dataflow-dependent, require inter-procedural context)

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

### 2.1 Async/Await Correctness (High Priority)

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| ADV003 | Non-Send types across `.await` | Data races | ✅ Complete |
| NEW | `select!` cancellation safety | Resource leaks | ❌ To implement |
| NEW | Executor starvation detection | DoS | ❌ To implement |
| NEW | Async drop correctness | Resource leaks | ❌ To implement |
| NEW | Spawned task panic propagation | Silent failures | ❌ To implement |

**Implementation Notes:**
- Requires async boundary tracking in MIR
- Must understand executor semantics (tokio, async-std, smol)

### 2.2 Lifetime/Borrow Escape Bugs (Medium Priority)

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| NEW | Returned reference to local | UAF | ❌ To implement |
| NEW | Closure capturing escaping refs | UAF | ❌ To implement |
| RUSTCOLA096 | `unsafe { &*ptr }` outliving pointee | UAF | ⚠️ Partial |
| NEW | Self-referential struct creation | UAF | ❌ To implement |

**Implementation Notes:**
- Leverage rustc's lifetime information where available
- Focus on `unsafe` blocks where borrow checker is bypassed

### 2.3 Panic Safety (Medium Priority)

| Rule ID | Name | Risk | Status |
|---------|------|------|--------|
| NEW | Panic in FFI boundary | UB | ❌ To implement |
| NEW | Panic while holding lock | Poison/Deadlock | ❌ To implement |
| NEW | `unwrap()`/`expect()` in hot paths | Crash | ❌ To implement |
| NEW | Panic in Drop impl | Double panic | ❌ To implement |

**Implementation Notes:**
- Identify FFI boundaries via `extern "C"` functions
- Track lock guard lifetimes and potential panic points

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
- [ ] All tests passing (0 failures)
- [ ] All rules migrated to modules (lib.rs < 5K LOC infrastructure only)
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
| Total Rules | 102 | 115+ |
| Test Pass Rate | 95.6% (132/138) | 100% |
| Rust-Specific Rules | ~20 | 35+ |
| Average Scan Time (medium crate) | TBD | <30s |
| Fast Mode Scan Time | N/A | <5s |
| False Positive Rate | TBD | <15% |

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

## Next Steps

1. **Immediate:** Begin Phase 1.1 - Fix the 6 failing tests
2. **This Week:** Complete Phase 1.2 - Migrate remaining lib.rs rules
3. **Next Sprint:** Start Phase 2.1 - Async correctness rules

---

## Document History

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2025-12-14 | 1.0 | GitHub Copilot | Initial production release plan |
