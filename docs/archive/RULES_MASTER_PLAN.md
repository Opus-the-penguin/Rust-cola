# Rust-Cola Rules Master Plan

**Date:** December 13, 2025
**Version:** 0.5.0
**Status:** Active

This document serves as the single source of truth for Rust-cola's rule implementation status, roadmap, and backlog. It consolidates previous planning documents into a unified view.

## 1. Executive Summary

**Current Status:**
- **Total Rules:** 102
- **Architecture:** Three-Tier Analysis Engine
- **Latest Release:** v0.5.0 (December 13, 2025)

Rust-cola has reached a high level of maturity with a robust set of 102 security rules covering memory safety, cryptography, injection, concurrency, and FFI. The system leverages a hybrid approach combining fast heuristics with deep semantic analysis.

### Architecture Overview

| Tier | Type | Count | Description |
|------|------|-------|-------------|
| **Tier 1** | **MIR Heuristics** | 93 | Fast, pattern-matching rules on compiler IR. Covers standard vulnerabilities (crypto, FFI, basic injection). |
| **Tier 2** | **Source Analysis** | 2 | AST-based checks for issues visible in source code (e.g., commented-out code, attributes). |
| **Tier 3** | **Advanced Dataflow** | 7 | Deep semantic analysis including inter-procedural taint tracking, async dataflow, and control-flow sensitivity. |

---

## 2. Active Roadmap (Next 3 Months)

### Phase 1: Deep Hardening (In Progress)
Focus on improving recall and reducing false positives for existing rules.

| Rule | Goal | Approach | Status |
|------|------|----------|--------|
| **RUSTCOLA053** (stdin no trim) | 10% FP | Convert from heuristic to dataflow | ✅ Complete |
| **RUSTCOLA054** (Infinite iterators) | 90%+ Recall | Detect loop break statements | ✅ Complete |
| **RUSTCOLA057** (Unnecessary borrow_mut) | 80%+ Recall | Full mutation tracking in MIR | ✅ Complete |
| **RUSTCOLA080** (Unchecked index) | 90%+ Recall | Better env::var taint propagation | ✅ Complete |

### Phase 2: Tier 3 Advanced Dataflow (Q1 2026)
Continuing the implementation of the inter-procedural analysis engine.

*   **Phase 3.3: Summary Application** (Completed)
    *   Apply function summaries at call sites to propagate taint.
    *   Handle return values and mutable reference modifications.
    *   **Status:** ✅ Complete (Dec 12, 2025)
*   **Phase 3.4: Recursion Handling** (In Progress)
    *   Detect and handle recursive cycles in the call graph.
    *   Implement fixed-point iteration for dataflow convergence.
*   **Phase 3.5: Field Sensitivity** (In Progress)
    *   Track taint at the struct field level (e.g., `user.name` vs `user.id`).
    *   Currently, taint on a struct taints all fields (coarse-grained).
    *   **Status:** 🚧 In Progress (Phase 3.6 Design)

### Phase 3: Advanced Rules (Phase 4)
Breaking ground on rules requiring new infrastructure.

*   **Uncontrolled Allocation Size** (In Progress)
    *   **Status:** 🚧 In Progress (ADV008 implemented)
*   **Regex Denial of Service** (In Progress)
    *   **Status:** 🚧 In Progress (ADV004 implemented)

---

## 3. Rule Backlog

Prioritized list of new rules requiring advanced analysis infrastructure.

### High Priority (Q1 2026)

1.  **Uncontrolled Allocation Size**
    *   **Risk:** DoS via memory exhaustion.
    *   **Detection:** Taint tracking from untrusted sources to `Vec::with_capacity`, `String::with_capacity`, etc.
    *   **Feasibility:** Advanced (Requires integer range analysis).

2.  **Regex Denial of Service (ReDoS)**
    *   **Risk:** DoS via catastrophic backtracking.
    *   **Detection:** Analyze regex patterns for nested quantifiers (e.g., `(a+)+`).
    *   **Feasibility:** Advanced (Requires pattern complexity analysis).

3.  **Template Injection**
    *   **Risk:** XSS / RCE.
    *   **Detection:** Track untrusted data into web framework response builders (e.g., `warp::reply::html`) without escaping.
    *   **Feasibility:** Medium (Framework-specific sinks).

### Medium Priority (Q2 2026)

4.  **Dangling Pointer Use-After-Free**
    *   **Risk:** Memory corruption.
    *   **Detection:** Track raw pointer creation, aliasing, and dereference after owner invalidation.
    *   **Feasibility:** Very Hard (Requires deep alias analysis).

5.  **Unsafe Send Across Async Boundaries**
    *   **Risk:** Data races.
    *   **Detection:** Flag non-`Send` types (Rc/RefCell) captured by multi-threaded executors (`tokio::spawn`).
    *   **Feasibility:** Hard (Requires async boundary tracking).

6.  **Cleartext Storage/Transmission**
    *   **Risk:** Data exposure.
    *   **Detection:** Track sensitive data (marked via heuristics or taint) to DB inserts or non-TLS network writes.
    *   **Feasibility:** Advanced.

### Low Priority / Research

7.  **Pointer Arithmetic on ZSTs** (Hardening)
    *   Improve detection for custom empty structs/enums.
8.  **Ptr::copy Overlap**
    *   Ensure non-overlapping regions for `copy_nonoverlapping`.

---

## 4. Completed Milestones (2025)

*   **Dec 13:** v0.5.0 Release (Major refactoring - modular rules architecture).
*   **Dec 13:** v0.3.1 Release (Version standardization, CI/CD improvements, legacy cleanup).
*   **Dec 13:** v0.3.0 Release (YAML Suppression).
*   **Dec 12:** Phase 3.3 Inter-procedural Taint Propagation complete.
*   **Dec 12:** Phase 3.5.2 Mutable Reference Propagation complete.
*   **Nov 25:** Phase 3.5.1 Branch-sensitive CFG analysis complete (0% FP).
*   **Nov 10:** Phase 2 Sanitization Detection complete.
*   **Oct 2025:** Phase 1 Taint Tracking Infrastructure complete.

## 5. Reference: Documentation Archive

Older planning documents have been moved to `docs/archive/` to maintain a clean workspace:
- `CURRENT-STATUS.md`
- `ROADMAP.md`
- `RULES-IMPROVEMENT-PLAN.md`
- `security-rule-backlog.md`
- `async-taint-fix.md`
- `phase3.5.2-mutable-ref-propagation-results.md`

Design documents are in `docs/design/`:
- `dangling-pointer-use-after-free-design.md`
- `phase3-interprocedural-design.md`
- `phase3.6-field-sensitive-design.md`
- `rustc-layout-api-solution.md`
- `tier3-hir-architecture.md`
