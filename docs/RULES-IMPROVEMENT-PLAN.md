# Rules Improvement Plan

**Date:** December 8, 2025  
**Status:** Active

This document outlines the prioritized plan for hardening existing rules and implementing new high-value security rules.

## Executive Summary

- **86 rules implemented** across memory safety, crypto, injection, concurrency
- **~17 rules with 100%/100% precision/recall** (Tier 1 quality)
- **~7 rules with good recall but gaps** (Tier 2 - needs hardening)
- **~4 rules with poor recall or FP issues** (Tier 3 - needs significant work)
- **~15-20 rules still on backlog** (Advanced analysis required)

## Phase 1: Quick Hardening Sprint

Low-effort fixes to improve existing rules. Target: 1-2 days.

### 1.1 RUSTCOLA062 - Weak Hashing Extended ✅

**Current:** 100% recall (8/8), 100% precision (0 FP after fix)  
**Issue:** ~~False positive on error message strings containing hash algorithm names (e.g., `"MD5 is not supported"`)~~  
**Fix:** Skip lines containing `const "` (string literals in MIR). Applied filter in `line_contains_weak_hash_extended()` to skip const string assignments and hex dump lines.  
**Effort:** Low (< 1 hour) - **COMPLETE**

### 1.2 RUSTCOLA064 - ZST Pointer Arithmetic

**Current:** 71% recall (5/7), 100% precision  
**Issue:** Misses custom empty struct/enum types without built-in type size info  
**Fix:** Integrate Tier 3 HIR type size queries to detect any type where `size_of::<T>() == 0`  
**Effort:** Low (1-2 hours) - infrastructure already exists in Tier 3

### 1.3 RUSTCOLA089 - YAML Deserialization

**Current:** 82% recall (9/11), 100% precision  
**Issue:** CLI arg flows and some interprocedural patterns not fully tracked  
**Fix:** Extend taint sources to include `clap` argument parsing patterns, improve interprocedural call chain following  
**Effort:** Medium (2-4 hours)

## Phase 2: New High-Value Rule

Implement one new high-impact rule using existing infrastructure.

### 2.1 RUSTCOLA091 - TOML/JSON Deserialization (Proposed)

**Rationale:** Extends YAML pattern to other serde formats. While TOML/JSON don't have YAML's billion laughs vulnerability, deeply nested structures can still cause stack overflow or memory exhaustion.

**Detection approach:**
- Sources: Same as YAML (env vars, CLI args, stdin, network, files)
- Sinks: `serde_json::from_str`, `serde_json::from_slice`, `serde_json::from_reader`, `toml::from_str`, `toml::de::from_str`
- Sanitizers: Depth limits, size limits, custom deserializers with bounds

**Test suite target:** 10 bad + 8 safe patterns  
**Target metrics:** 90%+ recall, 100% precision

**Effort:** Medium (4-6 hours) - reuses YAML infrastructure

## Phase 3: Deep Hardening (Future)

Rules requiring more significant work:

| Rule | Current | Target | Approach |
|------|---------|--------|----------|
| RUSTCOLA080 (Unchecked index) | 55% recall | 90%+ | Better env::var taint propagation |
| RUSTCOLA053 (stdin no trim) | 50% FP | 10% FP | Convert from heuristic to dataflow |
| RUSTCOLA054 (Infinite iterators) | 75% recall | 90%+ | Detect loop break statements |
| RUSTCOLA057 (Unnecessary borrow_mut) | 25% recall | 80%+ | Full mutation tracking in MIR |

## Phase 4: Advanced Rules (Backlog)

Rules requiring new infrastructure:

| Rule | Requirement | Priority |
|------|-------------|----------|
| Uncontrolled allocation size | Deep taint to allocator APIs | High |
| Regex denial-of-service | Pattern complexity analysis | High |
| Template injection | Web framework-specific sinks | Medium |
| Dangling pointer use-after-free | Lifetime/alias analysis | Low (very hard) |
| Unsafe Send across async | Async boundary tracking | Low (very hard) |

## Implementation Order

```
Week 1:
├── Phase 1.1: RUSTCOLA062 FP fix
├── Phase 1.2: RUSTCOLA064 Tier 3 integration
└── Phase 1.3: RUSTCOLA089 CLI arg improvement

Week 2:
└── Phase 2.1: RUSTCOLA091 TOML/JSON deserialization

Future:
├── Phase 3: Deep hardening of low-recall rules
└── Phase 4: Advanced analysis rules
```

## Success Metrics

| Metric | Current | Phase 1 Target | Phase 2 Target |
|--------|---------|----------------|----------------|
| Rules at 100%/100% | 17 | 19 | 20 |
| Rules at 90%+ recall | 24 | 27 | 28 |
| Rules with FP issues | 4 | 2 | 2 |
| Total implemented | 86 | 86 | 87 |

## Progress Log

### December 8, 2025
- Created improvement plan document
- Prioritized Phase 1 quick hardening sprint
- Identified RUSTCOLA091 as next new rule

---

*This is a living document. Update as rules are improved.*
