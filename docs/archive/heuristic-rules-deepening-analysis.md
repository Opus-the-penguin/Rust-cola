# Heuristic Rules Deepening Analysis

**Generated:** 2025-11-08  
**Current Status:** 40 rules implemented (20 heuristic, 14 dataflow, 6 metadata/policy)

## Overview

Of the 40 security rules currently implemented, **20 are heuristic-based** (string/pattern matching) and could benefit from dataflow analysis to reduce false positives and catch more sophisticated vulnerability patterns.

This document prioritizes which heuristic rules should be deepened first, based on:
1. **Security Impact** - How critical is the vulnerability class?
2. **False Positive Rate** - How noisy is the current implementation?
3. **Implementation Complexity** - How feasible is dataflow enhancement?
4. **Rule Maturity** - Is the current heuristic "good enough" or problematic?

---

## High Priority: Critical Security Rules Needing Dataflow

### 1. RUSTCOLA006 - untrusted-env-input ⚠️ CRITICAL

**Current Implementation:**
- Heuristic: Flags any `env::var()` or `env::var_os()` call
- No flow tracking: Can't tell if value is validated before use
- High false positives: Legitimate config reading triggers alerts

**Why Deepen:**
- Environment variables are a primary injection vector
- Current rule can't distinguish safe vs unsafe usage patterns
- Missing actual taint propagation to dangerous sinks (SQL, Command, Path)

**Required Enhancement:**
```rust
// Taint source: env::var, env::var_os, env::vars_os
let tainted = env::var("USER_INPUT")?;

// Safe patterns (should NOT alert):
if tainted.chars().all(|c| c.is_alphanumeric()) {
    use_validated_input(&tainted); // ✅ Validated
}

// Unsafe patterns (SHOULD alert):
Command::new("sh").arg(&tainted).spawn()?; // ❌ Direct to sink
fs::write(&tainted, data)?; // ❌ Path traversal risk
diesel::sql_query(&tainted)?; // ❌ SQL injection
```

**Dataflow Requirements:**
- Track tainted values from `env::var` through assignments, function args, and returns
- Identify sanitization points (allowlist checks, regex validation, type conversions)
- Recognize dangerous sinks: Command::arg, fs operations, SQL builders, regex patterns
- Report when tainted data reaches sinks without dominating sanitization

**Impact:** Transforms noisy rule into actionable security finding

---

### 2. RUSTCOLA007 - process-command-execution ⚠️ HIGH

**Current Implementation:**
- Heuristic: Flags any `Command::new()` or `Command::arg()` call
- No arg flow tracking: Can't tell if args are hardcoded or tainted
- Extremely high false positives: Every legitimate command triggers alert

**Why Deepen:**
- Command injection is a top OWASP vulnerability
- Current rule is essentially unusable due to noise
- Can't distinguish `Command::new("ls")` from `Command::new(&user_input)`

**Required Enhancement:**
```rust
// Safe patterns (should NOT alert):
Command::new("cargo").arg("build").spawn()?; // ✅ Hardcoded

// Suspicious patterns (SHOULD alert with evidence):
let cmd = format!("rm -rf {}", user_dir); // ❌ Concatenated
Command::new("sh").arg("-c").arg(&cmd).spawn()?; // ❌ Shell interpretation

let tool = env::var("TOOL")?;
Command::new(&tool).spawn()?; // ❌ Tainted executable name
```

**Dataflow Requirements:**
- Track tainted strings (env vars, user input, network data) into Command builder
- Flag when Command::new receives non-literal string
- Track format!/concat! operations that mix tainted + safe strings
- Recognize shell invocation patterns (`sh -c`, `bash -c`, `cmd /c`)
- Report Command::arg receiving tainted data without validation

**Relationship:** Extends RUSTCOLA006 (env taint) → RUSTCOLA007 (command sink)
**Impact:** Reduces noise by 90%+, catches real command injection

---

### 3. RUSTCOLA026 - nonnull-new-unchecked ⚠️ MEDIUM

**Current Implementation:**
- Heuristic: Flags any `NonNull::new_unchecked()` call
- No null check validation: Can't tell if ptr was validated first
- Medium false positives: Many legitimate unsafe blocks have proper checks

**Why Deepen:**
- Null pointer dereference is immediate UB
- Easy to verify with control flow analysis
- Dataflow enhancement is straightforward

**Required Enhancement:**
```rust
// Safe patterns (should NOT alert):
if !ptr.is_null() {
    let nn = NonNull::new_unchecked(ptr); // ✅ Dominated by null check
}

let nn = NonNull::new(ptr)?; // ✅ Safe constructor
let nn = ptr.as_ref().map(|r| NonNull::from(r))?; // ✅ Validated

// Unsafe patterns (SHOULD alert):
let nn = NonNull::new_unchecked(ptr); // ❌ No check
let nn = if rand() { NonNull::new_unchecked(ptr) } else { ... }; // ❌ Branch without check
```

**Dataflow Requirements:**
- Track pointer variables through assignments
- Identify dominating null checks: `!ptr.is_null()`, `ptr.as_ref()`, `NonNull::new()`
- Use control flow graph to prove checks dominate the unchecked call
- Report when no dominating check exists on any path

**Impact:** Reduces false positives by ~60%, catches actual UB

---

## Medium Priority: Reduce False Positives

### 4. RUSTCOLA003 - unsafe-usage

**Current:** Flags all `unsafe` blocks/functions  
**Enhancement:** Track specific unsafe invariants (aliasing, initialization, lifetime) and require doc comments

### 5. RUSTCOLA025 - static-mut-global

**Current:** Flags all `static mut` declarations  
**Enhancement:** Track actual concurrent accesses without synchronization

### 6. RUSTCOLA040 - panic-in-drop

**Current:** String matching for panic patterns in Drop impls  
**Enhancement:** Control flow analysis to prove panic is unreachable (behind if/match guards)

### 7. RUSTCOLA041 - unwrap-in-poll (just implemented!)

**Current:** String matching for unwrap/panic in Future::poll  
**Enhancement:** Control flow to prove Result is from non-failing source

---

## Low Priority: Informational Rules

### 8. RUSTCOLA001 - box-into-raw
**Enhancement:** Track pointer escapes across FFI boundaries

### 9. RUSTCOLA002 - std-mem-transmute
**Enhancement:** Type safety validation for transmute source/target

### 10. RUSTCOLA010 - mem-uninit-zeroed
**Enhancement:** Track which types require zero-init vs. arbitrary bytes

### 11. RUSTCOLA014 - hardcoded-home-path
**Enhancement:** Flow tracking (low security impact)

---

## Already Using Dataflow (No Changes Needed)

These rules already have sophisticated dataflow implementations:

- **RUSTCOLA008** - vec-set-len: Tracks initialization before set_len
- **RUSTCOLA009** - maybeuninit-assume-init: Tracks write before assume_init
- **RUSTCOLA015** - unsafe-send-sync-bounds: Trait bound analysis
- **RUSTCOLA016** - ffi-buffer-leak-early-return: Tracks alloc/free across returns
- **RUSTCOLA021** - content-length-allocation: Tracks tainted headers → allocation
- **RUSTCOLA022** - length-truncation-cast: Tracks cast flow to sinks
- **RUSTCOLA023** - tokio-broadcast-unsync-payload: Type analysis for Sync bounds
- **RUSTCOLA027** - mem-forget-guard: Tracks guard types through forget
- **RUSTCOLA030** - underscore-lock-guard: Pattern + type analysis
- **RUSTCOLA032** - OpenOptions missing truncate: Builder state tracking
- **RUSTCOLA035** - repr-packed-field-reference: Type + borrow analysis
- **RUSTCOLA036** - unsafe-cstring-pointer: Lifetime tracking
- **RUSTCOLA038** - vec-set-len-misuse: Initialization tracking
- **RUSTCOLA039** - hardcoded-crypto-key: Byte array dataflow

---

## Implementation Roadmap

### Phase 1: Foundation (Week 6-7)
**Goal:** Build taint tracking infrastructure

1. **Implement basic taint propagation engine**
   - Track variables through assignments, function calls, returns
   - Identify taint sources (env::var, network input, file reads)
   - Recognize common sinks (Command, fs, SQL, regex)
   - Handle simple control flow (if/else, match)

2. **Deepen RUSTCOLA006 (untrusted-env-input)**
   - Use taint engine to track env::var to sinks
   - Recognize validation patterns (allowlists, regex, type checks)
   - Reduce false positives from config reading
   - Validate on real-world crates

### Phase 2: Command Injection (Week 8)
**Goal:** Fix RUSTCOLA007's noise problem

1. **Extend taint tracking to Command builder**
   - Track tainted strings into Command::new and Command::arg
   - Detect format!/concat! operations
   - Flag shell invocation patterns
   - Test against command injection test suite

2. **Validate reduction in false positives**
   - Run on cargo-cola, mir-extractor (expect few findings)
   - Run on vulnerable-rust-examples (expect detections)
   - Measure precision/recall improvement

### Phase 3: Control Flow Analysis (Week 9-10)
**Goal:** Prove guards dominate dangerous calls

1. **Build CFG analysis for dominator checking**
   - Construct control flow graph from MIR basic blocks
   - Implement dominator tree algorithm
   - Track predicates (null checks, range checks, type checks)

2. **Deepen RUSTCOLA026 (nonnull-new-unchecked)**
   - Use CFG to validate null checks dominate call
   - Recognize safe alternatives (NonNull::new, as_ref)
   - Reduce false positives in unsafe blocks

3. **Apply to panic rules (RUSTCOLA040, RUSTCOLA041)**
   - Prove panic is unreachable via control flow
   - Recognize error handling patterns (early returns, guards)
   - Optional: Could wait for more false positive data

### Phase 4: Polish & Measure (Week 11)
**Goal:** Validate improvements and document

1. **Benchmark against real-world crates**
   - Run on top 100 crates.io downloads
   - Measure false positive rate before/after
   - Document precision/recall metrics

2. **Update documentation**
   - Mark deepened rules in security-rule-backlog.md
   - Create "Dataflow Analysis Guide" for contributors
   - Document taint sources, sinks, and sanitizers

---

## Success Metrics

### Before Deepening (Current Baseline)
- RUSTCOLA006: ~95% false positive rate (flags all env::var usage)
- RUSTCOLA007: ~98% false positive rate (flags all Command usage)
- RUSTCOLA026: ~60% false positive rate (flags all unchecked calls)

### After Phase 2 (Target)
- RUSTCOLA006: <20% false positive rate (only unsafe env→sink flows)
- RUSTCOLA007: <10% false positive rate (only tainted command args)

### After Phase 3 (Target)
- RUSTCOLA026: <10% false positive rate (only calls without checks)

---

## Dependencies & Blockers

### Required Infrastructure
- ✅ MIR extraction pipeline (already implemented)
- ✅ Pattern matching engine (already implemented)
- ❌ Taint propagation framework (needs implementation)
- ❌ Control flow graph builder (needs implementation)
- ❌ Dominator tree analysis (needs implementation)

### Optional Enhancements
- HIR extraction (Phase 1 in progress, see `docs/research/hir-extraction-plan.md`)
- Type inference (would help with trait bound analysis)
- Interprocedural analysis (for tracking across function boundaries)

### Constraints
- Must maintain <1.5x performance overhead vs. current heuristics
- Must not increase false negatives (keep catching current patterns)
- Must be maintainable by contributors without formal methods background

---

## Alternatives Considered

### Option A: Hybrid Approach (Recommended)
- Keep heuristic rules as "quick mode" (default)
- Add `--dataflow` flag for deeper analysis
- Let users choose speed vs. precision tradeoff

### Option B: Full Replacement
- Remove heuristic implementations entirely
- Always run dataflow (slower but more accurate)
- Risk: May slow down CI pipelines

### Option C: Heuristic + Dataflow Tiers
- Heuristic: Runs first, flags suspicious code
- Dataflow: Runs on flagged code only to confirm
- Best of both worlds but complex to implement

**Decision:** Start with Option A (hybrid), evaluate after Phase 2.

---

## Related Work

- **Semgrep:** Uses dataflow for taint tracking in Pro tier
- **CodeQL:** Full program analysis with QL queries (interprocedural)
- **Clippy:** Mostly heuristic, some dataflow (e.g., needless_borrow)
- **MIRAI:** Abstract interpretation (very sophisticated but slow)
- **Rudra:** MIR-based but focused on unsafe lifetime violations

**Positioning:** Rust-cola aims for CodeQL-level precision with Clippy-level performance.

---

## Conclusion

**Immediate Next Steps:**
1. ✅ Document this analysis (this file)
2. Implement basic taint propagation framework (3-5 days)
3. Deepen RUSTCOLA006 as proof-of-concept (2-3 days)
4. Measure false positive improvement and decide on full rollout

**Expected Impact:**
- Transforms 3 high-noise rules into actionable security findings
- Reduces overall false positive rate by ~40%
- Positions rust-cola as enterprise-ready security tool

**Timeline:** 6 weeks to complete Phases 1-3 (assuming 1 engineer)

---

_Last updated: 2025-11-08_
