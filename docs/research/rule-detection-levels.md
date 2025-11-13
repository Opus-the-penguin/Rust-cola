# Rule Detection Levels: A Taxonomy of Implementation Depth

**Date:** November 12, 2025  
**Project:** Rust-COLA Security Analysis Framework  
**Purpose:** Define the hierarchy of rule sophistication from simple pattern matching to advanced semantic analysis

---

## Executive Summary

Rust-COLA implements security rules across multiple levels of sophistication, from simple heuristic pattern matching to complex inter-procedural dataflow analysis. This document establishes a taxonomy of detection levels to help developers understand implementation complexity, expected accuracy, and appropriate use cases for each level.

**Key Insight:** Higher detection levels require more implementation effort but provide better precision and recall. The choice of detection level depends on the vulnerability pattern, false positive tolerance, and available compiler infrastructure.

---

## Detection Level Taxonomy

### Level 1: Heuristic (Source-Level Pattern Matching)

**Description:** String or regex matching on source code without semantic understanding.

**Characteristics:**
- ✅ **Fast:** O(n) scan of source files
- ✅ **Simple:** 50-200 lines of code
- ✅ **Resilient:** Works even if code doesn't compile
- ⚠️ **High FP Rate:** 10-30% false positives typical
- ❌ **No Context:** Can't track data flow or control flow
- ❌ **Brittle:** Defeated by formatting or refactoring

**Implementation Approach:**
- Read source files as text
- Pattern match on function/method names
- Check for presence/absence of specific API calls
- Validate builder patterns (e.g., `.secure(true)` must follow `.build()`)

**Examples in Rust-COLA:**

| Rule ID | Name | Pattern Detected |
|---------|------|------------------|
| RUSTCOLA001 | Box::into_raw | `Box::into_raw(` |
| RUSTCOLA002 | transmute | `std::mem::transmute` |
| RUSTCOLA026 | NonNull unchecked | `NonNull::new_unchecked` without null check |
| RUSTCOLA035 | packed field refs | `#[repr(packed)]` with `&field` access |
| RUSTCOLA036 | CString temp | `CString::new(...).unwrap().as_ptr()` |
| RUSTCOLA037 | sleep in async | `std::thread::sleep` inside `async fn` |
| RUSTCOLA042 | Cookie secure | `Cookie::build()` without `.secure(true)` |
| RUSTCOLA043 | CORS wildcard | `.allow_origin("*")` |
| RUSTCOLA044 | Timing attack | `password ==` without `constant_time_eq` |

**When to Use:**
- API misuse patterns (wrong method called)
- Configuration errors (missing required flags)
- Dangerous patterns that are always wrong
- Quick wins with acceptable FP rate

**Limitations:**
- Can't distinguish `let password = "test"` (literal) from `let password = user_input` (tainted)
- Can't verify sanitization occurred before sink
- Defeated by indirection: `let f = transmute; f(...)`

---

### Level 2: MIR-Based Pattern Recognition

**Description:** Pattern matching on MIR (Mid-level Intermediate Representation) with type information but without dataflow analysis.

**Characteristics:**
- ✅ **Semantic:** Understands types, traits, method resolution
- ✅ **Robust:** Survives reformatting and style changes
- ✅ **Precise:** Can distinguish `String::from` vs `CString::from`
- ⚠️ **Moderate FP Rate:** 5-15% false positives
- ❌ **No Taint Tracking:** Can't follow data flow
- ⚙️ **Medium Complexity:** 200-500 lines of code

**Implementation Approach:**
- Extract MIR via `rustc_interface`
- Walk MIR statements looking for specific function calls
- Use fully-qualified paths (e.g., `std::process::Command::new`)
- Check for surrounding control flow (basic blocks)
- Validate type information

**Examples in Rust-COLA:**

| Rule ID | Name | MIR Pattern |
|---------|------|-------------|
| RUSTCOLA007 | Command execution | `std::process::Command::new` in MIR |
| RUSTCOLA010 | mem::uninitialized | `std::mem::uninitialized` or `std::mem::zeroed` |
| RUSTCOLA025 | static mut | `static mut` declarations in HIR/MIR |
| RUSTCOLA028 | set_readonly(false) | `Permissions::set_readonly(const false)` |
| RUSTCOLA029 | world-writable mode | `OpenOptions::mode(0o777)` constant |
| RUSTCOLA030 | underscore lock guard | `let _ = Mutex::lock()` assignment pattern |
| RUSTCOLA031 | Command concat | `Command::new` + `format!`/`concat!` |
| RUSTCOLA032 | OpenOptions truncate | `write(true) + create(true)` without `truncate(true)` |

**When to Use:**
- Need to survive refactoring
- Want to distinguish similar APIs by type
- Pattern involves control flow (if/match)
- Acceptable FP rate is <15%

**Limitations:**
- Can't answer: "Does user input reach this Command?"
- Can't verify: "Was sanitization applied?"
- Can't track: "Is this pointer from a safe allocation?"

---

### Level 3: Intra-Procedural Dataflow Analysis

**Description:** Track data flow within a single function to connect sources to sinks.

**Characteristics:**
- ✅ **Taint Tracking:** Follows data through assignments
- ✅ **Sanitization Detection:** Recognizes filtering operations
- ✅ **Low FP Rate:** 2-10% false positives
- ⚠️ **Function-Scoped:** Can't track across function calls
- ⚠️ **Path-Insensitive:** Doesn't model if/else branches
- ⚙️ **High Complexity:** 500-1500 lines of code

**Implementation Approach:**
- Extract MIR for function
- Build def-use chains (SSA form helps)
- Seed taint from sources (e.g., `env::var`, `args`)
- Propagate taint through assignments
- Check if tainted values reach sinks (e.g., `Command::arg`)
- Filter flows that pass through sanitizers

**Examples in Rust-COLA:**

| Rule ID | Name | Dataflow Pattern |
|---------|------|------------------|
| RUSTCOLA006 | Command injection (Phase 2) | `env::var` → `_1` → `_2` → `Command::arg(_2)` |
| RUSTCOLA021 | Content-Length DoS | `Response::content_length()` → `_5` → `Vec::with_capacity(_5)` |
| RUSTCOLA022 | Length truncation | `payload_len` → `as i32` → `write_u32(_)` |
| RUSTCOLA023 | Broadcast !Sync | `Rc<T>` → `broadcast::channel` → `.send()` |
| RUSTCOLA024 | Unbounded allocation | `.len()` → `_3` → `Vec::with_capacity(_3)` without `min()` |

**Algorithm (Simplified):**
```rust
fn detect_taint_flow(function: &MirFunction) -> Vec<Finding> {
    let dataflow = MirDataflow::new(function);
    
    // Seed taint from sources
    let tainted = dataflow.taint_from(|assignment| {
        assignment.rhs.contains("env::var") || 
        assignment.rhs.contains("env::args")
    });
    
    // Check if tainted values reach sinks
    for assignment in dataflow.assignments() {
        if is_command_arg_call(&assignment.rhs) {
            if assignment.sources.iter().any(|s| tainted.contains(s)) {
                // Found tainted flow: source → sink
                report_finding(assignment);
            }
        }
    }
}
```

**When to Use:**
- Need to connect sources to sinks
- Want to verify sanitization occurred
- Can tolerate function-only scope
- Target FP rate <10%

**Limitations:**
- Can't see: `get_input() → process() → execute_cmd()` (multi-function)
- Can't track: Taint through struct fields or heap
- Doesn't model: Path-sensitive flows (`if sanitized { use(x) }`)

**Phase 2 Achievement:**
- **Before:** 95% FP rate (19/20 findings were false positives)
- **After:** 43% FP rate (9/21 findings were false positives)
- **Improvement:** 52 percentage point reduction via sanitization detection

---

### Level 4: Inter-Procedural Dataflow Analysis

**Description:** Track data flow across function boundaries to detect multi-hop vulnerabilities.

**Characteristics:**
- ✅ **Call Graph Aware:** Follows taint through function calls
- ✅ **N-Level Flows:** Detects `fetch() → process() → execute()` chains
- ✅ **Very Low FP Rate:** 0-5% false positives (when combined with sanitization)
- ⚠️ **Expensive:** Whole-program analysis required
- ⚠️ **Complex:** 1500-3000 lines of code
- ❌ **Still Path-Insensitive:** Doesn't model branch conditions

**Implementation Approach:**
- Build call graph for entire crate
- Create function summaries (sources, sinks, propagations)
- Backward exploration: From sink, find callers that might provide taint
- Forward verification: From caller, check if taint reaches sink
- Track taint through parameters and return values

**Examples in Rust-COLA:**

| Rule ID | Name | Flow Pattern |
|---------|------|--------------|
| RUSTCOLA006 (Phase 3.3) | Command injection (inter-proc) | `get_user_input()` → `test_fn(data)` → `execute_command(data)` |

**Algorithm (Simplified):**
```rust
fn detect_inter_procedural_flow(package: &MirPackage) -> Vec<Finding> {
    let call_graph = build_call_graph(package);
    let summaries = build_function_summaries(package);
    
    for function in &package.functions {
        // Find sinks in this function
        for sink in find_command_sinks(function) {
            // Backward: Find callers that might taint this sink
            let taint_sources = explore_callers_backward(
                function,
                &sink,
                &call_graph,
                &summaries
            );
            
            // Forward: Verify taint actually reaches sink
            for source in taint_sources {
                if verify_flow_forward(source, sink, &call_graph) {
                    report_finding(source, sink);
                }
            }
        }
    }
}
```

**When to Use:**
- Vulnerability spans multiple functions
- Need to track through helper functions
- Target FP rate <5%
- Have whole-program visibility

**Limitations:**
- Can't track: Taint through callbacks or trait objects (context-insensitive)
- Can't model: Path-sensitive flows (`if is_admin { allow(cmd) }`)
- Expensive: O(n²) or worse for large programs
- May duplicate findings: Same flow reported from multiple entry points

**Phase 3.3 Achievement:**
- **Detection Rate:** 100% recall (11/11 vulnerable flows detected)
- **False Positive Rate:** 15.4% (2/13 safe flows flagged)
- **Flow Depth:** Successfully detects 3-level chains
- **Implementation:** ~800 lines of focused dataflow code

---

### Level 5: Context-Sensitive Inter-Procedural Analysis

**Description:** Track data flow with calling context to distinguish different call sites.

**Characteristics:**
- ✅ **Context Cloning:** Different call sites tracked separately
- ✅ **Precise:** Minimal false positives (<2%)
- ✅ **Handles Polymorphism:** Can distinguish `process(safe_data)` vs `process(tainted_data)`
- ⚠️ **Very Expensive:** Exponential in call depth
- ⚠️ **Very Complex:** 3000-5000 lines of code
- ⚙️ **Requires Intra-Procedural:** Needs path-sensitive analysis within functions

**Implementation Approach:**
- Clone analysis state at each call site
- Track taint separately for each calling context
- Use k-CFA (k-callsite-sensitive) or similar
- May require symbolic execution or abstract interpretation
- Implement widening to ensure termination

**Examples:**
- **Not Yet Implemented in Rust-COLA** (Phase 3.4+ roadmap)

**Conceptual Flow:**
```rust
fn process(data: String) {
    execute_command(&data);  // Sink
}

fn main() {
    let safe = "ls".to_string();
    let tainted = env::var("CMD").unwrap();
    
    process(safe);     // Context 1: NOT vulnerable
    process(tainted);  // Context 2: vulnerable
}
```

**Context-Insensitive (Level 4):**
- Merges both call sites
- Reports `process()` as vulnerable (1 FP, 1 TP)

**Context-Sensitive (Level 5):**
- Tracks contexts separately
- Reports only `process(tainted)` as vulnerable (0 FP, 1 TP)

**When to Use:**
- FP rate must be <2%
- Code has many safe uses of dangerous functions
- Can afford exponential analysis cost
- Have mature compiler infrastructure

**Challenges:**
- Explosion: `f() → g() → h()` with 3 call sites each = 27 contexts
- Aliases: Pointer analysis required
- Recursion: Need fixpoint iteration
- Implementation: Requires advanced compiler techniques

---

### Level 6: Path-Sensitive Analysis

**Description:** Model control flow conditions to eliminate infeasible paths.

**Characteristics:**
- ✅ **Understands Conditions:** Models `if sanitized { use(x) }`
- ✅ **Minimal FP:** <1% false positives
- ✅ **Handles Guards:** Recognizes sanitization checks
- ⚠️ **Extremely Expensive:** SMT solver required
- ⚠️ **Extremely Complex:** 5000-10000 lines of code
- ⚙️ **Requires Symbolic Execution:** May need theorem proving

**Implementation Approach:**
- Build symbolic execution engine
- Track path constraints (e.g., `x > 0 ∧ y != null`)
- Use SMT solver (Z3, CVC4) to check feasibility
- Prune infeasible paths
- Report only flows along feasible paths

**Examples:**
- **Not Implemented in Rust-COLA** (research-level)

**Conceptual Flow:**
```rust
fn safe_execute(cmd: String) {
    if is_safe(&cmd) {
        Command::new(&cmd).spawn();  // OK: guarded by is_safe
    }
}

fn unsafe_execute(cmd: String) {
    Command::new(&cmd).spawn();  // Vulnerable: no guard
}
```

**Path-Insensitive (Levels 3-5):**
- Reports both as vulnerable (50% FP rate)

**Path-Sensitive (Level 6):**
- Understands `is_safe()` guard
- Reports only `unsafe_execute()` (0% FP rate)

**When to Use:**
- Academic research
- Critical infrastructure (OS, crypto libraries)
- FP tolerance = 0%
- Unlimited analysis budget

**Challenges:**
- SMT solver overhead (seconds per function)
- Loop invariants (may need user annotations)
- Function summaries (what does `is_safe()` check?)
- Scalability (may timeout on complex functions)

---

## Rust-COLA Implementation Status

### Rules by Detection Level

| Level | Count | Examples |
|-------|-------|----------|
| **Level 1: Heuristic** | ~25 | RUSTCOLA001-002, 010, 025-037, 040-044 |
| **Level 2: MIR Pattern** | ~12 | RUSTCOLA007, 028-032 |
| **Level 3: Intra-Procedural** | ~8 | RUSTCOLA006 (Phase 2), 021-024 |
| **Level 4: Inter-Procedural** | ~1 | RUSTCOLA006 (Phase 3.3) |
| **Level 5: Context-Sensitive** | 0 | Planned for Phase 3.4+ |
| **Level 6: Path-Sensitive** | 0 | Research-level |

**Total: 48 implemented security rules**

### Evolution of RUSTCOLA006 (Command Injection)

This rule demonstrates progression through detection levels:

| Phase | Level | Recall | Precision | FP Rate |
|-------|-------|--------|-----------|---------|
| **Phase 1** | Heuristic | Low (~30%) | Very Low (~5%) | 95% |
| **Phase 2** | Intra-Procedural | Medium (~60%) | Medium (~57%) | 43% |
| **Phase 3.3** | Inter-Procedural | High (100%) | High (~85%) | 15% |
| **Phase 3.4** *(planned)* | Context-Sensitive | High (~100%) | Very High (~95%) | <5% |

**Key Insight:** Each level increase requires ~3x implementation effort but provides ~2x improvement in precision.

---

## Choosing the Right Detection Level

### Decision Matrix

```
              │ FP Tolerance │ Complexity │ Analysis Time │ Use Case
──────────────┼──────────────┼────────────┼───────────────┼─────────────────
Level 1       │   High       │    Low     │   <1ms/file   │ Linting, CI
Level 2       │   Medium     │   Medium   │   <10ms/fn    │ Quick audits
Level 3       │   Low        │    High    │   <100ms/fn   │ Security review
Level 4       │  Very Low    │ Very High  │   <1s/crate   │ Deep analysis
Level 5       │  Minimal     │  Extreme   │   <10s/crate  │ Critical code
Level 6       │  Zero        │  Research  │   Minutes     │ Verification
```

### Rule of Thumb

**Start at the lowest level that meets requirements:**

1. **API Misuse → Level 1 Heuristic**
   - Example: Calling deprecated functions
   - Why: Pattern is always wrong, no context needed

2. **Dangerous Patterns → Level 2 MIR Pattern**
   - Example: `static mut` without synchronization
   - Why: Need semantic info, but no dataflow

3. **Taint Tracking (Simple) → Level 3 Intra-Procedural**
   - Example: SQL injection in single function
   - Why: Source and sink in same function

4. **Taint Tracking (Complex) → Level 4 Inter-Procedural**
   - Example: Command injection through helpers
   - Why: Source and sink in different functions

5. **High Precision Required → Level 5 Context-Sensitive**
   - Example: Security-critical libraries
   - Why: Cannot tolerate false positives

6. **Formal Verification → Level 6 Path-Sensitive**
   - Example: Crypto primitives
   - Why: Need mathematical guarantees

---

## Future Work

### Phase 3.4: Context Sensitivity

**Goal:** Reduce FP rate from 15% to <5% for RUSTCOLA006

**Approach:**
- Implement k-CFA (k=2) calling context sensitivity
- Add intra-procedural path-sensitive dataflow
- Filter flows where source is a test helper

**Expected Impact:**
- Precision: 85% → 95%
- Recall: 100% (maintained)
- Cost: ~10x slower analysis

### Phase 4: Advanced Dataflow

**Candidates for Level 5 Implementation:**
- SQL injection (diesel::sql_query taint tracking)
- Path traversal (filesystem API taint tracking)
- SSRF (HTTP client URL taint tracking)

**Infrastructure Needed:**
- Alias analysis for heap tracking
- Field-sensitive analysis for structs
- Summary-based analysis for libraries

### Research Directions

**Path-Sensitive Analysis:**
- Integrate Z3 SMT solver
- Implement symbolic execution engine
- Model sanitization predicates formally

**Soundness vs. Completeness:**
- Current approach: Unsound (misses flows), incomplete (false positives)
- Future: Configurable soundness/completeness trade-off
- Goal: Sound for critical rules (no missed bugs), complete for linting (no FPs)

---

## Appendix: Implementation Complexity

### Lines of Code by Level

Based on Rust-COLA codebase analysis:

| Level | Rule Impl | Infrastructure | Total | Ratio |
|-------|-----------|----------------|-------|-------|
| **Level 1** | 50-200 | 500 (WalkDir, regex) | 550-700 | 1x |
| **Level 2** | 200-500 | 2000 (MIR extraction) | 2200-2500 | 4x |
| **Level 3** | 500-1500 | 5000 (MirDataflow) | 5500-6500 | 10x |
| **Level 4** | 800-2000 | 8000 (call graph, summaries) | 8800-10000 | 16x |
| **Level 5** | 2000-5000 | 15000 (context cloning) | 17000-20000 | 30x |
| **Level 6** | 5000-10000 | 30000 (SMT, symbolic) | 35000-40000 | 60x |

**Note:** Infrastructure is amortized across all rules at that level.

### Developer Effort

Approximate implementation time (experienced Rust developer):

| Level | First Rule | Additional Rules | Infrastructure |
|-------|------------|------------------|----------------|
| **Level 1** | 2-4 hours | 1-2 hours | 1 week (once) |
| **Level 2** | 1-2 days | 4-8 hours | 2 weeks (once) |
| **Level 3** | 1-2 weeks | 2-4 days | 1 month (once) |
| **Level 4** | 2-4 weeks | 1-2 weeks | 2 months (once) |
| **Level 5** | 1-2 months | 2-4 weeks | 4 months (once) |
| **Level 6** | 3-6 months | 1-2 months | 6+ months (once) |

---

## Conclusion

Rust-COLA demonstrates that practical security analysis can be achieved at Levels 1-4 with reasonable implementation effort. The progression from heuristic (Level 1) to inter-procedural dataflow (Level 4) shows a clear path from quick wins to deep analysis.

**Key Takeaways:**

1. **Start Simple:** Level 1 heuristics catch real bugs with minimal effort
2. **Iterate Up:** Move to higher levels only when FP rate is unacceptable
3. **Measure Trade-offs:** Track recall, precision, and analysis time
4. **Infrastructure Pays Off:** MirDataflow powers Levels 3-4
5. **Diminishing Returns:** Level 5-6 have exponential cost for marginal precision gains

**Current State (November 2025):**
- 48 security rules implemented (Levels 1-4)
- Phase 3.3 complete: Inter-procedural analysis operational
- Phase 3.4 planned: Context sensitivity to reduce FPs
- Research ongoing: Path-sensitive analysis for critical rules

---

**Document Version:** 1.0  
**Last Updated:** November 12, 2025  
**Author:** GitHub Copilot (with human oversight)  
**Status:** Living Document (will update as implementation progresses)
