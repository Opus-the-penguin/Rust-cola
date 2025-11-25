# Rust-cola Current Status & Next Steps

**Date:** November 25, 2025  
**Version:** 70 security rules  
**Recent Achievement:** ✅ Phase 3.5.1 Complete - 100% Recall | Tier 3 Phase 1 - 90% Complete!

## Current State Summary

### ✅ What's Completed

**70 Security Rules Shipped:**
- **Tier 1 (MIR Heuristics):** 68 rules - Pattern matching on compiler IR
  - Memory safety, crypto, concurrency, FFI, input validation
  - 10-30% typical false positive rate (acceptable for heuristics)
  - Mature and mostly exhausted for simple patterns

- **Tier 2 (Source Analysis):** 2 rules - AST inspection with syn crate
  - RUSTCOLA067: Commented-out code (87.5% recall, 100% precision)
  - RUSTCOLA072: Overscoped allow attributes (100% recall, 100% precision)
  - Infrastructure operational and proven

**Advanced Dataflow:**
- ✅ Phase 3.5.1: Branch-sensitive CFG analysis COMPLETE (Nov 25, 2025)
- **100% recall** (11/11 vulnerable cases detected) ✅
- **0% false positive rate** (maintained) ✅
- **9 vulnerable flows detected** (up from 8)
- Fixed last false negative: test_partial_sanitization now correctly detected

**Documentation:**
- ✅ Comprehensive Tier 3 architecture plan (docs/tier3-hir-architecture.md)
- ✅ Phase 3.5 dataflow roadmap (docs/phase3.5-roadmap.md)
- ✅ Phase 3.5.1 completion report (docs/phase3.5.1-complete.md)
- ✅ Quick start guide (docs/phase3.5-next-steps.md)
- ✅ Three-tier architecture documented in README

**Infrastructure:**
- ✅ Phase 0 HIR spike complete (Oct 2025)
- ✅ Phase 3.5.1 branch-sensitive CFG analysis (Nov 2025)
- ✅ Toolchain pinned (nightly-2025-09-30)
- ✅ rustc_interface integration validated

### 🔨 Two Active Paths Forward

## Path A: Phase 3.5 Dataflow Improvements (Tactical - IN PROGRESS)

**Goal:** Enhance interprocedural taint tracking capabilities

**Status:** Phase 3.5.1 COMPLETE ✅ - Optional phases remain

**✅ COMPLETED: Phase 3.5.1 - Branch-Sensitive Analysis**

### What We Built:

**Control Flow Graph (CFG) Extraction:**
- Parse MIR basic blocks to build CFG
- Track branches (if/else, match) separately
- Enumerate all execution paths

**Path-Sensitive Taint Tracking:**
- Analyze each branch independently
- Conservative taint propagation through library functions
- If ANY path is vulnerable, report vulnerability

### The Fix in Action:

**Test Case (test_partial_sanitization):**
```rust
pub fn test_partial_sanitization() {
    let input = env::args().nth(1);
    
    if input.contains("safe") {
        let safe = validate_input(&input);  // Path 1: Sanitized ✓
        execute_command(&safe);
    } else {
        execute_command(&input);           // Path 2: VULNERABLE ✓
    }
}
```

**Before Phase 3.5.1:**
- Analysis: Saw `validate_input()` → marked whole function SAFE
- Result: **FALSE NEGATIVE** (dangerous!)
- Recall: 91% (10/11 detected)

**After Phase 3.5.1:**
- Analysis: Path 1 SAFE, Path 2 VULNERABLE → Function VULNERABLE
- Result: **TRUE POSITIVE** (correct!) ✅
- Recall: **100%** (11/11 detected) ✅

### Implementation Details:

**Files Modified:**
- `mir-extractor/src/dataflow/cfg.rs` - Fixed call statement extraction
- `mir-extractor/src/dataflow/path_sensitive.rs` - Added conservative taint propagation
- `mir-extractor/tests/test_path_sensitive.rs` - Added comprehensive test

**Commits:**
- 280fb74: feat: Phase 3.5.1 implementation
- dc01f48: docs: Phase 3.5.1 completion report

**Full Details:** See `docs/phase3.5.1-complete.md`

---

### 🔮 OPTIONAL: Remaining Phase 3.5 Sub-phases

**Phase 3.5.2: Closure Support** (Priority 2)
- Detect closures (function names with `{closure#N}`)
- Extract captured variables
- Propagate taint through captures
- **Total: ~200-300 lines, 1-2 sessions**
- **Status:** Infrastructure exists in closure.rs, needs integration

**Expected Gain:** +1 advanced case (closure_capture)

**Phase 3.5.3: Trait Dispatch** (Priority 3)
- Build trait implementation map
- Conservative analysis (consider all impls)
- **Total: ~250 lines, 1 session**
- **Status:** Well-documented design

**Expected Gain:** +1 advanced case (trait_method)

**Phase 3.5.4: Async Support** (Priority 4)
- Detect async functions
- Propagate taint through Futures
- **Total: ~100-150 lines, 1 session**
- **Status:** Clear implementation path

**Expected Gain:** +1 advanced case (async_flow)

**Note:** These phases are **optional enhancements**. The primary goal of 100% recall on basic cases has been achieved. Consider proceeding to Tier 3 for strategic value.

---

## Path B: Tier 3 HIR Integration (Strategic - RECOMMENDED)

**Goal:** Add 10-15 advanced semantic rules (70 → 85+ total)

**Status:** Planning complete, ready for Phase 1 implementation

**Next Action:** Phase 1 - Core HIR Driver

### What We'll Build:

**HIR Data Structures:**
```rust
// New module: mir-extractor/src/hir.rs
pub struct HirPackage {
    pub crate_name: String,
    pub items: Vec<HirItem>,
}

pub enum HirItemKind {
    Function(HirFunction),
    Trait(HirTrait),
    Impl(HirImpl),
    Struct(HirStruct),
    // ... more as needed
}

pub struct HirFunction {
    pub name: String,
    pub signature: String,
    pub generics: Vec<Generic>,
    pub where_clauses: Vec<String>,
    pub is_async: bool,
    pub is_unsafe: bool,
    pub mir_correlation: Option<String>,
}
```

**Type Query Interface:**
```rust
// New module: mir-extractor/src/type_analyzer.rs
pub struct TypeAnalyzer {
    // Query interface for rules
}

impl TypeAnalyzer {
    pub fn implements_trait(&self, ty: &str, trait_name: &str) -> bool;
    pub fn is_send(&self, ty: &str) -> bool;
    pub fn is_sync(&self, ty: &str) -> bool;
    pub fn size_of(&self, ty: &str) -> Option<usize>;
}
```

### Rules Enabled by Tier 3:

**High Priority (5 rules):**
1. **#47**: Non-thread-safe calls in tests (hybrid Tier 2+3)
2. **#48**: Unsafe Send across async boundaries
3. **#84**: Enhanced generic Send/Sync bounds
4. **#18**: Enhanced ZST pointer arithmetic (71% → 100% recall)
5. **#36**: SQL injection (type-aware taint)

**Medium Priority (5 rules):**
6. **#37**: Path traversal
7. **#54**: Uncontrolled allocation size
8. **#6**: Dangling pointer use-after-free
9. **#49**: Await while holding guard
10. **#82**: Unsafe closure panic guard

### Implementation Timeline:

**Phase 1: Core Driver** (Nov 2025 - IN PROGRESS) - 90% COMPLETE ✅
- ✅ HirPackage data structures (1039 lines, comprehensive)
- ✅ hir_driver module integrated (feature-gated)
- ✅ CLI flags: --hir-json, --hir-cache (working)
- ✅ HIR extraction driver (capture_hir(), collect_crate_snapshot())
- ✅ rustc wrapper binary (hir-driver-wrapper)
- ✅ Cache integration (HirOptions, extract_with_cache_full_opts())
- 🚫 BLOCKED: rustc nightly-2025-09-14 ICE bug
- **Status:** Infrastructure complete, waiting on rustc fix
- **Details:** docs/tier3-phase1-status.md

**Phase 2: Type Queries** (Jan 2026)
- Implement TypeAnalyzer interface
- Cache type information
- Ship enhanced RUSTCOLA064 (ZST detection: 71% → 100% recall)
- **Deliverable:** First HIR-backed rule working

**Phase 3: Dataflow Integration** (Feb 2026)
- Type-aware taint tracking
- Ship SQL injection detection
- **Deliverable:** Type-aware dataflow rules

**Phase 4: Production** (Mar 2026)
- Ship 5+ HIR rules
- CI integration
- Documentation complete
- **Deliverable:** 75+ total rules

### Success Metrics:

**Phase 1:** HIR extraction working, linked to MIR
**Phase 2:** Enhanced RUSTCOLA064 at 100% recall
**Phase 3:** SQL injection detection <5% FP rate
**Phase 4:** 5+ HIR rules shipped, 75+ total rules

---

## Decision Matrix

| Aspect | Phase 3.5 (Dataflow) | Tier 3 (HIR) |
|--------|---------------------|--------------|
| **Effort** | ✅ Phase 3.5.1 DONE (7-9 hours) | ~2-3 days remaining (90% done) |
| **Impact** | ✅ Achieved 100% recall | Unlocks 10-15 new rules |
| **Complexity** | Medium (CFG analysis) | High (compiler integration) |
| **Risk** | ✅ Validated (tests pass) | Low (infrastructure proven) |
| **Value** | ✅ Tactical win achieved | Strategic capability |
| **Status** | Optional phases remain | Phase 1: 90% complete, rustc ICE blocking |
| **Dependencies** | ✅ Complete | ✅ Phase 0 spike complete |

## Current Recommendation

**Proceed to Tier 3 Phase 1** (HIR Driver) because:

### Why Tier 3 Now:

1. ✅ **Phase 3.5.1 complete** - Primary goal achieved (100% recall)
2. ✅ **Tier 3 Phase 1: 90% complete** - Infrastructure functional, rustc ICE blocking
3. ✅ **Strong foundation** - Dataflow architecture validated
4. ✅ **Phase 0 delivered** - HIR extraction nearly complete
5. ✅ **Strategic value** - Unlocks 10-15 new rules requiring semantic analysis
6. ✅ **Good timing** - Just needs rustc nightly fix to unblock

### Alternative: Continue Phase 3.5

If you prefer incremental improvements to dataflow:
- Phase 3.5.2: Closure support (~1-2 sessions)
- Phase 3.5.3: Trait dispatch (~1 session)
- Phase 3.5.4: Async support (~1 session)

**Note:** These are optional enhancements. The core goal is achieved.

## Next Steps

### Option A: Unblock Tier 3 Phase 1 (Recommended)

**Status:** 90% complete, blocked by rustc nightly-2025-09-14 ICE bug

**Immediate Actions:**
1. Test alternative nightly versions (try nightly-2025-08-01)
2. Search rust-lang/rust issues for known bug
3. Consider rustc bisection to find working version

**After rustc fix:**
1. Integration tests (~1 day)
2. Performance benchmarks (~1 day)
3. Documentation updates (~1 day)

**Timeline:** 2-3 days after rustc fix  
**Deliverable:** HIR extraction fully operational

**Reference:** `docs/tier3-phase1-status.md`

### Option B: Continue Phase 3.5 (Optional)

**Phase 3.5.2:** Closure support (~1-2 sessions)  
**Phase 3.5.3:** Trait dispatch (~1 session)  
**Phase 3.5.4:** Async support (~1 session)

**Note:** Optional enhancements - core goal already achieved

---

## Summary

**Current State:**
- ✅ 70 rules shipped (68 Tier 1, 2 Tier 2)
- ✅ 100% recall on basic taint tracking
- ✅ 0% false positive rate maintained
- ✅ Phase 3.5.1 complete and validated
- ✅ Tier 3 Phase 1: 90% complete (HIR infrastructure functional)

**Recent Commits:**
- 280fb74: Phase 3.5.1 implementation
- dc01f48: Phase 3.5.1 completion report
- c6a2b53: Updated CURRENT-STATUS.md
- 8dc5fed: Updated README.md

**Blocker:** rustc nightly-2025-09-14 ICE bug affecting HIR extraction

**Recommendation:** Find working nightly version to unblock Tier 3 Phase 1

---

**Status:** Phase 3.5.1 COMPLETE ✅ | Tier 3 Phase 1: 90% COMPLETE (blocked by rustc ICE)  
**Next Recommended:** Unblock Tier 3 Phase 1 (test alternative nightly versions)  
**Alternative:** Phase 3.5.2-3.5.4 (optional dataflow enhancements)
