# Rust-cola Current Status & Next Steps

**Date:** November 25, 2025  
**Version:** 70 security rules  
**Recent Achievement:** Tier 2 source-level analysis operational + Tier 3 planning complete

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
- Phase 3.4: Inter-procedural taint tracking complete
- 0% false positive rate (exceptional!)
- ~91% recall (10/11 vulnerable cases detected)
- 1 false negative: test_partial_sanitization (branch-sensitivity issue)

**Documentation:**
- ✅ Comprehensive Tier 3 architecture plan (docs/tier3-hir-architecture.md)
- ✅ Phase 3.5 dataflow roadmap (docs/phase3.5-roadmap.md)
- ✅ Quick start guide (docs/phase3.5-next-steps.md)
- ✅ Three-tier architecture documented in README

**Infrastructure:**
- ✅ Phase 0 HIR spike complete (Oct 2025)
- ✅ Toolchain pinned (nightly-2025-09-30)
- ✅ rustc_interface integration validated

### 🔨 Two Active Paths Forward

## Path A: Phase 3.5 Dataflow Improvements (Tactical)

**Goal:** Achieve 100% recall on taint tracking (91% → 100%)

**Status:** Ready to implement, well-documented

**Next Action:** Phase 3.5.1 - Branch-Sensitive Analysis

### What We'll Build:

**Control Flow Graph (CFG) Extraction:**
```rust
// New module: mir-extractor/src/dataflow/cfg.rs
pub struct ControlFlowGraph {
    pub blocks: HashMap<String, BasicBlock>,
    pub edges: HashMap<String, Vec<String>>,
    pub entry_block: String,
}

// Parse MIR basic_blocks to build CFG
// Track branches (if/else, match) separately
```

**Path-Sensitive Taint Tracking:**
```rust
// New module: mir-extractor/src/dataflow/path_sensitive.rs
pub struct PathSensitiveTaintAnalysis {
    cfg: ControlFlowGraph,
    taint_at_block: HashMap<(String, String), TaintState>,
}

// Analyze each branch independently
// If ANY path is vulnerable, report vulnerability
```

### The Fix:

**Before (91% recall):**
```rust
pub fn test_partial_sanitization() {
    let input = env::args().nth(1);
    
    if input.contains("safe") {
        let safe = validate_input(&input);  // Sanitized ✓
        execute_command(&safe);
    } else {
        execute_command(&input);           // VULNERABLE but MISSED ✗
    }
}

// Current: Sees validate_input() → marks whole function SAFE
// Result: FALSE NEGATIVE (dangerous!)
```

**After (100% recall):**
```
Branch 1 (if): input → validate_input → safe → execute ✓ SAFE
Branch 2 (else): input → execute ✗ VULNERABLE

Analysis: At least one path vulnerable → REPORT VULNERABILITY ✓
Result: TRUE POSITIVE (correct!)
```

### Implementation Plan:

**Phase 3.5.1: Branch Analysis** (Priority 1)
- Step 1: CFG extraction (1-2 hours)
- Step 2: Path enumeration (1 hour)
- Step 3: Path-sensitive taint tracking (2-3 hours)
- Step 4: Integration with FunctionSummary (1 hour)
- Step 5: Testing & validation (1-2 hours)
- **Total: ~7-9 hours (1-2 coding sessions)**

**Expected Gain:** +1 recall (91% → 100% on basic cases)

**Phase 3.5.2: Closure Support** (Priority 2)
- Detect closures (function names with `{closure#N}`)
- Extract captured variables
- Propagate taint through captures
- **Total: ~200-300 lines, 1-2 sessions**

**Expected Gain:** +1 advanced case (closure_capture)

**Phase 3.5.3: Trait Dispatch** (Priority 3)
- Build trait implementation map
- Conservative analysis (consider all impls)
- **Total: ~250 lines, 1 session**

**Expected Gain:** +1 advanced case (trait_method)

**Phase 3.5.4: Async Support** (Priority 4)
- Detect async functions
- Propagate taint through Futures
- **Total: ~100-150 lines, 1 session**

**Expected Gain:** +1 advanced case (async_flow)

### Success Metrics:

**Target (Phase 3.5 complete):**
- ✅ 100% recall (11/11 basic + 3/3 advanced = 14/14 total)
- ✅ 0% false positive rate (maintained)
- ✅ Performance <2x current analysis time

---

## Path B: Tier 3 HIR Integration (Strategic)

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

**Phase 1: Core Driver** (Dec 2025)
- Create HirPackage data structures
- Integrate hir_driver module (feature-gated)
- Add CLI flags: --hir-json, --hir-cache
- Link HIR items to MIR functions
- **Deliverable:** Extract HIR from examples/simple

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
| **Effort** | ~7-9 hours for 3.5.1 | ~2-3 weeks for Phase 1 |
| **Impact** | Perfects 1 existing rule | Unlocks 10-15 new rules |
| **Complexity** | Medium (CFG analysis) | High (compiler integration) |
| **Risk** | Low (clear problem) | Medium (nightly API changes) |
| **Value** | Tactical quick win | Strategic capability |
| **Momentum** | Existing dataflow code | Fresh planning complete |
| **Dependencies** | None (standalone) | Phase 0 spike (done) |

## Recommendation

I recommend **starting with Phase 3.5.1** (Branch-Sensitive Analysis) because:

### Pros:
1. ✅ **Quick win** - 7-9 hours to 100% recall
2. ✅ **Low risk** - Clear problem, existing codebase
3. ✅ **Validates architecture** - Tests dataflow improvements
4. ✅ **Builds skills** - CFG experience useful for Tier 3
5. ✅ **Immediate value** - Fixes dangerous false negative

### Why not Tier 3 first?
- Tier 3 Phase 1 is 2-3 weeks of work
- Phase 3.5.1 can be done in 1-2 sessions
- Quick win provides validation before larger investment
- CFG analysis skills will inform Tier 3 design

### Suggested Sequence:

**Week 1:** Phase 3.5.1 (Branch Analysis)
- ✅ Achieve 100% recall on taint tracking
- ✅ Validate dataflow architecture
- ✅ Build CFG extraction skills

**Week 2-3:** Phase 3.5.2 & 3.5.3 (Closures & Traits) - Optional
- Continue if momentum good
- Or pivot to Tier 3 with lessons learned

**Week 4+:** Tier 3 Phase 1 (HIR Driver)
- Start HIR integration with confidence
- Apply lessons from dataflow work

## Next Immediate Steps

### To Start Phase 3.5.1:

```bash
cd /Users/peteralbert/Projects/Rust-cola

# Create new modules
mkdir -p mir-extractor/src/dataflow
touch mir-extractor/src/dataflow/cfg.rs
touch mir-extractor/src/dataflow/path_sensitive.rs

# Examine the problem case
grep -A 15 "test_partial_sanitization" examples/interprocedural/src/lib.rs

# Look at current MIR structure
cargo run --bin mir-extractor -- \
  --crate-path examples/interprocedural \
  --mir-json target/partial_mir.json

cat target/partial_mir.json | jq '.functions[] | select(.name | contains("partial_sanitization"))'

# Run current tests (baseline)
cargo test --test test_function_summaries test_inter_procedural_detection -- --nocapture
```

### Files to Reference:

- **Implementation guide:** `docs/phase3.5-next-steps.md`
- **Full design:** `docs/phase3.5-roadmap.md`
- **Test cases:** `examples/interprocedural/src/lib.rs`
- **Current analysis:** `mir-extractor/src/interprocedural.rs`

## Questions?

Ready to proceed with Phase 3.5.1 (Branch Analysis)? 

Or would you prefer to:
- Start Tier 3 Phase 1 instead (HIR driver)?
- Review the design docs more deeply?
- Something else?

---

**Status:** Ready to implement  
**Recommended:** Phase 3.5.1 (Branch Analysis)  
**Estimated Time:** 1-2 coding sessions (7-9 hours)  
**Expected Outcome:** 100% recall on taint tracking (perfect detection)
