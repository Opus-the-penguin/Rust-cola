# Tier 3 HIR Architecture: Advanced Semantic Analysis

**Status:** Planning  
**Target:** Q1 2026  
**Current Rules:** 70 (68 Tier 1 MIR + 2 Tier 2 Source)  
**Projected Additional Rules:** 10-15 advanced semantic rules

## Executive Summary

With Tier 1 (MIR heuristics) and Tier 2 (source-level analysis) successfully implemented and delivering 70 high-quality security rules, the next frontier is **Tier 3: HIR-based semantic analysis**. This tier will unlock advanced rules requiring:

- Type-level analysis (Send/Sync with generics)
- Trait implementation checking
- Proper taint tracking with type flow
- Context-sensitive analysis
- Attribute-aware semantic rules

## Three-Tier Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Rust-cola Analysis Engine                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Tier 1     │  │   Tier 2     │  │   Tier 3     │     │
│  │              │  │              │  │              │     │
│  │     MIR      │  │   Source     │  │     HIR      │     │
│  │  Heuristics  │  │   Analysis   │  │   Semantic   │     │
│  │              │  │              │  │   Analysis   │     │
│  │  68 rules    │  │   2 rules    │  │   0 rules    │     │
│  │  ✅ Complete │  │ ✅ Operational│  │  🔨 Planned  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                 │                  │             │
│         └─────────────────┴──────────────────┘             │
│                          │                                 │
│                   Rule Engine Core                         │
│                  (MirPackage-based)                       │
└─────────────────────────────────────────────────────────────┘
```

### Tier Comparison

| Aspect | Tier 1 (MIR) | Tier 2 (Source) | Tier 3 (HIR) |
|--------|--------------|-----------------|--------------|
| **Input** | MIR strings | Parsed AST (syn) | HIR + TyCtxt |
| **Capabilities** | Pattern matching on lowered IR | Attribute/comment inspection | Type resolution, trait queries |
| **Rules** | 68 | 2 | 0 (planned: 10-15) |
| **Implementation** | Simple string search | syn AST traversal | rustc_interface queries |
| **Complexity** | Low (50-200 LOC) | Medium (100-300 LOC) | High (300-500 LOC) |
| **False Positives** | 10-30% typical | <5% typical | Target: <2% |
| **Infrastructure** | ✅ Mature | ✅ Operational | 🔨 Phase 0 spike complete |
| **Performance** | Baseline | ~1.05x | Target: <1.2x |

## Rules Requiring Tier 3 (HIR)

### High Priority (Type/Trait Analysis)

1. **Rule #47: Non-thread-safe calls in tests**
   - **Need:** Detect `#[test]` functions calling non-Send APIs
   - **HIR requirement:** `#[test]` attribute detection (Tier 2) + type-level Send trait checking (Tier 3)
   - **Approach:** Hybrid Tier 2+3 rule
   - **Complexity:** Medium

2. **Rule #48: Unsafe Send across async boundaries**
   - **Need:** Detect Send requirements violated in futures
   - **HIR requirement:** Future trait analysis, async context detection, Send bound verification
   - **Approach:** Pure Tier 3
   - **Complexity:** High

3. **Rule #84: Generic Send/Sync bounds (enhanced)**
   - **Current:** RUSTCOLA015 detects missing bounds syntactically
   - **Enhancement:** Verify generic parameters in unsafe impl actually satisfy constraints
   - **HIR requirement:** Generic parameter resolution, trait bound checking
   - **Approach:** Upgrade existing Tier 1 rule to Tier 3
   - **Complexity:** Medium-High

4. **Rule #18: ZST pointer arithmetic (enhanced)**
   - **Current:** RUSTCOLA064 detects unit type and PhantomData (71% recall)
   - **Enhancement:** Detect custom empty structs/enums using size_of checks
   - **HIR requirement:** Type size queries via TyCtxt
   - **Approach:** Upgrade existing Tier 1 rule to Tier 3
   - **Complexity:** Medium

### Medium Priority (Advanced Dataflow)

5. **Rule #36: SQL injection**
   - **Need:** Track untrusted input to SQL query builders
   - **HIR requirement:** Proper taint tracking with type flow (String vs &str vs impl Display)
   - **Approach:** Tier 3 dataflow
   - **Complexity:** High

6. **Rule #37: Path traversal**
   - **Need:** Detect tainted paths to filesystem APIs
   - **HIR requirement:** Path/PathBuf type tracking, sanitization detection
   - **Approach:** Tier 3 dataflow
   - **Complexity:** High

7. **Rule #54: Uncontrolled allocation size**
   - **Need:** Taint tracking to Vec::with_capacity
   - **HIR requirement:** Numeric type tracking, bound analysis
   - **Approach:** Tier 3 dataflow
   - **Complexity:** High

### Lower Priority (Specialized Analysis)

8. **Rule #6: Dangling pointer use-after-free**
   - **Need:** Ensure no access after drop or reallocation
   - **HIR requirement:** Lifetime analysis, borrow checker integration
   - **Approach:** Tier 3 with lifetime queries
   - **Complexity:** Very High

9. **Rule #49: Await while holding guard**
   - **Need:** Detect guards held across await points
   - **HIR requirement:** Async lifetime analysis, RAII guard tracking
   - **Approach:** Tier 3 async analysis
   - **Complexity:** High

10. **Rule #82: Unsafe closure panic guard**
    - **Need:** Flag unsafe routines with panicking closures
    - **HIR requirement:** Closure capture analysis, panic path tracking
    - **Approach:** Tier 3 higher-order analysis
    - **Complexity:** Very High

## HIR Integration Strategy

### Phase 0: Spike (✅ Complete - Oct 2025)

**Status:** Complete (see `docs/research/hir-extraction-plan.md`)

**Achievements:**
- Built standalone `hir-spike` binary
- Integrated rustc_interface
- Captured HIR/MIR counts from examples/simple
- Established toolchain pinning (nightly-2025-09-30)
- Created wrapper for cargo metadata capture

**Key Learnings:**
- rustc_interface works but requires careful nightly tracking
- Binary size increases significantly (~2GB)
- ICE detection/logging essential for resilience
- Cargo metadata integration critical for workspace support

### Phase 1: Core Driver (🔨 Next - Dec 2025)

**Goal:** Extract basic HIR alongside MIR for single crates

**Tasks:**
1. Create `hir.rs` module with data structures:
   ```rust
   pub struct HirPackage {
       pub crate_name: String,
       pub crate_root: String,
       pub items: Vec<HirItem>,
   }
   
   pub struct HirItem {
       pub kind: HirItemKind,
       pub def_id: String,  // DefPathHash for correlation with MIR
       pub span: Option<SourceSpan>,
   }
   
   pub enum HirItemKind {
       Function(HirFunction),
       Trait(HirTrait),
       Impl(HirImpl),
       Struct(HirStruct),
       Enum(HirEnum),
       // ... more as needed
   }
   
   pub struct HirFunction {
       pub name: String,
       pub signature: String,  // Pretty-printed
       pub generics: Vec<Generic>,
       pub where_clauses: Vec<String>,
       pub is_async: bool,
       pub is_unsafe: bool,
       pub mir_correlation: Option<String>,  // Link to MirFunction
   }
   ```

2. Integrate `hir_driver.rs` module (feature-gated)
3. Add CLI flags: `--hir-json`, `--hir-cache`
4. Create integration tests
5. Update Rule trait to accept optional HIR:
   ```rust
   pub trait Rule: Send + Sync {
       fn metadata(&self) -> &RuleMetadata;
       fn evaluate(&self, package: &MirPackage) -> Vec<Finding>;
       
       // New optional method for HIR-aware rules
       fn evaluate_with_hir(
           &self, 
           mir_pkg: &MirPackage,
           hir_pkg: Option<&HirPackage>
       ) -> Vec<Finding> {
           // Default: ignore HIR
           self.evaluate(mir_pkg)
       }
   }
   ```

**Success Criteria:**
- Extract HIR from examples/simple
- Serialize to JSON
- Link HIR items to MIR functions
- Pass integration tests

### Phase 2: Type Queries (Jan 2026)

**Goal:** Enable type-level analysis for first HIR rules

**Tasks:**
1. Add TyCtxt query interface:
   ```rust
   pub struct TypeAnalyzer {
       // Query interface for rules
   }
   
   impl TypeAnalyzer {
       pub fn implements_trait(&self, ty: &str, trait_name: &str) -> bool;
       pub fn is_send(&self, ty: &str) -> bool;
       pub fn is_sync(&self, ty: &str) -> bool;
       pub fn size_of(&self, ty: &str) -> Option<usize>;
       pub fn is_copy(&self, ty: &str) -> bool;
   }
   ```

2. Cache type information in HirPackage
3. Implement first HIR rule: Enhanced ZST detection (RUSTCOLA064)
4. Benchmark performance impact

**Success Criteria:**
- RUSTCOLA064 recall improves from 71% to 100%
- Performance overhead <1.15x baseline

### Phase 3: Dataflow Integration (Feb 2026)

**Goal:** Combine HIR type info with existing MIR dataflow

**Tasks:**
1. Enhance MirDataflow with type awareness
2. Implement proper taint tracking with types
3. Add first dataflow rule: SQL injection (new)
4. Validate on real-world crates

**Success Criteria:**
- SQL injection detection working
- False positive rate <5%
- Performance overhead <1.2x baseline

### Phase 4: Advanced Rules (Mar 2026)

**Goal:** Ship 5+ advanced HIR-backed rules

**Target Rules:**
- #47: Non-thread-safe in tests (hybrid Tier 2+3)
- #48: Unsafe Send in async
- #84: Enhanced generic bounds
- #36: SQL injection
- #37: Path traversal

**Success Criteria:**
- 5 new rules shipped
- Total rules: 75+
- Documentation complete
- CI integration stable

## Technical Design

### Data Flow

```
Crate Source
     │
     ├──> cargo metadata ──> Dependency graph
     │
     ├──> Tier 1: MIR extraction (shell rustc)
     │         │
     │         └──> MirPackage (existing)
     │
     ├──> Tier 2: Source reading (walkdir + syn)
     │         │
     │         └──> SourceFile collection (existing)
     │
     └──> Tier 3: HIR extraction (rustc_interface)
               │
               ├──> tcx.hir() ──> HIR items
               ├──> tcx.type_of() ──> Type info
               ├──> tcx.predicates_of() ──> Trait bounds
               └──> HirPackage (new)
     
     
All three feed into Rule Engine:
     
Rule::evaluate(&MirPackage) -> Vec<Finding>           [Tier 1 rules]
Rule::evaluate(&MirPackage) -> Vec<Finding>           [Tier 2 rules access source via SourceFile::collect]
Rule::evaluate_with_hir(&MirPackage, &HirPackage)    [Tier 3 rules]
```

### Rule Implementation Pattern

```rust
// Tier 3 Rule Example: Enhanced ZST Detection
struct EnhancedZstPointerRule {
    metadata: RuleMetadata,
}

impl Rule for EnhancedZstPointerRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }
    
    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Fallback to Tier 1 heuristic if HIR unavailable
        self.evaluate_tier1_heuristic(package)
    }
    
    fn evaluate_with_hir(
        &self,
        mir_pkg: &MirPackage,
        hir_pkg: Option<&HirPackage>
    ) -> Vec<Finding> {
        let Some(hir_pkg) = hir_pkg else {
            return self.evaluate(mir_pkg);
        };
        
        let mut findings = Vec::new();
        
        for function in &mir_pkg.functions {
            // Check MIR for pointer arithmetic patterns
            for (idx, line) in function.body.iter().enumerate() {
                if let Some(ptr_type) = extract_pointer_type(line) {
                    // Query HIR for actual type size
                    if let Some(type_info) = hir_pkg.lookup_type(&ptr_type) {
                        if type_info.size_of() == 0 {
                            findings.push(/* ... */);
                        }
                    }
                }
            }
        }
        
        findings
    }
}
```

## Performance Targets

| Metric | Tier 1 | Tier 2 | Tier 3 Target |
|--------|--------|--------|---------------|
| **Extraction Time** | Baseline (1.0x) | 1.05x | <1.2x |
| **Memory Usage** | Baseline | +10MB | <+200MB |
| **Cache Size** | ~50KB/crate | +5KB/crate | <+500KB/crate |
| **Analysis Time** | Baseline | 1.02x | <1.15x |
| **False Positive Rate** | 10-30% | <5% | Target: <2% |

## Trade-offs & Risks

### Advantages
✅ Enables advanced semantic rules (10-15 new rules)  
✅ Significantly reduces false positives  
✅ Proper type-aware taint tracking  
✅ Better handling of generics and traits  
✅ Aligns with CodeQL/Semgrep enterprise capabilities  

### Challenges
⚠️ **Complexity:** rustc_interface requires deep compiler knowledge  
⚠️ **Nightly churn:** API breakage requires careful tracking  
⚠️ **Binary size:** +2GB when linked with rustc_private  
⚠️ **Performance:** Target <1.2x overhead may be challenging  
⚠️ **Memory:** Full HIR may consume >2GB on large crates  

### Mitigation Strategies
1. **Feature flag:** Keep HIR extraction optional
2. **Pinned toolchain:** Lock to stable rustc version
3. **Graceful degradation:** Rules fall back to Tier 1 if HIR unavailable
4. **Incremental rollout:** Start with 1-2 rules, validate before expanding
5. **CI resilience:** ICE detection and logging already implemented

## Success Metrics

### Phase 1 (Core Driver)
- [ ] Extract HIR from examples/simple
- [ ] Serialize to JSON successfully
- [ ] Link HIR to MIR functions
- [ ] Pass integration tests
- [ ] Performance overhead <1.15x

### Phase 2 (Type Queries)
- [ ] Implement TypeAnalyzer interface
- [ ] Ship enhanced RUSTCOLA064 (ZST detection)
- [ ] Achieve 100% recall on ZST test suite
- [ ] Performance overhead <1.15x

### Phase 3 (Dataflow)
- [ ] Implement type-aware taint tracking
- [ ] Ship SQL injection detection
- [ ] False positive rate <5%
- [ ] Performance overhead <1.2x

### Phase 4 (Production)
- [ ] Ship 5+ HIR-backed rules
- [ ] Total rules: 75+
- [ ] CI integration stable
- [ ] Documentation complete
- [ ] Performance targets met

## Next Steps

### Immediate (Nov 2025)
1. ✅ Document Tier 3 architecture (this file)
2. Review Phase 0 spike findings
3. Prioritize Phase 1 tasks
4. Assign team members (if applicable)

### Short-term (Dec 2025)
1. Begin Phase 1 implementation
2. Create HirPackage data structures
3. Integrate hir_driver module
4. Build first integration test

### Medium-term (Q1 2026)
1. Complete Phase 1 (Core Driver)
2. Begin Phase 2 (Type Queries)
3. Ship first HIR rule (enhanced ZST)
4. Validate performance

### Long-term (Q2 2026)
1. Complete Phases 3-4
2. Ship 5+ HIR rules
3. Achieve 75+ total rules
4. Publish Tier 3 methodology paper/blog post

## Resources

- **Existing Research:** `docs/research/hir-extraction-plan.md`
- **Phase 0 Code:** `mir-extractor/src/bin/hir_spike.rs` (behind feature flag)
- **Rule Backlog:** `docs/security-rule-backlog.md` (rules marked "Advanced")
- **Detection Levels:** `docs/research/rule-detection-levels.md`
- **Toolchain:** Pinned to `nightly-2025-09-30` in `rust-toolchain.toml`

## Conclusion

Tier 3 (HIR integration) represents the natural evolution of Rust-cola from pattern-matching (Tier 1) and syntax analysis (Tier 2) to full semantic understanding. With 70 high-quality rules already shipping, we have the foundation and track record to confidently pursue this advanced capability.

The phased approach ensures we can:
- Validate each step incrementally
- Maintain backward compatibility
- Keep performance acceptable
- Deliver value early with first HIR rules

Success in Tier 3 will position Rust-cola as a best-in-class security analysis tool for Rust, competitive with enterprise solutions like CodeQL while remaining open-source and domain-specialized.

---

**Status:** Planning complete, ready for Phase 1 implementation  
**Last Updated:** November 24, 2025  
**Next Review:** After Phase 1 completion (target: December 2025)
