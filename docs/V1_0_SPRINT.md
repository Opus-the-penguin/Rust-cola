# cargo-cola v1.0 Sprint

**Goal**: Complete UX and first-run-value enhancements for production release.

**Current Version**: 0.9.2  
**Target Version**: 1.0.0  
**Rules**: 124 (115 RUSTCOLA + 9 ADV)  
**Tests**: 200+ passing

---

## Completed (Phases 1-3)

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation (Taint, Lifetimes, Unsafe, SQL, Paths) | ✅ Complete |
| 2 | Gap Closure (Format strings, Panics, Conversions) | ✅ Complete |
| 3 | Precision (Field-sensitivity, Closures, FP reduction) | ✅ Complete |

---

## Sprint Backlog (Phase 4)

### P0 - Must Have for v1.0

| Item | Description | Effort |
|------|-------------|--------|
| Large workspace support | Fix OOM on projects like InfluxDB (24 crates, 1000+ functions). Stream rule evaluation or chunk processing. | Large |
| CVSS-like scoring | Severity scores based on exploitability factors | Medium |
| Code snippets in SARIF | Include source context in SARIF findings | Small |
| Rule profiles | strict/balanced/permissive presets via config | Medium |
| **Derive macro filtering** | ADV001 flags safe derive macro code (PartialEq, PartialOrd). Detect `<impl at file.rs:LINE:COL: LINE:COL>` function signatures and exclude. | Medium |
| **Trait method borrow safety** | ADV001 "pointer escapes" triggers on references passed to trait methods (eq, partial_cmp). These are safe borrows, not escaping pointers. | Medium |

### P1 - Should Have

| Item | Description | Effort |
|------|-------------|--------|
| `--fast` mode | Skip expensive analyses for quick feedback | Medium |
| Performance benchmarks | Document baseline performance metrics | Small |
| **FP heuristic expansion** | `compute_false_positive_likelihood` only checks test/example/mock. Add: derive macros, compiler-generated code, safe borrow patterns. | Medium |

### P2 - Nice to Have

| Item | Description | Effort |
|------|-------------|--------|
| Rich AST output | Enhance ast.json with function bodies, field types, full signatures for security researchers | Medium |
| `cola init` wizard | Interactive config file generation | Medium |
| IDE integration docs | VS Code, IntelliJ setup guides | Small |

---

## Precision Analysis (InfluxDB crates)

### Scan 1: influxdb3_id (ID types, 430 LOC)

**Baseline**: 10 findings → 3 true positives, 7 false positives = **30% precision**

| Finding Type | Count | Assessment |
|--------------|-------|------------|
| RUSTCOLA024 (unbounded alloc) | 3 | ✅ All TP - real DoS vectors |
| ADV001 (pointer escapes) | 6 | ❌ All FP - derive macro code |
| RUSTCOLA123 (panic) | 1 | ⚠️ Borderline - unlikely in practice |

### Scan 2: influxdb3_authz (authorization, 430 LOC)

**Baseline**: 20 findings → 8 true positives, 12 false positives = **40% precision**

| Finding Type | Count | Assessment |
|--------------|-------|------------|
| RUSTCOLA044 (timing attack) | 1 | ✅ TP - real timing side-channel in auth! |
| RUSTCOLA075 (cleartext logging) | 3 | ⚠️ Needs review - auth logging |
| RUSTCOLA123 (unwrap in hot path) | 2 | ✅ TP - panics in auth code |
| RUSTCOLA092 (commented code) | 2 | ⚠️ Low priority |
| ADV001 (pointer escapes) | 12 | ❌ All FP - derive macro code |

### Root Cause Analysis

| FP Category | Total | Root Cause | Fix |
|-------------|-------|------------|-----|
| Derive macro expansions | 18 | ADV001 flags `#[derive(PartialEq)]` generated code | Detect `<impl at file:LINE:COL>` pattern |
| Trait method borrows | 18 | `&self` passed to `PartialEq::eq` flagged as "pointer escapes" | Whitelist safe std trait methods |

**ADV001 is 60% of all findings and 100% false positives.**

**Target**: 70%+ precision without LLM assistance

### ADV001 Improvement Plan

1. **Derive macro detection**: Function names matching `<impl at .*:\d+:\d+: \d+:\d+>::(eq|partial_cmp|cmp|hash|fmt|clone)` are compiler-generated
2. **Safe trait borrow list**: References passed to these methods are safe:
   - `PartialEq::eq`, `PartialEq::ne`
   - `PartialOrd::partial_cmp`, `Ord::cmp`
   - `Hash::hash`, `Hasher::write`
   - `Debug::fmt`, `Display::fmt`
   - `Clone::clone`
3. **Heuristic signals**:
   - Function location `LINE:COL: LINE:COL` (e.g., `205:21: 205:30`) indicates derive span
   - MIR comment `// in scope 0 at file.rs:LINE:COL: LINE:COL` with colon-separated span

### Recall Wins

- ✅ RUSTCOLA044 found a **real timing attack** in authorization code
- ✅ RUSTCOLA024 found **real DoS vectors** in deserialization
- ✅ RUSTCOLA123 found **panics in hot paths**

---

## Definition of Done

- [ ] All P0 items complete
- [ ] Test coverage maintained (200+ tests)
- [ ] Performance benchmarks documented
- [ ] CHANGELOG updated
- [ ] v1.0.0 tag pushed

---

## Historical References

Archived planning documents:
- `docs/archive/PRODUCTION_RELEASE_PLAN.md` - Full phase breakdown
- `docs/archive/GAP-ANALYSIS-RUST-SPECIFIC.md` - Gap closure details
