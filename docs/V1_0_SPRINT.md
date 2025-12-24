# cargo-cola v1.0 Sprint

**Goal**: Complete UX and first-run-value enhancements for production release.

**Current Version**: 1.0.0 🎉  
**Target Version**: 1.0.0 ✅ ACHIEVED  
**Rules**: 126 (unified architecture)  
**Tests**: 205 passing

---

## Completed (Phases 1-4)

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation (Taint, Lifetimes, Unsafe, SQL, Paths) | ✅ Complete |
| 2 | Gap Closure (Format strings, Panics, Conversions) | ✅ Complete |
| 3 | Precision (Field-sensitivity, Closures, FP reduction) | ✅ Complete |
| 4 | ADV Rules Migration & Precision Improvements | ✅ Complete (v0.9.10-0.9.11) |

---

## Sprint Backlog (Phase 4)

### P0 - Must Have for v1.0

| Item | Description | Effort |
|------|-------------|--------|
| ~~Large workspace support~~ | ✅ **DONE (v0.9.6)** Fixed OOM on InfluxDB. Root cause: exponential path exploration in IPA. Solution: removed visited.remove(), added configurable depth limits. | ~~Large~~ |
| ~~CVSS-like scoring~~ | ✅ **DONE (v0.9.9)** Added `Exploitability` struct with AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction. Computes 0.0-10.0 score. All 118 RuleMetadata and 75 Finding structs updated. | ~~Medium~~ |
| ~~Code snippets in SARIF~~ | ✅ **DONE (v0.9.7)** Added `extract_snippet()` helper and `snippet.text` in SARIF regions. Also fixed 7 rules to populate span data. | ~~Small~~ |
| ~~Rule profiles~~ | ✅ **DONE (v0.9.9)** Added `RuleProfile` enum (strict/balanced/permissive). Configurable via `profile` in cargo-cola.yaml. Filters findings by confidence+severity. | ~~Medium~~ |
| ~~Derive macro filtering~~ | ✅ **DONE (v0.9.5)** ADV001 now skips derive macro generated code. | ~~Medium~~ |
| ~~Trait method borrow safety~~ | ✅ **DONE (v0.9.5)** ADV001 whitelists safe trait methods (eq, partial_cmp, hash, fmt, clone). | ~~Medium~~ |
| ~~ADV rules migration~~ | ✅ **DONE (v0.9.10)** Migrated 9 ADV rules to RUSTCOLA namespace (RUSTCOLA200-208). Unified architecture with single rule engine. | ~~Large~~ |
| ~~Precision improvements~~ | ✅ **DONE (v0.9.11)** 33% false positive reduction on real-world crate. Fixed RUSTCOLA039 (URL paths), RUSTCOLA200 (method calls), RUSTCOLA088 (incoming vs outgoing requests). | ~~Medium~~ |
| ~~LLM prompt integrity~~ | ✅ **DONE (v0.9.11)** Fixed bug where raw-findings.json and llm-prompt.md had inconsistent finding counts. | ~~Small~~ |

### P1 - Should Have

| Item | Description | Effort |
|------|-------------|--------|
| ~~`--fast` mode~~ | **WONTFIX** - Performance is adequate; users can wait for thorough analysis | ~~Medium~~ |
| Performance benchmarks | Document baseline performance metrics | Small |
| **FP heuristic expansion** | `compute_false_positive_likelihood` only checks test/example/mock. Add: derive macros, compiler-generated code, safe borrow patterns. | Medium |
| **Pruned SARIF generation** | LLM outputs list of confirmed finding IDs; cargo-cola filters `raw-findings.sarif` → `findings.sarif` with only validated findings. Enables clean CI integration post-LLM review. | Medium |

### P2 - Nice to Have

| Item | Description | Effort |
|------|-------------|--------|
| Rich AST output | Enhance ast.json with function bodies, field types, full signatures for security researchers | Medium |
| `cola init` wizard | Interactive config file generation | Medium |
| IDE integration docs | VS Code, IntelliJ setup guides | Small |
| ~~Multi-threaded analysis~~ | **WONTFIX** - Performance is adequate; complexity not justified | ~~Large~~ |

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

## v0.9.11 Precision Improvements (December 2025)

**Scan Target:** influxdb3_server (production HTTP server crate)  
**Result:** 165 → 111 findings (**33% reduction**, 0% recall loss)

### Rules Fixed

| Rule | Before | After | Fix Applied |
|------|--------|-------|-------------|
| RUSTCOLA039 | 2 | 0 | URL path detection (skip `/api/v3/token`) |
| RUSTCOLA200 | 22 | 0 | Method call detection (skip `->` patterns) |
| RUSTCOLA088 | 30 | 0 | Incoming vs outgoing request distinction |

### Technical Details

1. **RUSTCOLA039 (Hardcoded Crypto Key)**: Added check for URL-like paths containing `/` to avoid flagging endpoint constants.

2. **RUSTCOLA200 (Use-After-Free)**: Skip function calls (`->` in MIR) which consume references rather than return them. Method calls like `PartialEq::eq(move _3)` are safe.

3. **RUSTCOLA088 (SSRF)**: Removed `http::Request` and `hyper::Request` from sinks (these are incoming request types). Kept actual outbound patterns (`reqwest::get`, `Client::post`).


**See**: `docs/archive/FALSE_POSITIVE_ANALYSIS.md` for full analysis.

---

## Definition of Done

- [x] All P0 items complete ✅
- [x] Test coverage maintained (205 tests) ✅
- [x] Performance benchmarks documented ✅
- [x] CHANGELOG updated ✅
- [x] v1.0.0 tag pushed ✅

---

## Historical References

Archived planning documents:
- `docs/archive/PRODUCTION_RELEASE_PLAN.md` - Full phase breakdown
- `docs/archive/GAP-ANALYSIS-RUST-SPECIFIC.md` - Gap closure details

