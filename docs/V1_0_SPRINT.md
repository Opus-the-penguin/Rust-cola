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
| CVSS-like scoring | Severity scores based on exploitability factors | Medium |
| Code snippets in SARIF | Include source context in SARIF findings | Small |
| Rule profiles | strict/balanced/permissive presets via config | Medium |

### P1 - Should Have

| Item | Description | Effort |
|------|-------------|--------|
| `--fast` mode | Skip expensive analyses for quick feedback | Medium |
| Performance benchmarks | Document baseline performance metrics | Small |

### P2 - Nice to Have

| Item | Description | Effort |
|------|-------------|--------|
| `cola init` wizard | Interactive config file generation | Medium |
| IDE integration docs | VS Code, IntelliJ setup guides | Small |

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
