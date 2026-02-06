# Rules Cleanup Sprint

**Created:** 2026-02-06  
**Priority:** High  
**Estimated Effort:** 2-3 days

## Executive Summary

Code review of the rust-cola rules system identified **3 duplicate rule IDs** causing SARIF output conflicts, ID management gaps, and opportunities for improved consistency. This sprint addresses these issues to ensure rule integrity and output correctness.

---

## Critical Issues

### 1. Duplicate Rule IDs (P0 - Blocking)

These collisions cause duplicate/conflicting entries in SARIF output and confuse LLM triage:

| Duplicate ID | Rule 1 | Location | Rule 2 | Location |
|--------------|--------|----------|--------|----------|
| **RUSTCOLA011** | `modulo-bias-random` | crypto.rs:988 | `non-https-url` | web.rs:21 |
| **RUSTCOLA073** | `nonnull-new-unchecked` | memory.rs:1091 | `unsafe-ffi-pointer-return` | ffi.rs |
| **RUSTCOLA078** | `mem-forget-guard` | memory.rs | `maybeuninit-assume-init-without-write` | memory.rs:2181 |

**Impact:** SARIF consumers (VS Code, GitHub Code Scanning) may display incorrect rule metadata or deduplicate incorrectly.

### 2. Rule ID Gaps (P2 - Housekeeping)

The following IDs are unused, suggesting rapid development without ID reservation:

```
RUSTCOLA026, RUSTCOLA027, RUSTCOLA033, RUSTCOLA034
RUSTCOLA066, RUSTCOLA069, RUSTCOLA070, RUSTCOLA071
RUSTCOLA099, RUSTCOLA104, RUSTCOLA105, RUSTCOLA108
RUSTCOLA110, RUSTCOLA114
```

**Impact:** Minor - cosmetic only, but complicates documentation.

### 3. Documentation Sync (P1)

The rule table in `docs/RULE_DEVELOPMENT_GUIDE.md` documents the duplicates as two separate entries. This needs updating after ID reassignment.

---

## Sprint Plan

### Day 1: Duplicate ID Resolution

#### Task 1.1: Reassign RUSTCOLA011 duplicate
- [ ] Change `modulo-bias-random` from RUSTCOLA011 → **RUSTCOLA130**
- [ ] Update `mir-extractor/src/rules/crypto.rs` line ~988
- [ ] Grep for any test files referencing RUSTCOLA011 expecting modulo-bias

```rust
// BEFORE (crypto.rs)
id: "RUSTCOLA011".to_string(),
name: "modulo-bias-random".to_string(),

// AFTER
id: "RUSTCOLA130".to_string(),
name: "modulo-bias-random".to_string(),
```

#### Task 1.2: Reassign RUSTCOLA073 duplicate
- [ ] Change `unsafe-ffi-pointer-return` from RUSTCOLA073 → **RUSTCOLA131**
- [ ] Update `mir-extractor/src/rules/ffi.rs`
- [ ] Keep `nonnull-new-unchecked` as RUSTCOLA073 (appears first in memory.rs)

#### Task 1.3: Reassign RUSTCOLA078 duplicate
- [ ] Change `maybeuninit-assume-init-without-write` from RUSTCOLA078 → **RUSTCOLA132**
- [ ] Update `mir-extractor/src/rules/memory.rs` line ~2181
- [ ] Keep `mem-forget-guard` as RUSTCOLA078

#### Task 1.4: Validation
- [ ] Run `cargo-cola --rules | sort | uniq -d` to confirm no duplicates
- [ ] Run `cargo test -p mir-extractor` to catch broken tests

### Day 2: Documentation & Test Updates

#### Task 2.1: Update RULE_DEVELOPMENT_GUIDE.md
- [ ] Fix the duplicate entries in the rule inventory table
- [ ] Add new IDs (RUSTCOLA130-132) in correct positions

#### Task 2.2: Update README.md if needed
- [ ] Verify rule count still shows 126
- [ ] Verify category examples remain accurate

#### Task 2.3: Add duplicate-detection CI check
- [ ] Create `ci-test-crate/tests/no_duplicate_rule_ids.rs`:

```rust
#[test]
fn no_duplicate_rule_ids() {
    let engine = mir_extractor::RuleEngine::with_builtin_rules();
    let mut seen = std::collections::HashSet::new();
    for meta in engine.rule_metadata() {
        assert!(
            seen.insert(meta.id.clone()),
            "Duplicate rule ID: {}",
            meta.id
        );
    }
}
```

### Day 3: Polish & Verification

#### Task 3.1: Full regression test
- [ ] Run scan on `examples/` directory
- [ ] Verify SARIF output has no duplicate `ruleId` entries
- [ ] Spot-check that renamed rules produce expected findings

#### Task 3.2: Changelog entry
- [ ] Add to CHANGELOG.md under next version:

```markdown
### Fixed
- Fixed duplicate rule IDs (RUSTCOLA011, RUSTCOLA073, RUSTCOLA078) causing SARIF conflicts
  - `modulo-bias-random` → RUSTCOLA130
  - `unsafe-ffi-pointer-return` → RUSTCOLA131  
  - `maybeuninit-assume-init-without-write` → RUSTCOLA132
```

---

## Future Improvements (Backlog)

### New Rule Opportunities (Future Sprint)

The following vulnerability patterns are not currently covered and represent opportunities for new rules:

| Pattern | Description | Suggested ID | Priority |
|---------|-------------|--------------|----------|
| **Overflow in indexing** | `arr[x + y]` where arithmetic can overflow before bounds check | RUSTCOLA133 | High |
| **Iterator-based UB** | `.nth(usize::MAX)` or `.skip(usize::MAX)` causing overflow | RUSTCOLA134 | Medium |
| **Panic in no_std** | Panic handlers in `#![no_std]` contexts without proper handling | RUSTCOLA135 | Medium |
| **PhantomData misuse** | Incorrect PhantomData variance/lifetime annotations | RUSTCOLA136 | Low |
| **Manual Arc manipulation** | `Arc::decrement_strong_count` race conditions | RUSTCOLA137 | High |
| **mem::swap with uninit** | Swapping uninitialized memory locations | RUSTCOLA138 | High |
| **Double-free patterns** | Explicit double-free beyond general UAF detection | RUSTCOLA139 | Medium |
| **Pin projection unsoundness** | Incorrect pin projection in self-referential types | RUSTCOLA140 | Medium |

**Estimated effort:** 1-2 weeks for full implementation with tests and examples.

### Potential Rule Redundancy
| Rule A | Rule B | Notes |
|--------|--------|-------|
| RUSTCOLA003 (unsafe-usage) | N/A | Very noisy - consider making opt-in |
| RUSTCOLA040 (panic-in-drop) | RUSTCOLA124 (panic-in-drop-impl) | Review for consolidation |

### Missing CWE IDs
Many rules have empty `cwe_ids` vectors despite having clear CWE mappings. Consider a sweep to populate these for better SARIF interoperability.

### ID Reservation System
Consider adding a `RULE_ID_REGISTRY.md` file to prevent future collisions:

```markdown
# Rule ID Registry
| Range | Category | Status |
|-------|----------|--------|
| 001-025 | Core memory/crypto | Allocated |
| 026-034 | Reserved | Available |
| 035-070 | FFI/Input/Resource | Allocated |
...
```

---

## Acceptance Criteria

- [ ] `cargo-cola --rules` shows no duplicate IDs
- [ ] All tests pass (`cargo test --workspace`)
- [ ] SARIF output validates against schema
- [ ] Documentation reflects new IDs
- [ ] CI includes duplicate-detection test

---

## Files to Modify

| File | Change |
|------|--------|
| `mir-extractor/src/rules/crypto.rs` | RUSTCOLA011 → RUSTCOLA130 |
| `mir-extractor/src/rules/ffi.rs` | RUSTCOLA073 → RUSTCOLA131 |
| `mir-extractor/src/rules/memory.rs` | RUSTCOLA078 → RUSTCOLA132 |
| `docs/RULE_DEVELOPMENT_GUIDE.md` | Update rule table |
| `CHANGELOG.md` | Add fix entry |
| `ci-test-crate/tests/` | Add duplicate ID test |
