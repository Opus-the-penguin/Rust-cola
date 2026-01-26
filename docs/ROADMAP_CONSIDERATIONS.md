# Roadmap Considerations

> **Working Document**: This captures enhancement ideas and future considerations for rust-cola development.

## Guard Detection Enhancements

The taint tracker identifies data flow from sources to sinks but may miss validation/bounds checks along the path. This leads to false positives where bounded allocations or sanitized inputs are flagged.

### Current State (v1.0.1)

- LLM prompt includes Step 0.5 with guard detection guidance
- Rule-specific guard patterns provided per finding type
- Per-finding hints tell the LLM what to search for

### Future Infrastructure Options

#### 1. RuleMetadata Enhancement
Add a `guard_patterns: Vec<String>` field to `RuleMetadata` in `mir-extractor/src/lib.rs`:

```rust
pub struct RuleMetadata {
    // ... existing fields ...
    /// Patterns that indicate this finding may be guarded/mitigated
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_patterns: Vec<String>,
}
```

This would let each rule define its own guard patterns in a structured way rather than hardcoding in the prompt generator.

#### 2. Taint Tracker Guard Detection
Modify the taint tracker in `mir-extractor/src/dataflow/taint.rs` to:
- Detect common guard patterns during analysis (min/max/clamp calls)
- Track "sanitized" state on tainted values
- Reduce confidence or skip findings where guards are detected

#### 3. Constant Discovery
Scan the crate for `MAX_*`, `LIMIT_*`, `*_LIMIT` constants and correlate with allocation findings:
- If an allocation size derives from a field bounded by a constant, mark as potentially guarded
- Include constant values in finding evidence

#### 4. Context Extraction Enhancement
Extract more lines around findings (currently limited to 8 evidence lines):
- Capture 20-50 lines of context
- Search for guard patterns in extracted context
- Pre-filter findings with detected guards

#### 5. Inter-procedural Guard Detection
Extend interprocedural analysis to track:
- Validation functions that guard entry points
- Schema/type constraints that bound values
- Constructor validation that limits field values

---

## Confidence Scoring Improvements

### Current State
- Binary confidence levels (High/Medium/Low)
- Confidence set per-rule, not per-finding

### Future Options

#### 1. Evidence-Based Confidence
Score confidence based on evidence quality:
- Strong MIR evidence → High
- Pattern match only → Medium
- Heuristic detection → Low

#### 2. Reachability-Aware Confidence
Incorporate reachability into confidence:
- Proven entry-point → High
- Internal only → Medium
- Dead code path → Low

---

## Performance Optimizations

### Current State
- MIR caching with hash validation
- Parallel rule evaluation

### Future Options

#### 1. Incremental Analysis
Only re-analyze changed functions between runs.

#### 2. Rule Prioritization
Run high-confidence rules first, skip low-confidence rules on clean codebases.

---

## Integration Enhancements

### GitHub Actions
- Native GitHub Actions output format
- PR comment integration with finding diffs

### IDE Integration
- VS Code extension for inline finding display
- Real-time analysis on file save

### CI/CD
- Baseline management for suppressing known issues
- Finding trends over time

---

## Rule Development

### Custom Rule SDK
- Simplified API for custom rule development
- WASM rule hot-reloading in development

### Rule Testing Framework
- Positive/negative test case generation
- Mutation testing for rule coverage

---

## Notes

- Priority: Guard detection is highest priority as it directly impacts false positive rates
- Timeline: Consider for v1.1 or v1.2 release
- Dependencies: RuleMetadata changes require mir-extractor version bump
