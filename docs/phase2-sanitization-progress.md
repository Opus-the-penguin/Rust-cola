# Phase 2: Sanitization Detection - Progress Report

## Objective
Reduce false positives in taint tracking by recognizing sanitization patterns like `.parse()` and `.chars().all()`.

## Results Summary

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| RUSTCOLA006 Findings | 7 | 6 | 1 FP eliminated (14% reduction) |
| False Positive Rate | 43% (3/7) | 33% (2/6) | 10 percentage point reduction |

## Implementation Details

### Architecture: Backward Dataflow Analysis

Instead of removing sanitized variables from the tainted set (which didn't work because taint propagates on alternative paths), we implemented **backward dataflow tracing**:

1. **Detect Sanitizers**: Scan MIR for sanitization patterns (`::parse::<`, `as Iterator>::all::<`)
2. **Mark Sanitized Variables**: Track which variables are results of sanitization operations
3. **Trace Sinks Backward**: For each sink, do BFS backward through dataflow dependencies
4. **Check Path**: If backward path from sink reaches a sanitized variable, mark flow as sanitized

### Code Structure

**File**: `mir-extractor/src/dataflow/taint.rs`

**Key Components**:
- `SanitizerRegistry`: Holds patterns for sanitization operations
- `detect_sanitized_variables()`: Scans function body for sanitization patterns
- `is_flow_sanitized()`: BFS backward from sink through dependency graph
- `extract_referenced_variables()`: Extracts all `_N` variables from right-hand side of assignment

**Integration**: `TaintAnalyzer::analyze()` calls `is_flow_sanitized()` for each detected flow, sets `TaintFlow.sanitized` flag accordingly.

## Test Results

### ✅ Working Cases

#### 1. `sanitized_parse` - Parse to Type
```rust
let port_str = env::var("PORT").unwrap_or_default();
let port: u16 = port_str.parse().unwrap_or(8080);
Command::new("echo").arg(port.to_string()).spawn()?;
```

**MIR Pattern**: `core::str::<impl str>::parse::<u16>`

**Why It Works**: 
- Parse creates new variable `_4` with sanitized value
- `to_string()` converts u16 back to string in variable `_14`
- Backward trace from `_14` finds path through `_4` (parse result)
- Flow correctly marked as sanitized ✅

**Dataflow**:
```
_2 = env::var("PORT")        [SOURCE]
_4 = parse::<u16>(_5)        [SANITIZER] ← detected
_14 = to_string(_15)         [derived from _4]
Command::arg(_14)            [SINK]
```

Backward trace: `_14 → _15 → _3 → _4` (sanitized) ✅

### ❌ Not Working Yet

#### 2. `sanitized_allowlist` - Validation Guard
```rust
let user_name = env::var("USERNAME").unwrap_or_default();
if user_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
    Command::new("echo").arg(&user_name).spawn()?;
}
```

**MIR Pattern**: `<Chars<'_> as Iterator>::all::<{closure@...}>`

**Why It Fails**:
- `chars().all()` creates boolean result `_3`
- Command::arg is **inside if block** guarded by `_3`
- Backward trace from sink finds original tainted variable `_1`, not `_3` (the guard)
- Requires **control-flow analysis**: sink dominated by sanitization check
- Flow marked as unsanitized ❌

**Control Flow**:
```
_1 = env::var("USERNAME")     [SOURCE]
_3 = chars().all(...)         [GUARD] ← detected but not linked to sink
bb5: if _3 goto bb6 else bb7
bb6: Command::arg(&_1)        [SINK] - inside guarded block
```

**What's Needed**: Dominance analysis or CFG traversal to detect sink is only reachable when guard passes.

#### 3. `validated_regex` - Similar Issue
Same pattern as `sanitized_allowlist`: validation guard not recognized.

## Technical Challenges

### Dataflow vs Control-Flow Sanitization

| Type | Example | Detection Method | Status |
|------|---------|------------------|---------|
| **Dataflow** | `.parse()` creates new sanitized value | Backward trace through assignments | ✅ Working |
| **Control-Flow** | `if chars().all() { use() }` guards sink | Dominance/CFG analysis | ❌ Not implemented |

### Why Control-Flow Is Harder

1. **Dominance Analysis**: Need to compute which basic blocks dominate others
2. **Guard Tracking**: Must identify that sink is inside block dominated by sanitization check
3. **MIR CFG**: Requires parsing basic block structure (`bb0:`, `goto bb1`, etc.)
4. **False Positives**: Guard could fail, leading to different code path

**Example**:
```rust
let valid = input.chars().all(|c| c.is_alphanumeric());
if valid {
    use(input);  // ← Dominated by guard check
} else {
    // Not reached when valid
}
```

Need to detect that `use(input)` is **only reachable** when `valid` is true.

## Next Steps

### Option A: Implement Control-Flow Analysis (Complex)
**Estimated Effort**: 8-16 hours
**Components Needed**:
1. Basic block parser (extract `bb0:`, `bb1:`, etc.)
2. CFG builder (edges between blocks)
3. Dominance analysis (which blocks dominate which)
4. Guard detector (sanitization checks that control flow)
5. Integration with taint tracking

**Pros**: Would handle both remaining false positives
**Cons**: Significant complexity, potential for new bugs

### Option B: Defer to Phase 3 / Future Work (Pragmatic)
**Estimated Effort**: 0 hours now, defer to later
**Rationale**:
- Already achieved 14% FP reduction (7 → 6)
- FP rate improved from 43% to 33%
- Control-flow analysis is qualitatively different problem
- Could be separate feature: "validation guard detection"

**Recommend**: Document as known limitation, move to Phase 3 or backlog

## Metrics

### Current State
- **True Positives**: 4 (env_to_command, env_to_fs, env_through_format, env_through_assign)
- **False Positives**: 2 (sanitized_allowlist, validated_regex)
- **False Positive Rate**: 33% (down from 43%)

### Original Goal
- **Target**: <20% FP rate
- **Current**: 33% FP rate
- **Gap**: Need to eliminate 1 more FP to reach 25%, or both to reach 0%

### Assessment
- **Partial Success**: Meaningful improvement (10 percentage points)
- **Approach Validated**: Backward dataflow works for transformation-based sanitization
- **New Understanding**: Control-flow sanitization is separate problem domain

## Conclusion

Phase 2 successfully implemented **dataflow-based sanitization detection**, reducing false positives by 14%. The `.parse()` pattern is now correctly recognized. The remaining false positives require **control-flow analysis**, which is a more complex undertaking and should be evaluated as a separate phase.

**Recommendation**: Mark Phase 2 as successfully completed for dataflow sanitization, document control-flow sanitization as Phase 3 or future enhancement.
