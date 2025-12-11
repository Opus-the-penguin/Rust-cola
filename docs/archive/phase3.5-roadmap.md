# Phase 3.5: Advanced Inter-Procedural Analysis Roadmap

## Overview
Phase 3.5 extends our inter-procedural taint analysis with advanced features to handle:
1. **Intra-procedural CFG analysis** - Branch-sensitive taint tracking
2. **Closure capture** - Taint flows through closures
3. **Trait method resolution** - Dynamic dispatch
4. **Async function support** - Future-based flows

## Current State (Phase 3.4)

### Achievements
- ✅ 0% false positive rate (down from 15.4%)
- ✅ ~91% recall (10/11 vulnerable cases detected)
- ✅ Inter-procedural flow detection (multi-level)
- ✅ Validation guard filtering

### Limitations
1. **Branch insensitivity**: Can't distinguish which branch reaches sink
   - test_partial_sanitization: Marked safe but has unsafe branch ❌
2. **No closure support**: test_closure_capture not handled
3. **No trait dispatch**: test_trait_method not handled
4. **No async support**: test_async_flow not handled

## Phase 3.5 Goals

### Primary Objective
**Achieve 100% recall on all 14 basic test cases** while maintaining 0% FP rate.

### Metrics Targets
| Metric | Phase 3.4 | Phase 3.5 Target |
|--------|-----------|------------------|
| Recall | ~91% (10/11) | **100% (11/11)** |
| FP Rate | 0% | **0%** |
| Advanced Cases | 0/3 | **3/3** (closures, traits, async) |

## Feature 1: Intra-Procedural CFG Analysis

### Problem Statement
**test_partial_sanitization** has two control-flow paths:
```rust
pub fn test_partial_sanitization() {
    let input = std::env::args().nth(1).unwrap_or_default();
    
    if input.contains("safe") {
        let safe = validate_input(&input);  // Path 1: SAFE
        execute_command(&safe);
    } else {
        execute_command(&input);            // Path 2: VULNERABLE ❌
    }
}
```

Our current analysis sees `validate_input()` is called and marks entire function as safe, missing the vulnerable `else` branch.

### Solution Design

#### 1.1 Extract Control-Flow Graph
Parse MIR basic blocks to build CFG:

```rust
struct ControlFlowGraph {
    blocks: HashMap<BlockId, BasicBlock>,
    edges: HashMap<BlockId, Vec<BlockId>>,
    entry: BlockId,
    exits: Vec<BlockId>,
}

struct BasicBlock {
    id: BlockId,
    statements: Vec<Statement>,
    terminator: Terminator,  // Goto, SwitchInt, Return, Call, etc.
}
```

**Key MIR patterns:**
- `SwitchInt`: if/match expressions
- `Goto`: unconditional jumps
- `Call`: function calls (may branch on panic)
- `Return`: function exits

#### 1.2 Path-Sensitive Taint Propagation

Track taint separately for each path through the CFG:

```rust
struct PathSensitiveTaintAnalysis {
    // Map: (BlockId, Variable) -> TaintState
    taint_at_block: HashMap<(BlockId, String), TaintState>,
    
    // Track which paths reach sinks
    vulnerable_paths: Vec<Path>,
    safe_paths: Vec<Path>,
}

enum TaintState {
    Clean,
    Tainted { source: TaintSource },
    Sanitized { sanitizer: String },
}
```

**Algorithm:**
1. Start at entry block with tainted params
2. For each block, compute taint state of all variables
3. On SwitchInt (if/match):
   - Analyze condition to detect guards (is_safe_input, contains("safe"))
   - Propagate taint to both branches separately
4. On sanitization call: Mark variable as Sanitized on that path
5. On sink call: Check if taint is Clean/Sanitized or Tainted

#### 1.3 Guard Detection

Recognize patterns that validate data:

```rust
fn is_validation_guard(condition: &Expr) -> bool {
    match condition {
        // if is_safe_input(&x)
        Call { func: "is_safe*" | "is_valid*" | "validate*", .. } => true,
        
        // if x.is_empty() / x.len() > 0
        MethodCall { method: "is_empty" | "len", .. } => true,
        
        // if x.chars().all(char::is_alphanumeric)
        Call { func: "all", arg: "is_alphanumeric" } => true,
        
        _ => false,
    }
}
```

**Guard semantics:**
- If guard returns true, then variable is safe on the "then" branch
- If guard returns false, variable is unsafe on the "else" branch

#### 1.4 Expected Outcome

**test_partial_sanitization analysis:**
```
Entry block: input = TAINTED(env)

Block 1 (if input.contains("safe")):
  Branch true:  input -> validate_input -> safe = SANITIZED -> execute_command ✅ SAFE
  Branch false: input = TAINTED -> execute_command ❌ VULNERABLE

Result: Report VULNERABLE (at least one path is unsafe)
```

### Implementation Plan

**Step 1:** Add CFG extraction to MirFunction
```rust
// In mir-extractor/src/lib.rs
impl MirFunction {
    pub fn build_cfg(&self) -> ControlFlowGraph {
        // Parse basic_blocks array from MIR
    }
}
```

**Step 2:** Create path-sensitive taint analysis module
```rust
// New file: mir-extractor/src/dataflow/path_sensitive.rs
pub struct PathSensitiveTaintAnalysis {
    cfg: ControlFlowGraph,
    // ...
}

impl PathSensitiveTaintAnalysis {
    pub fn analyze(&mut self) -> Vec<TaintPath> {
        // Worklist algorithm over CFG
    }
}
```

**Step 3:** Integrate with FunctionSummary generation
```rust
// In interprocedural.rs
fn generate_summary(&self, function: &MirFunction) -> FunctionSummary {
    // If function has branches, use path-sensitive analysis
    if function.has_branches() {
        let path_analysis = PathSensitiveTaintAnalysis::new(function);
        path_analysis.analyze()
    } else {
        // Use existing simple analysis
    }
}
```

**Complexity:** Medium-High (~300-500 lines)
**Risk:** May increase false negatives if guard detection too strict

---

## Feature 2: Closure Capture Analysis

### Problem Statement
**test_closure_capture** captures tainted variable in closure:
```rust
pub fn test_closure_capture() {
    let tainted = std::env::args().nth(1).unwrap_or_default();
    
    let closure = || {
        let _ = Command::new("sh").arg("-c").arg(&tainted).spawn();
    };
    
    closure();  // Taint flows through closure
}
```

### Solution Design

#### 2.1 Identify Closures in MIR

MIR represents closures as anonymous structs with captured variables as fields:

```rust
// MIR pseudocode
_1 = std::env::args()     // source
_2 = || { Command::new("sh").arg(&_1) }  // closure captures _1

// Closure type: [closure@lib.rs:278:18: 278:20]
// Captures: [_1: &String]
```

**Detection pattern:**
- Function name contains `{closure#N}`
- Has upvar fields (captured variables)
- Parent function creates closure value

#### 2.2 Track Closure Captures

```rust
struct ClosureCapture {
    closure_def_id: String,  // e.g., "{closure#0}"
    captured_vars: Vec<CapturedVar>,
    parent_function: String,
}

struct CapturedVar {
    name: String,
    by_ref: bool,  // &T vs T
    taint_state: TaintState,
}
```

**Algorithm:**
1. When analyzing parent function, detect closure creation
2. Track which variables are captured (from MIR upvars)
3. Propagate taint from captured variables into closure
4. When closure is called, treat as regular function call with captured state

#### 2.3 Closure Call Graph

Extend CallGraph to include closure calls:

```rust
enum CallSite {
    DirectCall { callee: String },
    ClosureCall { closure_id: String },
    TraitCall { trait_name: String, method: String },
}
```

**Challenge:** Closures might be passed around, making callsites indirect.

**Simplification for Phase 3.5:** Only handle closures called in the same function they're defined.

#### 2.4 Expected Outcome

**test_closure_capture analysis:**
```
1. Analyze test_closure_capture:
   - tainted = TAINTED(env::args)
   - closure captures tainted by reference
   - closure contains sink (Command::new)
   
2. Analyze closure body:
   - Param 0 (captured tainted): TAINTED
   - Command::new(&tainted): SINK
   - Path: env::args -> tainted -> closure -> Command::new
   
Result: VULNERABLE ✅
```

### Implementation Plan

**Step 1:** Add closure detection
```rust
// In interprocedural.rs
fn is_closure(function_name: &str) -> bool {
    function_name.contains("{closure#")
}

fn get_parent_function(closure_name: &str) -> Option<String> {
    // Parse "module::parent::{closure#0}" -> "module::parent"
}
```

**Step 2:** Extract captured variables from MIR
```rust
fn extract_captures(function: &MirFunction) -> Vec<CapturedVar> {
    // Look for upvar_decls in MIR
}
```

**Step 3:** Propagate taint through captures
```rust
fn analyze_closure(&self, closure: &MirFunction, parent_summary: &FunctionSummary) -> FunctionSummary {
    let captures = extract_captures(closure);
    
    // Initial taint: captured variables inherit taint from parent
    let mut initial_taint = HashMap::new();
    for capture in captures {
        if let Some(taint) = parent_summary.get_taint(&capture.name) {
            initial_taint.insert(capture.name, taint);
        }
    }
    
    // Analyze closure body with initial taint
    self.analyze_with_initial_taint(closure, initial_taint)
}
```

**Complexity:** Medium (~200-300 lines)
**Risk:** Low (closures are well-structured in MIR)

---

## Feature 3: Trait Method Resolution

### Problem Statement
**test_trait_method** uses dynamic dispatch:
```rust
trait Executor {
    fn execute(&self, cmd: &str);
}

struct ShellExecutor;

impl Executor for ShellExecutor {
    fn execute(&self, cmd: &str) {
        let _ = Command::new("sh").arg("-c").arg(cmd).spawn();  // SINK
    }
}

pub fn test_trait_method() {
    let tainted = std::env::args().nth(1).unwrap_or_default();
    let executor: Box<dyn Executor> = Box::new(ShellExecutor);
    executor.execute(&tainted);  // Dynamic dispatch
}
```

### Solution Design

#### 3.1 Detect Trait Calls

MIR represents trait calls as virtual method calls:

```rust
// MIR pseudocode
_1 = Box::<ShellExecutor>::new(ShellExecutor)
_2 = _1 as Box<dyn Executor>  // trait object coercion
_3 = <dyn Executor>::execute(_2, tainted)  // trait method call
```

**Pattern:** `<dyn TraitName>::method_name`

#### 3.2 Resolve Implementations

Build a trait implementation map:

```rust
struct TraitResolution {
    // Map: (TraitName, MethodName) -> Vec<ImplFunction>
    impls: HashMap<(String, String), Vec<String>>,
}

// Example:
// ("Executor", "execute") -> ["ShellExecutor::execute", "SafeExecutor::execute"]
```

**Algorithm:**
1. Scan all functions in package
2. Identify impl blocks: `impl TraitName for TypeName`
3. Map trait methods to concrete implementations
4. When analyzing trait call, consider ALL possible implementations

#### 3.3 Conservative Analysis

For soundness, assume **any** implementation might be called:

```rust
fn analyze_trait_call(&self, trait_name: &str, method: &str, args: &[Taint]) -> TaintPropagation {
    let impls = self.trait_resolution.get_impls(trait_name, method);
    
    // Conservative: if ANY impl has a sink, treat as sink
    let has_sink = impls.iter().any(|impl_func| {
        self.summaries.get(impl_func).map_or(false, |s| s.has_sink())
    });
    
    if has_sink {
        TaintPropagation::ParamToSink { param: 0, sink_type: "trait_dispatch" }
    } else {
        // Merge all implementations' behavior
        merge_summaries(impls.iter().filter_map(|f| self.summaries.get(f)))
    }
}
```

#### 3.4 Expected Outcome

**test_trait_method analysis:**
```
1. Detect trait call: <dyn Executor>::execute(&tainted)
2. Resolve implementations:
   - ShellExecutor::execute (has Command::new sink)
3. Conservative: At least one impl has sink
4. Propagate taint: env::args -> tainted -> execute -> Command::new

Result: VULNERABLE ✅
```

### Implementation Plan

**Step 1:** Build trait implementation map
```rust
// New: mir-extractor/src/trait_resolution.rs
pub struct TraitResolver {
    impls: HashMap<(String, String), Vec<String>>,
}

impl TraitResolver {
    pub fn from_package(package: &MirPackage) -> Self {
        // Scan all functions, identify impl blocks
    }
}
```

**Step 2:** Detect trait calls in MIR
```rust
fn is_trait_call(function_name: &str) -> Option<(String, String)> {
    // Parse "<dyn TraitName>::method" -> (TraitName, method)
}
```

**Step 3:** Integrate with inter-procedural analysis
```rust
// In interprocedural.rs
fn analyze_call_site(&self, call: &CallSite) -> Vec<String> {
    match call {
        CallSite::DirectCall { callee } => vec![callee.clone()],
        CallSite::TraitCall { trait_name, method } => {
            self.trait_resolver.get_impls(trait_name, method)
        }
        // ...
    }
}
```

**Complexity:** Medium (~250 lines)
**Risk:** May increase false positives if trait has many impls

---

## Feature 4: Async Function Support

### Problem Statement
**test_async_flow** uses async/await:
```rust
async fn get_async_input() -> String {
    std::env::var("ASYNC_INPUT").unwrap_or_default()
}

async fn execute_async(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

pub async fn test_async_flow() {
    let input = get_async_input().await;
    execute_async(&input).await;
}
```

### Solution Design

#### 4.1 Understand Async MIR

Async functions are transformed into state machines:

```rust
// Original:
async fn foo() -> String { ... }

// MIR representation:
fn foo() -> impl Future<Output = String> {
    // Returns a generator/state machine
}
```

**Key insight:** Async functions return Futures, `.await` polls the Future.

#### 4.2 Async Call Detection

Detect async calls in MIR:
- Function returns `impl Future<Output = T>`
- Call site has `.await` (represented as `poll` in MIR)

```rust
fn is_async_function(return_type: &str) -> bool {
    return_type.contains("Future") || return_type.contains("impl Future")
}
```

#### 4.3 Taint Propagation Through Futures

Treat `.await` as unwrapping the Future:

```rust
// input_future = get_async_input()  // Future<Output = String>
// input = input_future.await        // String

// Taint analysis:
// If get_async_input() returns tainted, then input_future is tainted
// If input_future is tainted, then input (after .await) is tainted
```

**Simplification:** Treat async calls like synchronous calls (conservative).

#### 4.4 Expected Outcome

**test_async_flow analysis:**
```
1. get_async_input() -> Future<String> with taint from env::var
2. .await unwraps Future -> input = TAINTED
3. execute_async(&input) -> calls Command::new with tainted arg
4. Path: env::var -> get_async_input -> input -> execute_async -> Command::new

Result: VULNERABLE ✅
```

### Implementation Plan

**Step 1:** Detect async functions
```rust
fn is_async(&self, function: &MirFunction) -> bool {
    function.return_type.contains("Future")
}
```

**Step 2:** Handle .await in taint propagation
```rust
// When we see:
// _1 = call async_fn()  // Returns Future
// _2 = poll(_1)         // .await

// Propagate taint: if _1 is tainted, then _2 is tainted
```

**Step 3:** Integrate with call graph
```rust
// Treat async calls like sync calls for now
// Future work: Model async runtime scheduling
```

**Complexity:** Low-Medium (~100-150 lines)
**Risk:** Low (conservative approximation)

---

## Implementation Strategy

### Phase 3.5.1: Branch-Sensitive Analysis (Priority 1)
**Target:** Fix test_partial_sanitization
- Implement CFG extraction
- Add path-sensitive taint tracking
- Test on partial_sanitization and branching_sanitization

**Expected gain:** +1 recall (91% → 100% on basic cases)

### Phase 3.5.2: Closure Support (Priority 2)
**Target:** Handle test_closure_capture
- Add closure detection and capture tracking
- Extend call graph for closure calls
- Test on closure_capture

**Expected gain:** +1 advanced case (1/3 → 2/3)

### Phase 3.5.3: Trait Dispatch (Priority 3)
**Target:** Handle test_trait_method
- Build trait resolution map
- Integrate conservative trait call handling
- Test on trait_method

**Expected gain:** +1 advanced case (2/3 → 3/3)

### Phase 3.5.4: Async Support (Priority 4)
**Target:** Handle test_async_flow
- Detect async functions and .await
- Propagate taint through Futures
- Test on async_flow

**Expected gain:** All 17 test cases covered (14 basic + 3 advanced)

## Testing Plan

### Unit Tests
- CFG extraction: verify basic blocks, edges, entry/exit
- Path enumeration: verify all paths through branching code
- Closure capture: verify captured variable detection
- Trait resolution: verify impl discovery

### Integration Tests
- Run on all 17 test cases in examples/interprocedural
- Measure recall, precision, FP rate
- Compare with Phase 3.4 baseline

### Real-World Validation
- Test on influxdb codebase
- Measure performance impact
- Identify any new false positives/negatives

## Success Criteria

### Must Have (Phase 3.5.1)
- ✅ 100% recall on 11 basic vulnerable cases
- ✅ 0% false positive rate maintained
- ✅ test_partial_sanitization detected as vulnerable

### Should Have (Phase 3.5.2-3)
- ✅ 2/3 advanced cases handled (closures, traits)
- ✅ Performance <2x slower than Phase 3.4

### Nice to Have (Phase 3.5.4)
- ✅ 3/3 advanced cases handled (+ async)
- ✅ Documented architectural patterns for future extensions

## Timeline Estimate

| Phase | Feature | Lines of Code | Time Estimate |
|-------|---------|---------------|---------------|
| 3.5.1 | CFG + Branch Tracking | ~400-600 | 2-3 sessions |
| 3.5.2 | Closure Support | ~200-300 | 1-2 sessions |
| 3.5.3 | Trait Resolution | ~250 | 1 session |
| 3.5.4 | Async Support | ~100-150 | 1 session |
| **Total** | | **~1000-1300** | **5-7 sessions** |

## Risks and Mitigations

### Risk 1: CFG Complexity
**Risk:** Path explosion in complex control flow  
**Mitigation:** Limit path depth, merge similar paths

### Risk 2: Performance Degradation
**Risk:** Branch-sensitive analysis is expensive  
**Mitigation:** Only use for functions with branches, cache results

### Risk 3: False Negative Increase
**Risk:** Stricter guard detection misses real guards  
**Mitigation:** Conservative guard patterns, extensive testing

### Risk 4: Trait Resolution Incompleteness
**Risk:** Missing trait implementations  
**Mitigation:** Conservative analysis (assume any unknown impl might be unsafe)

## References

### MIR Documentation
- https://rustc-dev-guide.rust-lang.org/mir/index.html
- Control flow: https://rustc-dev-guide.rust-lang.org/mir/controlflow.html
- Closures: https://rustc-dev-guide.rust-lang.org/closures.html

### Related Work
- Rudra: Rust memory safety bugs (uses MIR)
- MIRAI: Abstract interpretation for Rust
- Clippy: Linting with basic control flow

---

**Document Status:** Planning  
**Created:** 2024  
**Target Start:** After Phase 3.4 completion  
**Owner:** Rust-Cola Team
