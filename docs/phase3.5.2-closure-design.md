# Phase 3.5.2: Closure and Higher-Order Function Analysis - Design

**Date**: November 12, 2025  
**Status**: Design Phase  
**Objective**: Extend taint analysis to track data flow through closures and higher-order functions

## Closure Representation in MIR

### Example: test_closure_capture

**Source Code**:
```rust
pub fn test_closure_capture() {
    let tainted = std::env::args().nth(1).unwrap_or_default();
    
    let closure = || {
        let _ = Command::new("sh").arg("-c").arg(&tainted).spawn();
    };
    
    closure();
}
```

### MIR Representation

#### 1. Closure Creation (Parent Function)

```mir
bb4: {
    _6 = &_1;  // Create reference to tainted data
    _5 = {closure@examples/interprocedural/src/lib.rs:278:19: 278:21} { tainted: move _6 };
    _8 = &_5;  // Reference to closure
    _7 = <{closure@...} as Fn<()>>::call(move _8, const ()) -> [return: bb5, unwind: bb7];
}
```

**Key Observations**:
- Closure creation: `_5 = {closure@...} { tainted: move _6 }`
  - Syntax: `{closure@<file>:<line>:<col>} { <captured_var>: <value> }`
  - Captures `_1` (tainted) via reference `_6`
- Closure invocation: `<{closure@...} as Fn<()>>::call(move _8, const ())`
  - Uses trait method call pattern
  - Closure passed as first argument

#### 2. Closure Body (Separate Function)

Function name: `test_closure_capture::{closure#0}`

```mir
bb0: {
    _6 = Command::new::<&str>(const "sh") -> [return: bb1, unwind continue];
}

bb2: {
    _7 = deref_copy ((*_1).0: &std::string::String);  // Access captured variable
    _3 = Command::arg::<&String>(copy _4, copy _7) -> [return: bb3, unwind: bb7];
}

bb3: {
    _2 = Command::spawn(copy _3) -> [return: bb4, unwind: bb7];
}
```

**Key Observations**:
- Captured variable access: `((*_1).0: &std::string::String)`
  - Pattern: `((*<param>).<index>: <type>)`
  - `_1` is the closure environment parameter
  - Field access `.0` gets the first captured variable
- Taint flow: captured `tainted` → `Command::arg` → `Command::spawn` (sink)

## Design Challenges

### 1. Closure Detection

**Challenge**: Identify closure creation, closure invocations, and closure bodies in MIR.

**Patterns to Detect**:
- **Creation**: `_X = {closure@<location>} { <captures> }`
- **Invocation**: `<{closure@...} as Fn<()>>::call(...)` or `<... as FnOnce<...>>::call_once(...)`
- **Body**: Function name contains `::{closure#N}`

### 2. Capture Analysis

**Challenge**: Extract which variables are captured and track taint through captures.

**Approach**:
1. Parse capture list from closure creation: `{ var1: value1, var2: value2 }`
2. Map parent function variables to closure environment fields
3. Track taint: if captured variable is tainted, closure environment is tainted

### 3. Inter-Function Taint Propagation

**Challenge**: Connect parent function's tainted data to closure's usage.

**Solution**:
1. When closure is created with captured tainted variable:
   - Mark closure environment as tainted
   - Create mapping: `{closure#0}._1.0 ← parent._X`
2. When analyzing closure body:
   - Check if `((*_1).N)` accesses are tainted based on captures
3. When closure is invoked:
   - Propagate taint from parent to closure execution context

### 4. Higher-Order Functions

**Challenge**: Handle cases like `vec.iter().map(|x| process(x))`.

**Examples**:
```rust
// Case 1: Direct closure
let data = env::args();
data.map(|arg| execute_command(&arg));  // VULNERABLE

// Case 2: Closure with capture
let tainted = env::args().nth(1);
vec.iter().map(|_| execute_command(&tainted));  // VULNERABLE

// Case 3: Safe transformation
let data = env::args();
data.map(|arg| sanitize(arg))
    .map(|safe| execute_command(&safe));  // SAFE
```

## Proposed Architecture

### 1. Closure Registry (New Component)

```rust
pub struct ClosureRegistry {
    /// Maps closure names to their parent functions
    closure_parents: HashMap<String, String>,
    
    /// Maps closure names to captured variables
    /// Key: "{closure#N}", Value: [(field_index, parent_var, taint_state)]
    captures: HashMap<String, Vec<CapturedVariable>>,
    
    /// Maps closure creation sites to closures
    /// Key: (parent_function, variable), Value: closure_name
    closure_bindings: HashMap<(String, String), String>,
}

pub struct CapturedVariable {
    pub field_index: usize,      // Position in closure environment (.0, .1, etc.)
    pub parent_var: String,       // Variable from parent function
    pub capture_mode: CaptureMode, // ByValue, ByRef, ByMutRef
    pub taint_state: TaintState,  // Propagated from parent
}

pub enum CaptureMode {
    ByValue,    // move
    ByRef,      // &
    ByMutRef,   // &mut
}
```

### 2. Enhanced MIR Analysis

Add to `MirFunction` analysis:

```rust
impl MirFunction {
    /// Check if this is a closure function
    pub fn is_closure(&self) -> bool {
        self.name.contains("::{closure#")
    }
    
    /// Extract closure number from name
    /// "test_func::{closure#0}" -> Some(("test_func", 0))
    pub fn parse_closure_name(&self) -> Option<(String, usize)> {
        // Parse pattern: "<parent>::{closure#<N>}"
    }
    
    /// Extract parent function name
    pub fn get_parent_function(&self) -> Option<String> {
        if let Some((parent, _)) = self.parse_closure_name() {
            Some(parent)
        } else {
            None
        }
    }
}
```

### 3. Closure-Aware Taint Analysis

Extend `PathSensitiveTaintAnalysis`:

```rust
impl PathSensitiveTaintAnalysis {
    /// Analyze closure with knowledge of captured variables
    pub fn analyze_closure(
        &mut self,
        function: &MirFunction,
        captures: &[CapturedVariable],
    ) -> PathSensitiveResult {
        // Initialize taint state with captured variables
        let mut initial_taint = HashMap::new();
        for capture in captures {
            if matches!(capture.taint_state, TaintState::Tainted { .. }) {
                // Map closure environment field to tainted state
                let env_var = format!("(*_1).{}", capture.field_index);
                initial_taint.insert(env_var, capture.taint_state.clone());
            }
        }
        
        // Run path analysis with initial taint
        self.analyze_with_initial_taint(function, initial_taint)
    }
}
```

### 4. Detection Patterns

#### Pattern 1: Closure Creation with Tainted Capture

```mir
_6 = &_1;  // _1 is TAINTED
_5 = {closure@...} { tainted: move _6 };
```

**Detection**:
1. Parse `{closure@...} { ... }` syntax
2. Extract captured variable (`_6`)
3. Check if `_6` is tainted
4. If yes, mark closure `_5` as containing tainted data

#### Pattern 2: Closure Invocation

```mir
_8 = &_5;  // _5 is closure with tainted capture
_7 = <{closure@...} as Fn<()>>::call(move _8, const ());
```

**Detection**:
1. Identify `Fn::call`, `FnMut::call_mut`, or `FnOnce::call_once`
2. Extract closure variable (`_8`)
3. Look up closure definition to get captures
4. Propagate taint to closure execution

#### Pattern 3: Captured Variable Access in Closure

```mir
// Inside closure body:
_7 = deref_copy ((*_1).0: &std::string::String);
```

**Detection**:
1. Parse `((*_1).<N>)` pattern (environment field access)
2. Look up capture mapping: field N → parent variable
3. Propagate taint from parent to `_7`

#### Pattern 4: Higher-Order Function Call

```mir
// vec.map(closure)
_X = <Vec<T> as Iterator>::map::<_, Closure>(move _vec, move _closure);
```

**Detection**:
1. Identify iterator methods: `map`, `filter`, `fold`, `for_each`
2. Extract closure argument
3. Analyze if closure uses tainted captures
4. Propagate taint through transformation chain

## Implementation Plan

### Phase 1: Closure Detection (Current Task)
- [ ] Add closure pattern matching to MIR parsing
- [ ] Extract closure creation sites
- [ ] Build closure registry with parent mappings

### Phase 2: Capture Analysis
- [ ] Parse capture syntax `{ var: value }`
- [ ] Map captured variables to closure environment fields
- [ ] Track taint state of captures

### Phase 3: Taint Propagation
- [ ] Extend path-sensitive analysis for closures
- [ ] Initialize closure analysis with captured taint
- [ ] Detect environment field accesses `((*_1).N)`

### Phase 4: Integration
- [ ] Modify inter-procedural analysis to handle closures
- [ ] Connect parent function taint to closure taint
- [ ] Test on `test_closure_capture`

### Phase 5: Higher-Order Functions
- [ ] Detect iterator methods (`map`, `filter`, etc.)
- [ ] Track taint through functional pipelines
- [ ] Handle closure chains

## Success Criteria

1. ✅ Detect `test_closure_capture` as VULNERABLE
2. ✅ Correctly identify tainted data flowing through closure capture
3. ✅ Distinguish safe vs unsafe closure usage
4. ✅ Handle basic higher-order functions (map, filter)
5. 📊 Maintain 0% false positive rate
6. 📊 Improve recall by detecting closure-based vulnerabilities

## Example Test Cases

### Case 1: Vulnerable Closure Capture (Should Detect)
```rust
let tainted = env::args().nth(1);
let closure = || {
    Command::new("sh").arg(&tainted).spawn();  // VULNERABLE
};
closure();
```

### Case 2: Safe Closure with Sanitization (Should Not Detect)
```rust
let tainted = env::args().nth(1);
let safe = sanitize(&tainted);
let closure = || {
    Command::new("sh").arg(&safe).spawn();  // SAFE
};
closure();
```

### Case 3: Closure Passed to Higher-Order Function (Should Detect)
```rust
let args: Vec<_> = env::args().collect();
args.iter().for_each(|arg| {
    Command::new("sh").arg(arg).spawn();  // VULNERABLE
});
```

## References

- MIR Documentation: https://rustc-dev-guide.rust-lang.org/mir/
- Closure Representation: https://rustc-dev-guide.rust-lang.org/closures.html
- Phase 3.5.1 Results: docs/phase3.5.1-results.md
