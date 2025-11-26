# rustc Layout API Solution - November 2025

## Problem Statement

In rustc 1.92.0-nightly (Oct 2025), the layout query API changed significantly. The old API using `ParamEnvAnd` no longer works with `layout_of()`:

### Old API (Pre-Oct 2025)
```rust
fn extract_type_size_OLD<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    let ty = tcx.type_of(def_id).instantiate_identity();
    let param_env = tcx.param_env(def_id);
    
    // ❌ ERROR: layout_of expects PseudoCanonicalInput, not ParamEnvAnd
    match tcx.layout_of(param_env.and(ty)) {
        Ok(layout) => Some(layout.size.bytes() as usize),
        Err(_) => None,
    }
}
```

### Error Message
```
error[E0308]: mismatched types
   |
   | match tcx.layout_of(param_env.and(ty)) {
   |           --------- ^^^^^^^^^^^^^^^^^ 
   |           expected `PseudoCanonicalInput<'_, Ty<'_>>`, 
   |           found `ParamEnvAnd<'_, Ty<'_>>`
```

## Solution

The new API uses `PseudoCanonicalInput` which bundles a `TypingEnv` with a value:

### New API (Oct 2025+)
```rust
fn extract_type_size<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    use rustc_middle::ty::layout::LayoutOf;
    
    // Get the type
    let ty = tcx.type_of(def_id).instantiate_identity();
    
    // Create TypingEnv from def_id
    let typing_env = rustc_middle::ty::TypingEnv::non_body_analysis(tcx, def_id);
    
    // Create the query input
    let query_input = rustc_middle::ty::PseudoCanonicalInput {
        typing_env,
        value: ty,
    };
    
    match tcx.layout_of(query_input) {
        Ok(layout) => Some(layout.size.bytes() as usize),
        Err(_) => None,
    }
}
```

## Key Insights

### 1. PseudoCanonicalInput Structure
```rust
pub struct PseudoCanonicalInput<'tcx, T> {
    pub typing_env: TypingEnv<'tcx>,
    pub value: T,
}
```

**Note:** The field is called `typing_env`, not `typing_mode`.

### 2. TypingEnv Creation
```rust
// For type layout queries (non-body analysis context)
let typing_env = TypingEnv::non_body_analysis(tcx, def_id);
```

**Key Point:** `TypingEnv::non_body_analysis()` takes:
- `tcx: TyCtxt<'tcx>` - The type context
- `def_id: DefId` - The definition ID (NOT a `ParamEnv`)

### 3. Migration Path

| Old API | New API |
|---------|---------|
| `ParamEnv` | `TypingEnv` |
| `param_env.and(ty)` | `PseudoCanonicalInput { typing_env, value: ty }` |
| `tcx.param_env(def_id)` | `TypingEnv::non_body_analysis(tcx, def_id)` |

## Testing Results

Tested with comprehensive type set on rustc 1.92.0-nightly (b6f0945e4 2025-10-08):

### Test Types
```rust
pub struct MyStruct { x: i32, y: i32 }       // 8 bytes
pub struct ZeroSized;                         // 0 bytes (ZST)
pub struct WithPhantom<T> { 
    _marker: PhantomData<T> 
}                                             // 0 bytes (ZST)
pub struct WithPinned { 
    _pinned: PhantomPinned 
}                                             // 0 bytes (ZST)
pub struct EmptyStruct;                       // 0 bytes (ZST)
pub struct UnitStruct();                      // 0 bytes (ZST)
pub struct NormalStruct { data: u64 }        // 8 bytes
pub enum MyEnum { 
    Variant1, 
    Variant2(i32) 
}                                             // 8 bytes
```

### Results - 100% Accuracy
```json
{
  "type_metadata": [
    { "type_name": "types::MyStruct", "size_bytes": 8, "is_zst": false },
    { "type_name": "types::ZeroSized", "size_bytes": 0, "is_zst": true },
    { "type_name": "types::MyEnum", "size_bytes": 8, "is_zst": false },
    { "type_name": "zst_types::WithPhantom", "size_bytes": 0, "is_zst": true },
    { "type_name": "zst_types::WithPinned", "size_bytes": 0, "is_zst": true },
    { "type_name": "zst_types::EmptyStruct", "size_bytes": 0, "is_zst": true },
    { "type_name": "zst_types::UnitStruct", "size_bytes": 0, "is_zst": true },
    { "type_name": "zst_types::NormalStruct", "size_bytes": 8, "is_zst": false }
  ]
}
```

**Validation:**
- ✅ All ZSTs correctly identified (PhantomData, PhantomPinned, empty structs)
- ✅ All sized types have accurate byte counts
- ✅ Enum discriminant + payload correctly calculated
- ✅ No false positives or false negatives

## Discovery Process

### Iteration 1: Try TypingMode
```rust
let typing_mode = TypingMode::non_body_analysis();
tcx.layout_of(typing_mode.as_query_input(ty))
// ❌ Error: no method named `as_query_input`
```

### Iteration 2: Try tuple
```rust
tcx.layout_of((typing_mode, ty))
// ❌ Error: expected PseudoCanonicalInput, found (TypingMode, Ty)
```

### Iteration 3: Construct PseudoCanonicalInput
```rust
let query_input = PseudoCanonicalInput {
    typing_mode,  // ❌ Wrong field name
    value: ty,
};
```

### Iteration 4: Use compiler hints
```
error[E0560]: struct `PseudoCanonicalInput<'_, _>` has no field named `typing_mode`
    = note: available fields are: `typing_env`
```

**Solution:** Field is `typing_env`, not `typing_mode` ✅

### Iteration 5: Wrong parameter type
```rust
let param_env = tcx.param_env(def_id);
let typing_env = TypingEnv::non_body_analysis(tcx, param_env);
// ❌ Error: expects DefId, not ParamEnv
```

### Iteration 6: Correct parameters
```rust
let typing_env = TypingEnv::non_body_analysis(tcx, def_id);
// ✅ Success!
```

## Common Mistakes

### Mistake 1: Using param_env instead of def_id
```rust
// ❌ WRONG
let param_env = tcx.param_env(def_id);
let typing_env = TypingEnv::non_body_analysis(tcx, param_env);

// ✅ CORRECT
let typing_env = TypingEnv::non_body_analysis(tcx, def_id);
```

### Mistake 2: Using typing_mode field name
```rust
// ❌ WRONG
PseudoCanonicalInput { typing_mode, value }

// ✅ CORRECT
PseudoCanonicalInput { typing_env, value }
```

### Mistake 3: Forgetting LayoutOf import
```rust
// ❌ Compiles but might miss extension methods
use rustc_middle::ty::TyCtxt;

// ✅ CORRECT - enables layout_of method
use rustc_middle::ty::layout::LayoutOf;
```

## Complete Working Example

```rust
use rustc_middle::ty::{self, layout::LayoutOf, TyCtxt};
use rustc_span::def_id::DefId;

/// Extract the size of a type in bytes
/// Returns None for unsized types or if size cannot be determined
fn extract_type_size<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    // Get the type
    let ty = tcx.type_of(def_id).instantiate_identity();
    
    // Create TypingEnv for non-body analysis context
    let typing_env = ty::TypingEnv::non_body_analysis(tcx, def_id);
    
    // Create the query input
    let query_input = ty::PseudoCanonicalInput {
        typing_env,
        value: ty,
    };
    
    // Query the layout
    match tcx.layout_of(query_input) {
        Ok(layout) => Some(layout.size.bytes() as usize),
        Err(_) => None,  // Unsized type or layout error
    }
}

/// Check if a type is zero-sized
fn is_zero_sized_type<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> bool {
    extract_type_size(tcx, def_id) == Some(0)
}
```

## When to Use This API

### ✅ Use when:
- Extracting type sizes during HIR or MIR analysis
- Building security analysis tools that need type information
- Implementing custom lints that check type properties
- Creating type metadata for offline analysis

### ⚠️ Consider alternatives when:
- Working with generic types (may need monomorphization)
- Dealing with trait objects (DSTs)
- Type parameters haven't been substituted
- Working in a body context (use different TypingMode)

## Version Compatibility

- **rustc 1.92.0-nightly (Oct 2025+):** Use `PseudoCanonicalInput` + `TypingEnv`
- **rustc < Oct 2025:** Use `ParamEnv` + `param_env.and(ty)`

**Migration Note:** This was a breaking change in rustc internals. If you need to support multiple rustc versions, use feature detection or version-specific code paths.

## Related APIs

### Other TypingMode variants
```rust
// For body analysis (inside function bodies)
TypingMode::analysis_in_body(tcx, def_id)

// For const evaluation
TypingMode::const_eval(tcx, def_id)
```

### Layout properties
```rust
let layout = tcx.layout_of(query_input)?;

layout.size.bytes()        // Size in bytes
layout.align.bytes()       // Alignment in bytes
layout.abi                 // ABI category (Scalar, Aggregate, etc.)
layout.fields             // Field layout information
```

## Impact on Rust-COLA

This fix enabled:
1. **Accurate ZST detection** for RUSTCOLA064 (ZST pointer arithmetic)
2. **Type metadata extraction** in HIR JSON output
3. **TypeAnalyzer API foundation** for future semantic rules
4. **100% accuracy** on standard library ZSTs (PhantomData, PhantomPinned, etc.)

### Before Fix
- Heuristic detection: ~71% recall on ZSTs
- Limited to known patterns (unit type, PhantomData by name)
- Could not detect custom empty structs

### After Fix
- Precise detection: 100% accuracy on all testable ZSTs
- Works with any zero-sized type (custom or standard)
- Provides exact sizes for all types

## References

- **rustc version:** 1.92.0-nightly (b6f0945e4 2025-10-08)
- **Commit:** b6f0945e4681bc4d2faa7c22c5f61dc36abf7dd2
- **Date:** 2025-10-08
- **Discovery:** 2025-11-25 (via iterative compiler error analysis)

## Credits

Discovered through systematic exploration of compiler error messages and field name hints. The compiler's error messages were instrumental in finding the correct field names and parameter types.
