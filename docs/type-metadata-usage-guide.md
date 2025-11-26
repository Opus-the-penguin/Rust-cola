# Using Type Metadata in Rust-COLA

This guide shows how to use the type metadata system in Rust-COLA for security analysis.

## Overview

Rust-COLA provides two complementary APIs for type queries:

1. **HirQuery** - Offline analysis of HIR JSON metadata
2. **TypeAnalyzer** - Live queries during compilation (future use)

## HirQuery - Offline Analysis

Use `HirQuery` when analyzing HIR JSON files produced by `cargo-cola --hir-json`.

### Basic Usage

```rust
use mir_extractor::{HirPackage, HirQuery};

// Load HIR JSON
let hir_json = std::fs::read_to_string("output.hir.json")?;
let package: HirPackage = serde_json::from_str(&hir_json)?;

// Create query interface
let query = HirQuery::new(&package);

// Query type sizes
if let Some(size) = query.size_of("my_crate::MyStruct")? {
    println!("MyStruct is {} bytes", size);
}

// Check if type is zero-sized
if query.is_zst("my_crate::EmptyStruct")? {
    println!("EmptyStruct is a ZST");
}
```

### Finding All ZSTs

```rust
// Iterate over all zero-sized types
for zst in query.find_all_zsts() {
    println!("Found ZST: {} ({} bytes)", 
        zst.type_name, 
        zst.size_bytes.unwrap_or(0)
    );
}
```

### Custom Type Queries

```rust
// Find all types larger than 1KB
for meta in query.find_types(|m| {
    m.size_bytes.map(|s| s > 1024).unwrap_or(false)
}) {
    println!("Large type: {} ({} bytes)", meta.type_name, meta.size_bytes.unwrap());
}
```

### ZST Pointer Detection

```rust
// Check if a MIR line contains a pointer to a ZST
let mir_line = "_2 = std::ptr::const_ptr::<impl *const PhantomData<T>>::offset(...)";

if query.looks_like_zst_pointer(mir_line) {
    println!("Warning: Pointer arithmetic on ZST detected!");
}
```

## Enhanced RUSTCOLA064 Example

Here's how to enhance the ZST pointer arithmetic rule with HIR metadata:

```rust
impl Rule for ZSTPointerArithmeticRule {
    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Load HIR metadata if available
        let hir_package = load_hir_if_available(package);
        let query = hir_package.as_ref().map(|p| HirQuery::new(p));

        for function in &package.functions {
            for line in &function.body {
                // Check heuristics first (fast)
                if looks_like_zst_pointer_arithmetic(line) {
                    findings.push(create_finding(function, line));
                    continue;
                }

                // If HIR is available, check for custom ZSTs
                if let Some(q) = &query {
                    if q.looks_like_zst_pointer(line) {
                        findings.push(create_finding(function, line));
                    }
                }
            }
        }

        findings
    }
}
```

## HIR Type Metadata Structure

The `HirTypeMetadata` struct contains:

```rust
pub struct HirTypeMetadata {
    /// Full type path (e.g., "my_crate::module::MyStruct")
    pub type_name: String,
    
    /// Size in bytes (None for unsized types like [T] or dyn Trait)
    pub size_bytes: Option<usize>,
    
    /// Whether the type is zero-sized (computed from size_bytes == Some(0))
    pub is_zst: bool,
    
    /// Whether the type implements Send (future: to be populated)
    pub is_send: Option<bool>,
    
    /// Whether the type implements Sync (future: to be populated)
    pub is_sync: Option<bool>,
}
```

## Generating HIR JSON

To produce HIR JSON with type metadata:

```bash
# Generate HIR JSON during analysis
cargo-cola --crate-path ./my-crate --hir-json output.hir.json

# The JSON will contain a type_metadata array
cat output.hir.json | jq '.type_metadata'
```

Example output:

```json
{
  "type_metadata": [
    {
      "type_name": "my_crate::Config",
      "size_bytes": 64,
      "is_zst": false
    },
    {
      "type_name": "my_crate::EmptyMarker",
      "size_bytes": 0,
      "is_zst": true
    }
  ]
}
```

## Type Size Extraction Implementation

The type size extraction uses rustc's layout API:

```rust
fn extract_type_size<'tcx>(tcx: TyCtxt<'tcx>, def_id: DefId) -> Option<usize> {
    use rustc_middle::ty::layout::LayoutOf;
    
    let ty = tcx.type_of(def_id).instantiate_identity();
    
    // Create TypingEnv for layout query
    let typing_env = rustc_middle::ty::TypingEnv::non_body_analysis(tcx, def_id);
    
    // Create query input
    let query_input = rustc_middle::ty::PseudoCanonicalInput {
        typing_env,
        value: ty,
    };
    
    // Query layout
    match tcx.layout_of(query_input) {
        Ok(layout) => Some(layout.size.bytes() as usize),
        Err(_) => None,
    }
}
```

## Best Practices

### 1. Combine Heuristics with Metadata

```rust
// Fast path: check heuristics first
if quick_heuristic_check(line) {
    return true;
}

// Slow path: check metadata if available
if let Some(query) = hir_query {
    return query.is_zst(extract_type_name(line))?;
}

false
```

### 2. Cache HIR Queries

```rust
struct CachedQuery {
    hir: Option<HirPackage>,
    query: Option<HirQuery<'static>>,
}

impl CachedQuery {
    fn is_zst(&self, type_name: &str) -> bool {
        self.query
            .as_ref()
            .and_then(|q| q.is_zst(type_name).ok())
            .unwrap_or(false)
    }
}
```

### 3. Handle Missing Metadata Gracefully

```rust
// HIR metadata may not be available for:
// - Generic types (not monomorphized)
// - External crates  
// - Types with errors

match query.size_of(type_name)? {
    Some(0) => println!("Definite ZST"),
    Some(n) => println!("Sized type: {} bytes", n),
    None => println!("Unknown or unsized - fall back to heuristics"),
}
```

## Future Enhancements

### Planned Features

1. **Send/Sync Detection**
   - Pre-compute during HIR extraction
   - Store in `is_send` and `is_sync` fields
   - Enable rules checking thread safety

2. **Trait Implementation Queries**
   - Pre-compute common traits (Clone, Copy, Default)
   - Store in extended metadata
   - Enable semantic analysis rules

3. **Generic Type Support**
   - Track monomorphization instances
   - Provide size for instantiated generics
   - Link to source generic definitions

## Common Patterns

### Pattern 1: Detect ZST Containers

```rust
// Find all types that contain only ZST fields
for meta in query.all_types() {
    if meta.is_zst && meta.type_name.contains("Wrapper") {
        println!("ZST wrapper type: {}", meta.type_name);
    }
}
```

### Pattern 2: Size-Based Warnings

```rust
// Warn about large stack allocations
for meta in query.find_types(|m| m.size_bytes.map(|s| s > 4096).unwrap_or(false)) {
    eprintln!("Warning: Large type on stack: {} ({} bytes)", 
        meta.type_name, 
        meta.size_bytes.unwrap()
    );
}
```

### Pattern 3: Cross-Reference with MIR

```rust
// Find functions that create large local variables
for function in mir_package.functions {
    for local in &function.locals {
        if let Some(size) = query.size_of(&local.ty)? {
            if size > 1024 {
                println!("Large local in {}: {} bytes", function.name, size);
            }
        }
    }
}
```

## Testing Your Rules

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zst_detection_with_metadata() {
        let hir_json = r#"{
            "crate_name": "test",
            "crate_root": "/tmp",
            "target": {"kind": "lib", "crate_name": "test"},
            "items": [],
            "functions": [],
            "type_metadata": [
                {
                    "type_name": "test::Empty",
                    "size_bytes": 0,
                    "is_zst": true
                }
            ]
        }"#;
        
        let package: HirPackage = serde_json::from_str(hir_json).unwrap();
        let query = HirQuery::new(&package);
        
        assert!(query.is_zst("test::Empty").unwrap());
        assert_eq!(query.size_of("test::Empty").unwrap(), Some(0));
    }
}
```

## Performance Tips

1. **Load HIR once**: Cache HirPackage, don't reload per-function
2. **Use heuristics first**: Metadata lookups are slower than string matching
3. **Pre-filter candidates**: Only check metadata for suspicious lines
4. **Batch queries**: Process multiple types in one pass

## Troubleshooting

### Type not found in metadata

```rust
// Type may be:
// - From external crate (not analyzed)
// - Generic (not instantiated)
// - Compiler built-in (primitives)

if query.get_type(type_name).is_none() {
    // Fall back to heuristics or skip
    eprintln!("Type not in metadata: {}", type_name);
}
```

### Size is None

```rust
// Unsized types return None:
// - Trait objects: dyn Trait
// - Slices: [T]
// - str

match meta.size_bytes {
    Some(size) => println!("Sized: {} bytes", size),
    None => println!("Unsized type (DST)"),
}
```

## See Also

- `docs/rustc-layout-api-solution.md` - Technical details of layout API
- `docs/tier3-phase2-progress.md` - Implementation progress
- `mir-extractor/src/hir_query.rs` - Full API documentation
- `mir-extractor/src/type_analyzer.rs` - Compile-time API (future)
