# Phase 3.6: Field-Sensitive Taint Analysis - Design Document

**Date**: November 12, 2025  
**Status**: Design Phase  
**Goal**: Track taint at struct field granularity to improve precision

## Problem Statement

Current taint analysis treats entire structs as tainted when any field is tainted. This leads to **false positives** when:

1. Only one field of a struct receives tainted data
2. Clean fields are used in operations (incorrectly flagged as vulnerable)
3. Different fields have different security levels

### Example False Positive

```rust
struct UserData {
    username: String,  // Clean
    password: String,  // Tainted from env
    email: String,     // Clean
}

let mut user = UserData::default();
user.username = "admin".to_string();           // Clean
user.password = env::args().nth(1).unwrap();  // TAINTED
user.email = "admin@example.com".to_string(); // Clean

// Current analysis: VULNERABLE (incorrect!)
// Should be: SAFE - username is not tainted
Command::new("sh").arg(&user.username).spawn();

// Current analysis: VULNERABLE (correct)
// Should be: VULNERABLE - password is tainted  
Command::new("sh").arg(&user.password).spawn();
```

**Current Behavior**: Both sink calls flagged as vulnerable  
**Desired Behavior**: Only the second sink call flagged as vulnerable

## MIR Field Access Patterns

### Flat Struct Fields

**Source Code**:
```rust
struct UserData {
    username: String,  // field index 0
    password: String,  // field index 1
    email: String,     // field index 2
}
```

**MIR Pattern**:
```mir
// Field assignment
(_1.0: std::string::String) = move _2;  // user.username = _2
(_1.1: std::string::String) = move _4;  // user.password = _4
(_1.2: std::string::String) = move _8;  // user.email = _8

// Field read
_15 = &(_1.0: std::string::String);     // &user.username
_21 = &(_1.1: std::string::String);     // &user.password
```

**Key Observations**:
- Field access: `(_VAR.INDEX: TYPE)`
- Index starts at 0
- Type is explicitly annotated

### Nested Struct Fields

**Source Code**:
```rust
struct Credentials {
    username: String,  // field index 0
    password: String,  // field index 1
}

struct Account {
    id: u32,              // field index 0
    credentials: Credentials,  // field index 1
    active: bool,         // field index 2
}
```

**MIR Pattern**:
```mir
// Nested field assignment
((_1.1: Credentials).1: std::string::String) = move _6;
// account.credentials.password = _6

// Nested field read
_22 = &((_1.1: Credentials).0: std::string::String);
// &account.credentials.username

_28 = &((_1.1: Credentials).1: std::string::String);
// &account.credentials.password
```

**Key Observations**:
- Nested access: `((_VAR.OUTER_INDEX: OUTER_TYPE).INNER_INDEX: INNER_TYPE)`
- Can chain arbitrarily deep
- Each level has type annotation

### Tuple Struct Fields

**Source Code**:
```rust
struct Config(String, String, u32);
//           field 0, field 1, field 2
```

**MIR Pattern**: Same as regular structs - uses numeric indices

```mir
(_1.0: std::string::String) = move _2;  // config.0 = _2
(_1.1: std::string::String) = move _4;  // config.1 = _4
```

## Proposed Design

### 1. Field Path Representation

```rust
/// Represents a path to a struct field
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldPath {
    /// Base variable (e.g., "_1", "_3")
    pub base_var: String,
    
    /// Field indices from root to leaf (e.g., [1, 2] for _1.1.2)
    pub indices: Vec<usize>,
}

impl FieldPath {
    /// Create from string like "(_1.1: Type).2: Type2" 
    pub fn from_mir_expr(expr: &str) -> Option<Self>;
    
    /// Convert to canonical string: "_1.1.2"
    pub fn to_string(&self) -> String;
    
    /// Check if this path is a prefix of another
    /// Example: _1.1 is prefix of _1.1.2
    pub fn is_prefix_of(&self, other: &FieldPath) -> bool;
}
```

### 2. Field Taint State

```rust
/// Taint state for a specific field
#[derive(Debug, Clone)]
pub enum FieldTaint {
    /// Field is clean
    Clean,
    
    /// Field is tainted
    Tainted {
        source_type: String,
        source_location: String,
    },
    
    /// Field was sanitized
    Sanitized {
        sanitizer: String,
    },
    
    /// Unknown (not yet analyzed)
    Unknown,
}

/// Tracks taint for all fields of all variables
pub struct FieldTaintMap {
    /// Maps field paths to taint states
    /// Example: "_1.1.2" -> Tainted
    fields: HashMap<FieldPath, FieldTaint>,
    
    /// Tracks which variables are structs (need field tracking)
    struct_vars: HashSet<String>,
}

impl FieldTaintMap {
    /// Set taint for a specific field
    pub fn set_field_taint(&mut self, path: FieldPath, taint: FieldTaint);
    
    /// Get taint for a specific field
    pub fn get_field_taint(&self, path: &FieldPath) -> FieldTaint;
    
    /// When entire struct is assigned, propagate to all known fields
    pub fn set_struct_taint(&mut self, base_var: &str, taint: FieldTaint);
    
    /// Get most specific taint (checks field, then parent, then base)
    pub fn get_taint_for_expr(&self, expr: &str) -> FieldTaint;
}
```

### 3. Field Projection Parsing

```rust
pub mod field_projection {
    use super::*;
    
    /// Parse field access from MIR expression
    /// Input: "(_1.1: Credentials)"
    /// Output: FieldPath { base_var: "_1", indices: [1] }
    pub fn parse_field_access(expr: &str) -> Option<FieldPath>;
    
    /// Parse nested field access
    /// Input: "((_1.1: Credentials).2: String)"
    /// Output: FieldPath { base_var: "_1", indices: [1, 2] }
    pub fn parse_nested_field_access(expr: &str) -> Option<FieldPath>;
    
    /// Detect if expression is a field access
    pub fn is_field_access(expr: &str) -> bool {
        expr.contains("(_") && expr.contains(".")
    }
    
    /// Extract all field paths from a complex expression
    pub fn extract_field_paths(expr: &str) -> Vec<FieldPath>;
}
```

### 4. Integration with Taint Analysis

**Modified process_statement**:

```rust
fn process_statement(
    &self,
    block_id: &str,
    statement: &str,
    field_taint: &mut FieldTaintMap,  // NEW: field-level tracking
    sink_calls: &mut Vec<SinkCall>,
    source_calls: &mut Vec<SourceCall>,
    sanitizer_calls: &mut Vec<SanitizerCall>,
) {
    // Parse assignment
    if let Some((lhs, rhs)) = Self::parse_assignment(statement) {
        
        // Check if LHS is a field access
        if let Some(lhs_field) = parse_field_access(&lhs) {
            // Field assignment: user.password = env::args()
            
            if Self::is_source_call(&rhs) {
                // Taint only this specific field
                field_taint.set_field_taint(lhs_field, FieldTaint::Tainted {
                    source_type: "environment".to_string(),
                    source_location: rhs.clone(),
                });
            } else if let Some(rhs_field) = parse_field_access(&rhs) {
                // Field-to-field: user2.password = user1.password
                let taint = field_taint.get_field_taint(&rhs_field);
                field_taint.set_field_taint(lhs_field, taint);
            }
        } else {
            // Whole struct assignment: user = tainted_struct
            // Propagate to all fields
            if let Some(rhs_var) = Self::extract_variable(&rhs) {
                // Mark this as a struct that needs field tracking
                field_taint.mark_as_struct(&lhs);
            }
        }
    }
    
    // Check sink calls
    if Self::is_sink_call(statement) {
        // Extract argument
        if let Some(arg_field) = extract_field_from_arg(statement) {
            // Check if THIS SPECIFIC FIELD is tainted
            let taint = field_taint.get_field_taint(&arg_field);
            if matches!(taint, FieldTaint::Tainted { .. }) {
                sink_calls.push(SinkCall {
                    block_id: block_id.to_string(),
                    statement: statement.to_string(),
                    sink_function: "Command::spawn".to_string(),
                    tainted_args: vec![arg_field.to_string()],
                });
            }
        }
    }
}
```

## Taint Propagation Rules

### Rule 1: Field Assignment from Source
```mir
(_1.1: String) = env::args()
```
→ Mark `_1.1` as **Tainted**  
→ `_1.0`, `_1.2` remain **Clean**

### Rule 2: Field-to-Field Copy
```mir
(_2.1: String) = (_1.1: String)
```
→ `_2.1` inherits taint state of `_1.1`  
→ Other fields of `_2` unaffected

### Rule 3: Whole Struct Assignment
```mir
_2 = _1
```
→ **Conservative**: All fields of `_2` inherit from corresponding fields of `_1`  
→ If `_1` structure unknown, mark entire `_2` as tainted

### Rule 4: Nested Field Assignment
```mir
((_1.1: Credentials).2: String) = source
```
→ Mark `_1.1.2` as **Tainted**  
→ `_1.1.0`, `_1.1.1`, `_1.0`, `_1.2` remain **Clean**

### Rule 5: Reference to Field
```mir
_3 = &(_1.1: String)
```
→ `_3` is a **field reference**  
→ Track: `_3` → `_1.1`  
→ Dereference of `_3` has same taint as `_1.1`

## Test Cases

### Test 1: Partial Struct Taint (False Positive Fix)
```rust
let mut user = UserData::default();
user.username = "admin".to_string();           // _1.0 = clean
user.password = env::args().nth(1).unwrap();  // _1.1 = TAINTED
user.email = "admin@example.com".to_string(); // _1.2 = clean

Command::new("sh").arg(&user.username).spawn();  // Safe (was false positive)
Command::new("sh").arg(&user.password).spawn();  // Vulnerable (correct)
```

**Expected**:
- Taint map: `{_1.1: Tainted, _1.0: Clean, _1.2: Clean}`
- First sink: **SAFE** (field `_1.0` is clean)
- Second sink: **VULNERABLE** (field `_1.1` is tainted)

### Test 2: Nested Fields
```rust
account.credentials.password = env::args().nth(1).unwrap();  // _1.1.1 = TAINTED

Command::new("sh").arg(&account.credentials.username).spawn();  // Safe
Command::new("sh").arg(&account.credentials.password).spawn();  // Vulnerable
```

**Expected**:
- Taint map: `{_1.1.1: Tainted, _1.1.0: Clean, _1.0: Clean, _1.2: Clean}`
- First sink: **SAFE** (field `_1.1.0` is clean)
- Second sink: **VULNERABLE** (field `_1.1.1` is tainted)

### Test 3: Field-to-Field Propagation
```rust
user1.password = env::args().nth(1).unwrap();  // _1.1 = TAINTED
user2.password = user1.password.clone();        // _2.1 = TAINTED (propagated)
user2.username = "clean".to_string();           // _2.0 = Clean

Command::new("sh").arg(&user2.username).spawn();  // Safe
Command::new("sh").arg(&user2.password).spawn();  // Vulnerable
```

**Expected**:
- Taint map: `{_1.1: Tainted, _2.1: Tainted, _2.0: Clean}`
- First sink: **SAFE**
- Second sink: **VULNERABLE**

## Implementation Plan

### Phase 1: Data Structures (Task 2)
- [ ] Create `FieldPath` struct
- [ ] Create `FieldTaint` enum
- [ ] Create `FieldTaintMap` struct
- [ ] Implement basic operations

### Phase 2: Parsing (Task 3)
- [ ] Implement `parse_field_access()` for flat fields
- [ ] Implement `parse_nested_field_access()` for nested fields
- [ ] Add field extraction from complex expressions
- [ ] Unit tests for parsing

### Phase 3: Taint Propagation (Task 4)
- [ ] Modify taint analysis to use `FieldTaintMap`
- [ ] Implement field assignment handling
- [ ] Implement field-to-field propagation
- [ ] Handle whole struct assignments

### Phase 4: Integration (Task 5)
- [ ] Update `PathSensitiveTaintAnalysis`
- [ ] Modify `process_statement()` for field support
- [ ] Update sink detection to check specific fields
- [ ] Handle field references

### Phase 5: Testing (Task 6)
- [ ] Test partial struct taint
- [ ] Test nested fields
- [ ] Test field-to-field propagation
- [ ] Test tuple structs
- [ ] Compare with non-field-sensitive results

## Expected Benefits

### Precision Improvement

**Without Field-Sensitive Analysis**:
```
Test: test_partial_struct_taint
  Sinks detected: 2/2 (100% - both flagged)
  False positives: 1 (user.username sink)
  Precision: 50%
```

**With Field-Sensitive Analysis**:
```
Test: test_partial_struct_taint
  Sinks detected: 1/2 (only password flagged)
  False positives: 0
  Precision: 100%
```

### Real-World Impact

Common patterns that benefit:
- HTTP request objects (only body is tainted, not headers)
- Database models (user input fields vs. system fields)
- Configuration structs (user settings vs. defaults)
- Authentication tokens (secret vs. public claims)

## Challenges and Limitations

### Challenge 1: Type Information

MIR doesn't always preserve field names, only indices. We must:
- Track field indices
- Cannot provide field names in error messages (only indices)
- **Mitigation**: Use type information when available

### Challenge 2: Dynamic Field Access

```rust
let field_name = env::args().nth(1).unwrap();
let value = match field_name.as_str() {
    "username" => &user.username,
    "password" => &user.password,
    _ => &user.email,
};
```

**Problem**: Cannot statically determine which field is accessed  
**Solution**: Conservative - assume all fields might be accessed

### Challenge 3: Array/Vec Fields

```rust
struct Data {
    items: Vec<String>,  // Which elements are tainted?
}
```

**Current Scope**: Treat entire Vec as single field  
**Future Work**: Element-level tracking (Phase 3.7)

### Challenge 4: Performance

Tracking individual fields increases memory usage:
- Old: One taint state per variable
- New: One taint state per field per variable

**Estimated Impact**:
- Structs with 5 fields: 5x memory per struct variable
- Typical function: 20 variables, 5 are structs → 100 vs. 120 taint states
- **Acceptable**: Still O(n) where n = variables × avg_fields

## Success Criteria

1. ✅ Parse flat struct field access from MIR
2. ✅ Parse nested struct field access from MIR
3. ✅ Track taint independently for each field
4. ✅ Detect vulnerabilities with field-level precision
5. ✅ Reduce false positives by ≥30% on test suite
6. ✅ Performance degradation <20% vs. non-field-sensitive

## Next Steps

1. Implement `FieldPath` and `FieldTaintMap` (Task 2)
2. Implement field projection parsing (Task 3)
3. Extend taint propagation (Task 4)
4. Integrate with path-sensitive analysis (Task 5)
5. Test and document (Task 6)

---

**End of Design Document**
