# RUSTCOLA049: Crate-Wide Allow Attribute Detection

This example demonstrates why crate-wide `#![allow(...)]` attributes are problematic and how to use more targeted suppression.

## The Problem

Crate-wide `#![allow(...)]` attributes disable lints for the **entire crate**, reducing security and code quality coverage.

```rust
// PROBLEMATIC: Disables lint for ENTIRE crate
#![allow(dead_code)]

// Impact: Now ALL dead code in ALL modules is hidden
fn unused_function_1() {}
fn unused_function_2() {}
fn unused_security_check() {}  // ⚠️ This might be important!
```

## Why It's Dangerous

### 1. **Hides Security Issues**
```rust
#![allow(clippy::all)]  // ❌ VERY BAD

// This now hides:
// - clippy::suspicious_else_formatting (auth bypass bugs)
// - clippy::suspicious_open_options (file security)
// - clippy::zombie_processes (resource leaks)
// - clippy::invalid_regex (ReDoS vulnerabilities)
```

### 2. **Obscures Technical Debt**
```rust
#![allow(unused_variables, dead_code)]

// Legitimate problems are now invisible:
fn process_payment(amount: f64, user: &str) {
    let tax = calculate_tax(amount); // Never used! Charging wrong amount?
    charge(amount); // Bug: Should be amount + tax
}
```

### 3. **Non-Local Effect**
```rust
// At top of lib.rs:
#![allow(clippy::cognitive_complexity)]

// 3000 lines later in utils.rs:
fn complex_auth_logic(...) {
    // This function is too complex and contains bugs,
    // but the warning is suppressed by the crate-level allow
    // that you forgot about from lib.rs
}
```

### 4. **Maintenance Burden**
- Future developers don't know WHY lint was disabled
- Hard to track which code actually needs suppression
- Suppression outlives its justification
- Can't incrementally fix issues

## Recommended Pattern

### ✅ Item-Level Suppression
```rust
// GOOD: Scoped to specific item
#[allow(dead_code)]
fn intentionally_unused_for_compatibility() {
    // Clear why this exists and why it's allowed
}

// GOOD: Narrow scope with justification
#[allow(clippy::too_many_arguments)]
#[deprecated(note = "TODO: Refactor to use config struct")]
fn legacy_function(
    arg1: i32, arg2: i32, arg3: i32, arg4: i32,
    arg5: i32, arg6: i32, arg7: i32, arg8: i32,
) {
    // Temporary suppression with plan to fix
}
```

### ✅ Module-Level When Justified
```rust
#[cfg(test)]
#[allow(dead_code)]
mod test_helpers {
    // Test utilities that aren't all used in every test file
    pub fn helper1() {}
    pub fn helper2() {}
}
```

## Real-World Examples

### Authentication Bypass
```rust
#![allow(clippy::suspicious_else_formatting)]

// This bug is now invisible:
if user.is_admin()
    grant_admin_access();
else
grant_admin_access();  // Looks like else, but it's not!
```

### File Security
```rust
#![allow(clippy::suspicious_open_options)]

// This security issue is now hidden:
OpenOptions::new()
    .write(true)
    .create(true)
    // Missing .truncate(true) - file contains old data!
    .open("secrets.txt")?;
```

### Resource Leaks
```rust
#![allow(clippy::zombie_processes)]

// This resource leak is now invisible:
Command::new("background_worker")
    .spawn()?;
// Missing .wait() - creates zombie process!
```

## Test Results

Expected findings:
- **0 findings** in this example (no actual #![allow(...)] present)
- In real code with crate-level allows, would detect all instances

### What Would Be Detected
If the code contained:
```rust
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(clippy::cognitive_complexity)]
```

Each would generate a RUSTCOLA049 finding.

## Scope Comparison

| Pattern | Scope | Visibility | Maintenance |
|---------|-------|------------|-------------|
| `#![allow(lint)]` | Entire crate | Hidden | Hard |
| `#[allow(lint)]` on module | One module | Clear | Medium |
| `#[allow(lint)]` on item | One item | Very clear | Easy |

## Fix Guidance

### 1. **Remove Crate-Level Allows**
```bash
# Find all crate-level allows
rg '#!\[allow' --type rust
```

### 2. **Move to Item-Level**
```rust
// Before: lib.rs
#![allow(dead_code)]

// After: Specific items
#[allow(dead_code)]
fn specific_unused_function() { }
```

### 3. **Fix the Root Cause**
```rust
// Better: Remove the unused code
// fn unused_function() { } // Delete this!

// Or make it used
pub fn now_used_function() { }
```

### 4. **Document Suppressions**
```rust
#[allow(clippy::too_many_arguments)]
/// TODO(cleanup): Refactor to use a configuration struct
/// Tracked in issue #123
fn needs_refactoring(...) { }
```

## Dylint Parity

This rule provides parity with Dylint's `crate_wide_allow` lint, encouraging best practices for lint suppression hygiene.

## References

- **Dylint**: `crate_wide_allow` lint
- **Rust RFC 2103**: Attribute scoping
- **Clippy Documentation**: Lint configuration best practices

## CI/CD Integration

```bash
# Fail builds with crate-wide allows
cargo clippy -- -D clippy::crate_wide_allow

# Or use rustcola
cargo run -p mir-extractor -- --crate-path . --out-dir out/
```

Remember: **Suppress narrowly, document thoroughly, fix eventually!**
