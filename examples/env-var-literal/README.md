# RUSTCOLA047: Environment Variable Literal Detection

This example demonstrates why environment variable names should be defined as constants rather than string literals.

## The Problem

Using string literals for environment variable names leads to several maintenance issues:

```rust
// PROBLEMATIC: String literal
fn get_home() -> Option<String> {
    env::var("HOME").ok()  // Typo risk, hard to maintain
}
```

## The Solution

Define environment variable names as constants:

```rust
// RECOMMENDED: Constant
const HOME_DIR: &str = "HOME";

fn get_home() -> Option<String> {
    env::var(HOME_DIR).ok()  // Clear, maintainable, refactorable
}
```

## Benefits of Using Constants

### 1. **Compile-Time Safety**
```rust
const HOME_DIR: &str = "HOME";
// Typo in constant name caught by compiler
env::var(HOME_DRI).ok() // ❌ Compile error!

// vs
env::var("HOMR").ok()   // ✅ Compiles but wrong at runtime
```

### 2. **Single Source of Truth**
```rust
const DATABASE_URL: &str = "DATABASE_URL";

// Change once, affects all uses
fn connect() { env::var(DATABASE_URL); }
fn log_config() { env::var(DATABASE_URL); }
fn validate() { env::var(DATABASE_URL); }
```

### 3. **Self-Documentation**
```rust
// Constants clearly document env var dependencies
const SMTP_HOST: &str = "SMTP_HOST";
const SMTP_PORT: &str = "SMTP_PORT";
const SMTP_USERNAME: &str = "SMTP_USERNAME";
```

### 4. **IDE Support**
- **Find all usages** of a specific env var
- **Rename refactoring** works correctly
- **Auto-completion** prevents typos
- **Go to definition** shows where var is used

### 5. **Easier Auditing**
```bash
# Find all env vars used in codebase
$ grep -n "const.*&str.*=" src/*.rs | grep -v "//"
```

## Test Results

Expected findings:
- **7 vulnerable functions** using string literals
- **4 safe functions** using constants - 0 false positives

### Vulnerable Functions
1. `vulnerable_read_home_literal` - Direct "HOME" literal
2. `vulnerable_read_path_literal` - Direct "PATH" literal
3. `vulnerable_read_user_literal` - Direct "USER" literal
4. `vulnerable_multiple_literals` - Multiple literals
5. `vulnerable_configure_logging_literal` - "RUST_LOG" literal
6. `vulnerable_typo_risk` - Demonstrates typo "HOMR"
7. `vulnerable_repeated_literal` - Repeated "DATABASE_URL"

### Safe Functions
1. `safe_read_home_with_const` - Uses HOME_DIR constant
2. `safe_read_path_with_const` - Uses PATH_VAR constant
3. `safe_read_user_with_const` - Uses USER_NAME constant
4. `safe_configure_logging_with_const` - Uses RUST_LOG constant

### Edge Cases
- `edge_case_dynamic_var_name` - Runtime variable (acceptable)
- `edge_case_platform_specific` - Platform-specific var

## Real-World Impact

### Typo Prevention
```rust
// Literal: Typo goes unnoticed until runtime
env::var("DTABASE_URL")  // Oops! Missing 'A'

// Constant: Typo caught immediately
const DTABASE_URL: &str = "DATABASE_URL";  // Name tells us it's wrong
env::var(DTABASE_URL)  // Would work, but const name shows mistake
```

### Refactoring Safety
```rust
// Need to change "DATABASE_URL" to "DB_CONNECTION_STRING"
// With literals: Error-prone find/replace
// With constants: Change one line
const DATABASE_URL: &str = "DB_CONNECTION_STRING";
```

### Configuration Overview
```rust
// At a glance, see all env var dependencies:
const API_KEY: &str = "API_KEY";
const API_SECRET: &str = "API_SECRET";
const API_ENDPOINT: &str = "API_ENDPOINT";
const API_TIMEOUT: &str = "API_TIMEOUT_SECONDS";
```

## Dylint Parity

This rule provides parity with Dylint's `env_literal` lint, encouraging the same best practice of using constants for environment variable names.

## References

- **Dylint**: `env_literal` lint
- **Rust Best Practices**: Const declarations for configuration
- **Maintenance**: DRY principle (Don't Repeat Yourself)

## Fix Guidance

1. **Define constants** at module or crate level
2. **Use descriptive names** that match the env var purpose
3. **Group related vars** together
4. **Document expected values** in comments

```rust
/// Database configuration
const DB_HOST: &str = "DATABASE_HOST";     // e.g., "localhost"
const DB_PORT: &str = "DATABASE_PORT";     // e.g., "5432"
const DB_NAME: &str = "DATABASE_NAME";     // e.g., "myapp"
```
