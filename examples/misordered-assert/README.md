# RUSTCOLA050: Misordered assert_eq Arguments Detection

This example demonstrates why argument order matters in `assert_eq!` and how misordering creates confusing error messages.

## The Problem

`assert_eq!` shows error messages as "left == right". When arguments are misordered, error messages become confusing:

```rust
// MISORDERED:
let result = calculate();
assert_eq!(42, result);  // ❌ Expected first, actual second

// When it fails:
// assertion failed: `(left == right)`
//   left: `42`,        <- This looks like what we got
//  right: `100`        <- This looks like what we expected
// But it's backwards!
```

## The Convention

**assert_eq!(actual, expected)**

- First argument: The value you're testing (actual)
- Second argument: What you expect it to be (expected)

This makes error messages read naturally:
```
left: [what you got]
right: [what you expected]
```

## Examples

### ❌ Misordered (Confusing)
```rust
#[test]
fn test_calculation() {
    let result = add(2, 3);
    assert_eq!(5, result);  // Literal first = wrong order
}

// Fails as:
// left: `5`,  <- Looks like result but it's the expected value!
// right: `6`  <- Looks like expected but it's the actual result!
```

### ✅ Correct (Clear)
```rust
#[test]
fn test_calculation() {
    let result = add(2, 3);
    assert_eq!(result, 5);  // Variable first = correct order
}

// Fails as:
// left: `6`,  <- The result we got
// right: `5`  <- The value we expected
// Much clearer!
```

## Real-World Impact

### Security Test Confusion
```rust
#[test]
fn test_auth_token_length() {
    let token = generate_auth_token();
    
    // MISORDERED:
    assert_eq!(32, token.len());
    // Fails: "left: 32, right: 16"
    // Is the token 32 or 16 bytes? Confusing!
    
    // CORRECT:
    assert_eq!(token.len(), 32);
    // Fails: "left: 16, right: 32"  
    // Clear: token is 16 bytes but should be 32
}
```

### HTTP Status Codes
```rust
#[test]
fn test_api_response() {
    let response = call_api();
    
    // MISORDERED:
    assert_eq!(200, response.status());
    // Fails: "left: 200, right: 403"
    // Did we expect 200 or get 200? Unclear!
    
    // CORRECT:
    assert_eq!(response.status(), 200);
    // Fails: "left: 403, right: 200"
    // Clear: got 403 when we expected 200
}
```

### Permission Checks
```rust
#[test]
fn test_admin_permissions() {
    let user = get_user();
    
    // MISORDERED:
    assert_eq!(true, user.is_admin());
    // Fails: "left: true, right: false"
    // Is admin true or false? Confusing!
    
    // CORRECT:
    assert_eq!(user.is_admin(), true);
    // Fails: "left: false, right: true"
    // Clear: user is not admin but should be
}
```

## Test Results

Expected findings:
- **4 misordered assertions** in test functions
- **4 correctly ordered assertions** - 0 false positives

### Misordered Tests
1. `test_add_misordered` - assert_eq!(5, result)
2. `test_multiply_misordered` - assert_eq!(12, result)
3. `test_status_misordered` - assert_eq!(200, status)
4. `test_comparison_misordered` - assert_eq!(42, value)

### Correct Tests
1. `test_add_correct` - assert_eq!(result, 5)
2. `test_multiply_correct` - assert_eq!(result, 12)
3. `test_status_correct` - assert_eq!(status, 200)
4. `test_comparison_correct` - assert_eq!(value, 42)

## Error Message Comparison

### Misordered: assert_eq!(5, result) where result = 6
```
thread 'tests::test_add_misordered' panicked at 'assertion failed: `(left == right)`
  left: `5`,
 right: `6`
```
**Confusing**: Which is the expected value?

### Correct: assert_eq!(result, 5) where result = 6
```
thread 'tests::test_add_correct' panicked at 'assertion failed: `(left == right)`
  left: `6`,    <- result (actual)
 right: `5`    <- 5 (expected)
```
**Clear**: result was 6 but we expected 5

## Fix Guidance

### 1. **Follow the Convention**
```rust
// Pattern: assert_eq!(actual, expected)
assert_eq!(function_call(), EXPECTED_VALUE);
assert_eq!(variable, expected);
assert_eq!(calculation(), result);
```

### 2. **Literal on Right**
```rust
// ❌ Wrong
assert_eq!(200, status_code);
assert_eq!(true, is_valid);
assert_eq!(0, count);

// ✅ Right
assert_eq!(status_code, 200);
assert_eq!(is_valid, true);
assert_eq!(count, 0);
```

### 3. **Variable Names Help**
```rust
// Good variable names make order clearer:
assert_eq!(actual_count, expected_count);
assert_eq!(result, expected_result);
assert_eq!(got, want);
```

### 4. **Consider assert! with Comparison**
```rust
// Sometimes clearer than assert_eq:
assert!(result == expected, "expected {} but got {}", expected, result);
```

## Dylint Parity

This rule provides parity with Dylint's `assert_eq_arg_misordering` lint, enforcing the same best practice for test clarity.

## CI/CD Integration

```bash
# Enable in CI
cargo test
cargo clippy -- -W clippy::assert_eq_misordering
```

## References

- **Dylint**: `assert_eq_arg_misordering` lint
- **Rust std**: `assert_eq!` macro documentation
- **Testing Best Practices**: Clear failure messages

Remember: **assert_eq!(what_you_got, what_you_expected)**
