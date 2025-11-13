# Unix Permissions Not Octal Test Cases

This example demonstrates detection of Unix file permissions specified using decimal literals instead of octal notation.

## The Problem

Unix file permissions are traditionally written in octal (base-8) notation because each digit represents a group of 3 permission bits (read, write, execute). However, Rust requires an explicit `0o` prefix for octal literals.

### Common Mistake

```rust
// WRONG: Looks like octal 644 but is actually decimal 644
let perms = Permissions::from_mode(644);
// Decimal 644 = Octal 0o1204 = binary 001_010_000_100
// This is NOT rw-r--r-- (0o644)!

// CORRECT: Explicit octal notation
let perms = Permissions::from_mode(0o644);
// Octal 0o644 = binary 110_100_100 = rw-r--r--
```

### What the Values Mean

| Intended | Octal  | Decimal | Wrong Decimal Interpretation |
|----------|--------|---------|------------------------------|
| rw-r--r-- | 0o644 | 420     | 644 = 0o1204 (nonsense)     |
| rwxr-xr-x | 0o755 | 493     | 755 = 0o1363 (nonsense)     |
| rwxrwxrwx | 0o777 | 511     | 777 = 0o1411 (nonsense)     |
| rw------- | 0o600 | 384     | 600 = 0o1130 (nonsense)     |

## The Risk

Using decimal notation leads to:

1. **Incorrect permissions**: The file gets wrong permissions (often more restrictive or more permissive than intended)
2. **Security vulnerabilities**: Files might be world-readable when they should be private, or vice versa
3. **Confusion**: Code looks correct but behaves incorrectly
4. **Maintenance issues**: Future developers may not realize the bug

## Detection Strategy

RUSTCOLA055 detects:

1. **Permission APIs**: Calls to `from_mode()`, `set_mode()`, `chmod()`, `DirBuilder::mode()`
2. **Suspicious decimal values**: Common permission values like 644, 755, 777, 600, 700, etc.
3. **Missing octal prefix**: Values that look like octal but lack the `0o` prefix

## Examples

### Problematic (Detected)

```rust
// All of these use decimal when octal was intended
Permissions::from_mode(644)    // Should be 0o644
Permissions::from_mode(755)    // Should be 0o755
DirBuilder::new().mode(777)    // Should be 0o777
Permissions::from_mode(600)    // Should be 0o600
```

### Safe (Not Detected)

```rust
// Proper octal notation
Permissions::from_mode(0o644)
Permissions::from_mode(0o755)
DirBuilder::new().mode(0o777)
Permissions::from_mode(0o600)

// Variables (can't check statically)
Permissions::from_mode(mode_var)
```

## References

- Sonar RSPEC-7448: File permissions should be in octal format
- Rust Book: Integer literals require explicit octal prefix `0o`
