# Length Truncation Cast Example

This example demonstrates **RUSTSEC-2024-0363** and **RUSTSEC-2024-0365**: Protocol length truncation vulnerabilities in database clients (SQLx, PostgreSQL).

## Vulnerability Overview

When serializing protocol messages, casting payload lengths from `usize` (or `u64`) to narrower integer types like `u32`, `i32`, `u16`, or `u8` without bounds checking can enable protocol smuggling attacks:

```rust
let payload_len = huge_payload.len(); // e.g., 5GB
let len_u32 = payload_len as u32;     // Truncates to ~1GB
buffer.put_u32(len_u32);              // Server expects 1GB
buffer.put_slice(huge_payload);       // But receives 5GB!
```

The extra ~4GB can contain smuggled SQL commands or protocol messages.

## What RUSTCOLA022 Detects

The rule tracks length values through dataflow and flags narrowing casts that feed into serialization sinks:

### Taint Sources (Length Identifiers)
- Variables named: `len`, `length`, `size`, `payload`
- Expressions: `.len()`, `.count()`, `.size()`

### Narrowing Casts (Triggers)
- `as i32`, `as u32` (from `usize`/`u64`)
- `as i16`, `as u16`
- `as i8`, `as u8`
- `.try_into::<u32>().unwrap()` (defeats safety check)

### Serialization Sinks
- `BufMut::put_i32()`, `put_u32()`, `put_u16()`, `put_u8()`
- `write_i32()`, `write_u32()`, etc.
- Protocol serialization helpers

### Required Guards
To avoid flagging, code must use:
- `min(len, MAX_SIZE)` - clamp to maximum
- `try_into()` with proper error handling (not `.unwrap()`)
- `assert!(len <= MAX)` - explicit validation
- Range checks before cast
- No cast (use wider types like `u64`)

## Test Cases

### Vulnerable Patterns (8 test cases)
1. **Direct cast u32**: `len as u32` → `put_u32()`
2. **Direct cast i32**: `len as i32` → `put_i32()`
3. **Direct cast u16**: `len as u16` → `put_u16()`
4. **Direct cast u8**: `len as u8` → `put_u8()`
5. **try_into with unwrap**: `len.try_into().unwrap()` defeats safety
6. **Indirect cast**: Taint through variable reassignment
7. **Cast in expression**: Direct cast in function argument
8. **Cast chain**: Multiple casts still narrows

### Safe Patterns (7 test cases)
1. **min() clamp**: `len.min(MAX_SIZE) as u32`
2. **Checked conversion**: `try_into()` with `?` operator
3. **Range check**: `assert!(len <= MAX)` before cast
4. **if-let pattern**: Conditional execution on conversion success
5. **Wider type**: Using `u64` instead of `u32`
6. **Saturating ops**: `saturating_sub()` for bounds
7. **Constant size**: Not derived from payload length

### Edge Cases (3 test cases)
1. **Unrelated cast**: Cast for logging, not serialization
2. **Unused cast**: Cast happens but value not serialized
3. **Multiple casts**: Only one flows to serialization

## Expected Results

When running `mir-extractor` on this crate:
- **8 findings** for vulnerable patterns (RUSTCOLA022)
- **0 findings** for safe patterns (no false positives)
- **0-3 findings** for edge cases (depending on dataflow precision)

## Real-World Impact

**RUSTSEC-2024-0363 (SQLx)**:
- PostgreSQL protocol uses 32-bit message lengths
- Payload >4GB truncates, allowing command smuggling
- Severity: Critical (enables arbitrary SQL injection)

**RUSTSEC-2024-0365 (PostgreSQL wire protocol)**:
- Similar truncation in protocol frame headers
- Enables protocol-level attacks

## Prevention

Always validate or clamp lengths before narrowing casts:
```rust
// ❌ VULNERABLE
let len_u32 = payload.len() as u32;

// ✅ SAFE
let len_u32 = payload.len().min(u32::MAX as usize) as u32;

// ✅ SAFE
let len_u32: u32 = payload.len().try_into()
    .map_err(|_| "Payload too large")?;
```

## References

- [RUSTSEC-2024-0363](https://rustsec.org/advisories/RUSTSEC-2024-0363.html) - SQLx PostgreSQL
- [RUSTSEC-2024-0365](https://rustsec.org/advisories/RUSTSEC-2024-0365.html) - Protocol truncation
- CWE-190: Integer Overflow or Wraparound
- RUSTCOLA022: length-truncation-cast rule
