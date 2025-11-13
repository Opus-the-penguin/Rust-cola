# Content-Length DoS Vulnerability Example

This example demonstrates **RUSTSEC-2025-0015**: Trusting remote `Content-Length` headers for memory allocations.

## Vulnerability Overview

When HTTP clients trust the `Content-Length` header from remote servers to pre-allocate buffers, attackers can trigger denial-of-service by sending extremely large values:

```http
HTTP/1.1 200 OK
Content-Length: 4294967295
...
```

This can cause the client to attempt allocating 4GB of memory, leading to OOM crashes.

## What RUSTCOLA021 Detects

The rule tracks taint from Content-Length sources through dataflow to allocation sinks:

### Taint Sources
- `Response::content_length()`
- `HeaderName::from_static("content-length")`
- `HeaderValue::from_static("content-length")`
- `from_bytes(b"content-length")`
- `CONTENT_LENGTH` constants

### Allocation Sinks
- `Vec::with_capacity()`
- `Vec::reserve()`
- `Vec::reserve_exact()`
- `BytesMut::with_capacity()`
- Other capacity-based allocators

### Required Guards
To avoid flagging, code must use one of:
- `min(len, MAX_SIZE)` - clamp to maximum
- `clamp(MIN, MAX)` - enforce range
- `assert!(len <= MAX)` - explicit validation
- `saturating_sub()` / `checked_sub()` - safe arithmetic
- Streaming without pre-allocation

## Test Cases

### Vulnerable Patterns (7 test cases)
1. **Direct allocation**: `Vec::with_capacity(response.content_length())`
2. **Header lookup**: Using `HeaderName::from_static("content-length")`
3. **Constant lookup**: Using `CONTENT_LENGTH` constant
4. **BytesMut allocation**: `BytesMut::with_capacity(len)`
5. **Vec::reserve**: Growing existing vec with untrusted size
6. **Vec::reserve_exact**: Exact reservation with untrusted size
7. **Indirect flow**: Taint propagation through local variables

### Safe Patterns (7 test cases)
1. **min() clamp**: `(len as usize).min(MAX_SIZE)`
2. **clamp()**: `len.clamp(MIN_SIZE, MAX_SIZE)`
3. **assert!**: Explicit validation before allocation
4. **saturating_sub**: Safe arithmetic for bounds
5. **checked operations**: Using checked_sub for validation
6. **Streaming**: No pre-allocation, dynamic growth
7. **Fixed size**: Unrelated constant buffer size

### Edge Cases (2 test cases)
1. **Unrelated allocation**: Size from config, not Content-Length
2. **Tuple/Option flows**: Taint through destructuring patterns

## Expected Results

When running `mir-extractor` on this crate:
- **7 findings** for vulnerable patterns
- **0 findings** for safe patterns (no false positives)
- **1-2 findings** for edge cases (depending on tuple flow tracking)

## References

- [RUSTSEC-2025-0015](https://rustsec.org/advisories/RUSTSEC-2025-0015.html) - web-push DoS vulnerability
- CWE-400: Uncontrolled Resource Consumption
- RUSTCOLA021: content-length-allocation rule
