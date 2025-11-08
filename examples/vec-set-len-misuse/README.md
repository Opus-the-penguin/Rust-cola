# Vec::set_len Misuse Test Examples

⚠️ **WARNING: This crate contains INTENTIONAL security vulnerabilities** ⚠️

This crate is part of the Rust-cola SAST tool's test suite for **RUSTCOLA038: Vec::set_len misuse detection**.

## About the Vulnerability

Calling `Vec::set_len()` without ensuring all elements are initialized leads to **undefined behavior** when the uninitialized memory is accessed. This can cause:

- Reading arbitrary memory contents (information disclosure)
- Program crashes or unpredictable behavior
- Potential security vulnerabilities if uninitialized data is used

## Test Patterns

### Bad Patterns (Should be detected)

1. **bad_set_len_uninitialized**: Calling `set_len` on a vector with capacity but no initialization
2. **bad_set_len_partial_init**: Setting length larger than the number of initialized elements
3. **bad_set_len_immediate**: Setting length immediately after `with_capacity`
4. **bad_set_len_calculated**: Setting length with a calculated value without initialization

### Good Patterns (Should NOT be detected)

1. **good_resize**: Using `Vec::resize()` which properly initializes elements
2. **good_resize_with**: Using `Vec::resize_with()` with a closure
3. **good_manual_init**: Manual initialization with `ptr::write` before `set_len`
4. **good_vec_macro**: Using `vec!` macro for initialization
5. **good_push_elements**: Using `push()` to add elements
6. **good_extend**: Using `extend()` from an iterator

## Safe Alternatives

Instead of manually calling `set_len()`, use these safe alternatives:

```rust
// Instead of: unsafe { vec.set_len(n) }

// Use resize with a default value
vec.resize(n, default_value);

// Use resize_with for complex initialization
vec.resize_with(n, || expensive_constructor());

// Use push in a loop
for item in items {
    vec.push(item);
}

// Use extend from iterator
vec.extend(iterator);
```

## References

- [Vec::set_len documentation](https://doc.rust-lang.org/std/vec/struct.Vec.html#method.set_len)
- Rust security advisory patterns
- Memory safety best practices

## Scanner Configuration

This crate should be **excluded** from security scans or marked as a false positive. The vulnerabilities are intentional test cases.
