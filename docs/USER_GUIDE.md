# User Guide

## False Positive Suppression

Suppress findings using comments in the source code.

### Syntax

Add `// rust-cola:ignore <RuleID>` on the preceding line or the same line.

Format:
```rust
// rust-cola:ignore <RuleID> [explanation]
```

### Examples

Previous line:
```rust
// rust-cola:ignore RUSTCOLA001 Manual verification
unsafe {
    let ptr = buffer.as_mut_ptr();
}
```

Same line:
```rust
let x = unsafe { *ptr }; // rust-cola:ignore RUSTCOLA002 Valid pointer
```

Multiple rules:
```rust
// rust-cola:ignore RUSTCOLA001
// rust-cola:ignore RUSTCOLA002
unsafe {
    // ...
}
```

### Recommendations

- Suppress specific Rule IDs.
- Include an explanation.
- Review suppressions periodically.
