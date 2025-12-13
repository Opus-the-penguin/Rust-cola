# User Guide

## False Positive Suppression

Rust-cola supports two methods for suppression:
1.  **Source Code Comments**: Best for quick, localized suppressions.
2.  **YAML Configuration**: Best for keeping source code clean or suppressing issues in bulk.

### Method 1: Source Code Comments

Add `// rust-cola:ignore <RuleID>` on the preceding line or the same line.

Format:
```rust
// rust-cola:ignore <RuleID> [explanation]
```

#### Examples

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

### Method 2: YAML Configuration

You can define suppressions in a YAML file and load it using the `--rulepack` flag.

#### Syntax

Create a YAML file (e.g., `suppressions.yaml`) with a `suppressions` list:

```yaml
suppressions:
  - rule_id: "RUSTCOLA001"
    file: "src/unsafe_module.rs"  # Optional: substring match
    function: "dangerous_op"      # Optional: substring match
    reason: "Verified safe by audit team"
```

#### Usage

```bash
cargo-cola --crate-path . --rulepack suppressions.yaml
```

#### Fields

- `rule_id` (Required): The ID of the rule to suppress.
- `file` (Optional): Suppress only if the file path contains this string.
- `function` (Optional): Suppress only if the function name contains this string.
- `reason` (Optional): Documentation for why the finding is suppressed.

### Recommendations

- Suppress specific Rule IDs.
- Include an explanation.
- Review suppressions periodically.
