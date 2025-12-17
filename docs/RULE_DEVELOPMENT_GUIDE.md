# Rule Development Guide

Two ways to create custom rules: YAML rulepacks (recommended) or Rust code.

---

## Option 1: YAML Rulepacks (Recommended)

Create a `.yaml` file with pattern-based rules. No compilation required.

### Example Rulepack

```yaml
# my-rules.yaml
rules:
  - id: ORG001
    name: no-unwrap
    short_description: Avoid unwrap in production
    full_description: Calls to unwrap() can panic. Handle errors explicitly.
    severity: medium
    message: Replace unwrap() with proper error handling.
    body_contains_any:
      - "unwrap"

  - id: ORG002
    name: no-into-raw
    short_description: Detect Box::into_raw usage
    severity: high
    body_contains_any:
      - "into_raw"
```

### Load the Rulepack

```sh
cargo cola --rulepack my-rules.yaml --crate-path ./my-crate
```

Multiple rulepacks can be loaded:

```sh
cargo cola --rulepack team-rules.yaml --rulepack project-rules.yaml
```

### Available Match Conditions

| Field | Description |
|-------|-------------|
| `body_contains_any` | Match if function body contains any pattern |
| `body_contains_all` | Match if function body contains all patterns |
| `function_name_contains_any` | Match if function name contains any pattern |
| `function_name_contains_all` | Match if function name contains all patterns |

### Required Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (e.g., ORG001) |

### Optional Fields

| Field | Default |
|-------|---------|
| `name` | Same as id |
| `short_description` | Same as id |
| `full_description` | Auto-generated |
| `severity` | medium |
| `message` | Auto-generated |
| `help_uri` | None |

### Severity Values

`critical`, `high`, `medium`, `low`, `note`

---

## Option 2: Rust Rules

For complex logic (taint tracking, type analysis), write a Rust rule.

### Steps

1. Define a struct implementing `Rule` trait in `mir-extractor/src/rules/`
2. Register in `with_builtin_rules()` in `mir-extractor/src/lib.rs`
3. Add tests

### Minimal Example

```rust
pub struct MyRule { metadata: RuleMetadata }

impl MyRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA999".to_string(),
                name: "my-rule".to_string(),
                short_description: "Brief description".to_string(),
                full_description: "Detailed description".to_string(),
                default_severity: Severity::Medium,
                ..Default::default()
            }
        }
    }
}

impl Rule for MyRule {
    fn metadata(&self) -> &RuleMetadata { &self.metadata }
    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        let mut findings = Vec::new();
        for function in &package.functions {
            // Pattern matching logic here
        }
        findings
    }
}
```

### Test

```sh
cargo test -p mir-extractor
```

---

## Example Rulepack File

See `examples/rulepacks/example-basic.yaml` for a working example.
