# Rule Development Guide

This guide explains how to add new security rules to Rust-cola. We'll walk through implementing a heuristic rule from start to finish.

## Table of Contents

- [Rule Types](#rule-types)
- [Step-by-Step: Creating a Heuristic Rule](#step-by-step-creating-a-heuristic-rule)
- [MIR Pattern Matching](#mir-pattern-matching)
- [Testing Requirements](#testing-requirements)
- [SARIF Metadata](#sarif-metadata)
- [Best Practices](#best-practices)

## Rule Types

Rust-cola supports three types of rules:

1. **Heuristic Rules** - Pattern matching on MIR text (simplest, recommended for new rules)
2. **Dataflow Rules** - Taint tracking and flow analysis (more complex)
3. **Declarative Rules** - YAML-based pattern matching (for customization)

This guide focuses on **heuristic rules** as they're the easiest to implement and cover most security patterns.

## Step-by-Step: Creating a Heuristic Rule

### 1. Choose a Rule ID

Find the next available `RUSTCOLA` ID by searching `mir-extractor/src/lib.rs`:

```bash
grep 'id: "RUSTCOLA' mir-extractor/src/lib.rs | sort -u
```

Current range: RUSTCOLA001-031 (use RUSTCOLA032 for next rule)

### 2. Define the Rule Struct

Create a new struct in `mir-extractor/src/lib.rs`. Place it logically among similar rules (e.g., memory safety rules together, crypto rules together).

```rust
struct MyNewRule {
    metadata: RuleMetadata,
}

impl MyNewRule {
    fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA032".to_string(),
                name: "my-new-rule".to_string(),
                short_description: "Brief one-liner description".to_string(),
                full_description: "Detailed explanation of what this rule detects and why it matters. Include specific examples if helpful.".to_string(),
                help_uri: Some("https://link-to-documentation-or-advisory".to_string()),
                default_severity: Severity::High, // or Medium, Low
                origin: RuleOrigin::BuiltIn,
            },
        }
    }
}
```

**Severity Guidelines:**
- **High**: Memory unsafety, injection vulnerabilities, data exposure
- **Medium**: Potential bugs, deprecated APIs, missing security checks
- **Low**: Code quality issues, performance concerns

### 3. Implement the Rule Trait

```rust
impl Rule for MyNewRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
        // Skip analyzing our own crate to avoid self-references
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            // Analyze each function's MIR
            for line in &function.body {
                let trimmed = line.trim();
                
                // Pattern matching logic here
                if trimmed.contains("dangerous_pattern") {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Detected dangerous pattern in `{}`",
                            function.name
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![trimmed.to_string()],
                        span: function.span.clone(),
                    });
                }
            }
        }

        findings
    }
}
```

### 4. Register the Rule

Add your rule to the engine in the `with_builtin_rules()` function (around line 4250):

```rust
pub fn with_builtin_rules() -> Self {
    let mut engine = Self::new();
    
    // ... existing rules ...
    engine.register_rule(Box::new(MyNewRule::new()));
    
    engine
}
```

### 5. Update Documentation

Mark the rule as shipped in `docs/security-rule-backlog.md`:

```markdown
XX. **My new rule** *(shipped — RUSTCOLA032)* – Description of what it detects. 
**Signal:** What patterns trigger it. **Feasibility:** Heuristic.
```

## MIR Pattern Matching

### Understanding MIR Structure

MIR (Mid-level Intermediate Representation) is the compiler's internal representation. Example:

**Rust code:**
```rust
let x = Box::into_raw(b);
```

**MIR representation:**
```
_1 = Box::<i32>::into_raw(move _2);
```

### Common Patterns

#### 1. Function Calls

```rust
// Detect Box::into_raw
if trimmed.contains("Box::into_raw") || 
   trimmed.contains("Box::<") && trimmed.contains("::into_raw") {
    // Found it!
}
```

#### 2. Type Constructors

```rust
// Detect NonNull::new_unchecked
if trimmed.contains("NonNull::new_unchecked") {
    evidence.push(trimmed.to_string());
}
```

#### 3. Assignment Patterns

```rust
// Detect underscore assignments: _ = mutex.lock()
if (trimmed.starts_with("_ =") || 
    (trimmed.starts_with('_') && trimmed.contains(" = "))) &&
    trimmed.contains("::lock(") {
    // Immediately dropped lock guard
}
```

#### 4. Guard Types

```rust
fn guard_type_tokens() -> &'static [&'static str] {
    &[
        "MutexGuard",
        "RwLockReadGuard",
        "RwLockWriteGuard",
        // ...
    ]
}

// Use in detection
for line in &function.body {
    for guard_type in Self::guard_type_tokens() {
        if line.contains(guard_type) {
            // Found a guard type
        }
    }
}
```

### Pattern Matching Tips

1. **Case Sensitivity**: MIR preserves original casing
2. **Generics**: `Box::<i32>` vs `Box::` - match both forms
3. **Whitespace**: Use `.trim()` and avoid relying on exact spacing
4. **Module Paths**: `std::mem::transmute` vs `core::mem::transmute`

## Testing Requirements

### Manual Testing

Test against the examples:

```bash
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola
```

Check `out/cola/findings.json` for your rule's output.

### Integration Tests

Add a test in the `#[cfg(test)]` section of `mir-extractor/src/lib.rs`:

```rust
#[test]
fn test_my_new_rule() {
    let package = MirPackage {
        crate_name: "demo".to_string(),
        crate_root: ".".to_string(),
        functions: vec![MirFunction {
            name: "dangerous_fn".to_string(),
            signature: "fn dangerous_fn()".to_string(),
            body: vec![
                "    _1 = dangerous_pattern(move _2);".to_string(),
            ],
            span: None,
            ..Default::default()
        }],
    };

    let mut engine = RuleEngine::with_builtin_rules();
    let analysis = engine.run(&package);
    
    let findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.rule_id == "RUSTCOLA032")
        .collect();
    
    assert_eq!(findings.len(), 1, "Expected exactly one finding");
    assert!(findings[0].message.contains("dangerous pattern"));
}
```

Run tests:

```bash
cargo test -p mir-extractor
```

## SARIF Metadata

### Help URIs

Always provide helpful documentation links:

```rust
help_uri: Some("https://rustsec.org/advisories/RUSTSEC-XXXX-XXXX.html".to_string())
```

Good sources:
- RustSec advisories: `https://rustsec.org/advisories/`
- CWE references: `https://cwe.mitre.org/data/definitions/XXX.html`
- Clippy lints: `https://rust-lang.github.io/rust-clippy/master/index.html#/lint_name`
- Internal docs: `https://github.com/Opus-the-penguin/Rust-cola/blob/main/docs/research/...`

### Evidence Quality

Provide actionable evidence:

```rust
let mut evidence = vec![line_with_issue.clone()];

// Add context
if !related_line.is_empty() {
    evidence.push(format!("related: {}", related_line));
}

// Add variable names
if !tainted_vars.is_empty() {
    evidence.push(format!("tainted variables: {}", tainted_vars.join(", ")));
}
```

## Best Practices

### 1. Minimize False Positives

```rust
// BAD: Too broad
if line.contains("unsafe") {
    // This will flag legitimate unsafe code
}

// GOOD: Specific pattern
if line.contains("unsafe") && 
   line.contains("transmute") && 
   !has_safety_comment_nearby(function) {
    // More targeted
}
```

### 2. Skip Self-Analysis

Always skip analyzing `mir-extractor` itself:

```rust
if package.crate_name == "mir-extractor" {
    return Vec::new();
}
```

### 3. Performance Considerations

```rust
// GOOD: Early return
for function in &package.functions {
    if !function.body.iter().any(|line| line.contains("pattern")) {
        continue; // Skip functions without the pattern
    }
    
    // Detailed analysis only on relevant functions
    // ...
}
```

### 4. Clear Messages

```rust
// BAD: Vague message
message: format!("Problem in `{}`", function.name)

// GOOD: Actionable message
message: format!(
    "Lock guard assigned to `_` in `{}`, immediately releasing the lock and creating a race condition",
    function.name
)
```

### 5. Severity Calibration

- Start conservative (Medium/Low)
- Increase to High only if:
  - Directly exploitable security issue
  - Memory unsafety
  - Code execution / injection risk
  - Data exposure

## Real-World Examples

### Example 1: UnderscoreLockGuardRule (RUSTCOLA030)

Simple pattern matching for immediately-dropped lock guards:

```rust
// Key insight: Look for _ = pattern with lock methods
if (trimmed.starts_with("_ =") || 
    (trimmed.starts_with('_') && trimmed.contains(" = "))) {
    
    let has_lock_call = ["::lock(", "::read(", "::write("]
        .iter()
        .any(|pattern| trimmed.contains(pattern));
    
    if has_lock_call {
        findings.push(/* ... */);
    }
}
```

### Example 2: CommandArgConcatenationRule (RUSTCOLA031)

Two-pass analysis to correlate concatenation with command usage:

```rust
// Pass 1: Collect concatenation and command lines
for (idx, line) in function.body.iter().enumerate() {
    if line.contains("format!") || line.contains("concat!") {
        concat_lines.push((idx, line.clone()));
    }
    if line.contains("Command::new(") {
        command_lines.push((idx, line.clone()));
    }
}

// Pass 2: Check proximity
for (cmd_idx, cmd_line) in &command_lines {
    let nearby_concat = concat_lines.iter()
        .filter(|(idx, _)| idx < cmd_idx && cmd_idx - idx < 10)
        .collect();
    
    if !nearby_concat.is_empty() {
        findings.push(/* ... */);
    }
}
```

## Checklist

Before submitting your rule:

- [ ] Unique RUSTCOLA ID assigned
- [ ] Clear, actionable rule name (kebab-case)
- [ ] Comprehensive `full_description`
- [ ] Appropriate severity level
- [ ] Help URI provided
- [ ] Registered in `with_builtin_rules()`
- [ ] Self-analysis excluded (`mir-extractor` check)
- [ ] Manual testing against `examples/simple`
- [ ] Integration test added
- [ ] Documentation updated in `security-rule-backlog.md`
- [ ] Evidence includes relevant context
- [ ] Message is clear and actionable

## Getting Help

- Review existing rules in `mir-extractor/src/lib.rs`
- Check research prototypes in `mir-extractor/src/prototypes.rs`
- Read MIR examples in `examples/simple/`
- Ask questions in GitHub Issues or Discussions

## Next Steps

1. Pick a rule from `docs/security-rule-backlog.md` marked "Heuristic"
2. Follow this guide to implement it
3. Test thoroughly
4. Submit a Pull Request

Happy rule writing! 🦀🔍
