
# Rule Development Guide (Short Version)

This guide shows how to add a new heuristic rule to Rust-cola. Keep it simple and direct.

## 1. Get a Rule ID
- Find the next free RUSTCOLA ID:
  ```sh
  grep 'id: "RUSTCOLA' mir-extractor/src/lib.rs | sort -u
  ```

## 2. Add Your Rule
- In `mir-extractor/src/lib.rs`, define your struct and implement the `Rule` trait.
- Example:
  ```rust
  struct MyNewRule { metadata: RuleMetadata }
  impl MyNewRule {
      fn new() -> Self { /* fill metadata */ }
  }
  impl Rule for MyNewRule {
      fn metadata(&self) -> &RuleMetadata { &self.metadata }
      fn evaluate(&self, package: &MirPackage) -> Vec<Finding> {
          if package.crate_name == "mir-extractor" { return Vec::new(); }
          // Pattern match on function.body lines
          // Push Finding if pattern matches
          Vec::new()
      }
  }
  ```

## 3. Register the Rule
- Add to `with_builtin_rules()`:
  ```rust
  engine.register_rule(Box::new(MyNewRule::new()));
  ```

## 4. Test the Rule
- Manual: Run on an example crate:
  ```sh
  cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola
  cat out/cola/findings.json
  ```
- Integration: Add a test in `mir-extractor/src/lib.rs` under `#[cfg(test)]`.
- Run:
  ```sh
  cargo test -p mir-extractor
  ```

## 5. Update Docs
- Mark as shipped in `docs/security-rule-backlog.md`.

## 6. Checklist
- [ ] Unique RUSTCOLA ID
- [ ] Rule name (kebab-case)
- [ ] `full_description` in metadata
- [ ] Severity set (start Medium/Low)
- [ ] Help URI in metadata
- [ ] Registered in `with_builtin_rules()`
- [ ] Skips `mir-extractor` crate
- [ ] Manual and integration tests
- [ ] Docs updated
- [ ] Evidence and message are clear

## Pattern Matching Tips
- Use `.trim()` on MIR lines.
- Match both `Box::` and `Box::<T>` forms.
- Avoid broad patterns (e.g., just `unsafe`).
- Prefer actionable, specific messages.

## Example Patterns
- Function call: `if line.contains("Box::into_raw") { ... }`
- Assignment: `if line.starts_with("_ =") && line.contains("::lock(") { ... }`

## Help
- See existing rules in `mir-extractor/src/lib.rs`.
- Ask in GitHub Issues if stuck.
