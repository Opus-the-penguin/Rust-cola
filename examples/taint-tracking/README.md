# Taint Tracking Test Suite

This crate contains test cases for validating the taint tracking infrastructure in rust-cola.

## Purpose

Taint tracking is a dataflow analysis technique that identifies when untrusted data (from environment variables, network input, etc.) flows to security-sensitive operations (command execution, file system access, SQL queries) without proper sanitization.

## Test Structure

### Positive Cases (`src/positive_cases.rs`)

These functions **SHOULD be detected** as vulnerabilities:

1. **`env_to_command`** - Direct env::var → Command::arg  
   Basic command injection vulnerability

2. **`env_to_fs`** - Direct env::var → fs::write  
   Path traversal vulnerability

3. **`env_through_format`** - env::var → format! → Command::arg  
   Taint propagates through string formatting

4. **`env_through_assign`** - env::var → alias → Command::arg  
   Taint propagates through variable assignment

5. **`env_through_transform`** - env::var → transform → fs::remove_file  
   Taint propagates through method calls (uppercase, trim, etc.)

### Negative Cases (`src/negative_cases.rs`)

These functions **should NOT be detected** as vulnerabilities:

1. **`hardcoded_safe`** - Uses hardcoded strings, no taint source

2. **`sanitized_parse`** - Type conversion via `.parse::<u16>()` sanitizes

3. **`sanitized_allowlist`** - `.chars().all(allowlist)` validates input

4. **`sanitized_canonicalize`** - `fs::canonicalize` reduces path traversal risk

5. **`validated_regex`** - Regex/length validation before use

6. **`env_var_no_sink`** - Reads env var but doesn't pass to dangerous sink

## Expected Results

### Phase 1 (Current)
- **Precision**: Detects all 5 positive cases
- **False Positives**: May flag some negative cases (sanitization detection incomplete)

### Phase 2 (After sanitization enhancement)
- **Precision**: Detects all 5 positive cases
- **False Positives**: 0 on negative cases (proper sanitization recognition)

## Running Tests

```bash
# Build the crate
cargo build -p taint-tracking

# Run rust-cola analysis
cargo run -p cargo-cola -- \
  --crate-path examples/taint-tracking \
  --out-dir target/taint-test \
  --fail-on-findings false

# Check results
cat target/taint-test/findings.json | python3 -c "
import sys, json
findings = [f for f in json.load(sys.stdin) if f['rule_id'] == 'RUSTCOLA006']
print(f'Found {len(findings)} RUSTCOLA006 findings')
for f in findings:
    print(f\"  - {f['function']}: {f['message']}\")
"
```

## Success Criteria

- [x] All 5 positive cases detected (100% recall)
- [ ] 0 false positives on negative cases (100% precision) - Phase 2
- [x] Taint propagates through assignments, format!, transforms
- [ ] Sanitization patterns recognized (parse, allowlist, regex) - Phase 2

## Related

- Design doc: `docs/research/taint-tracking-design.md`
- Implementation: `mir-extractor/src/dataflow/taint.rs`
- Rule: RUSTCOLA006 (untrusted-env-input)
