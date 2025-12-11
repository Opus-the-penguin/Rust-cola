# Workspace Filtering Fix for Rust-cola CI

## Problem

GitHub Code Scanning alerts were showing "Detected by rust-cola" errors from test example crates with intentional vulnerabilities, even after:

1. Adding `--crate-path mir-extractor` to cargo-cola invocation
2. Configuring CodeQL path filters
3. Modifying workflow build commands

## Root Cause

**cargo metadata discovers ALL workspace members regardless of `--crate-path` argument.**

When cargo-cola runs:
```bash
cargo run -p cargo-cola -- --crate-path mir-extractor
```

The `resolve_crate_roots()` function in `cargo-cola/src/main.rs` uses `cargo_metadata` which:

1. Reads `Cargo.toml` workspace configuration
2. Discovers **all 14 workspace members** (including test examples)
3. Analyzes every discovered crate
4. Generates findings from test examples with intentional vulnerabilities

The `--crate-path` flag only determines the starting point for metadata discovery but doesn't filter workspace members.

## Solution

**Temporarily modify the workspace during CI to exclude test crates.**

### Implementation

The `.github/workflows/cola-ci.yml` workflow now:

1. **Creates a production-only workspace** before analysis:
   ```yaml
   - name: Temporarily exclude test examples from workspace
     run: |
       cat > Cargo.toml.production <<'EOF'
       [workspace]
       members = [
           "cargo-cola",
           "mir-extractor",
           "examples/simple",
           "examples/hir-typeck-repro",
       ]
       resolver = "2"
       EOF
       mv Cargo.toml Cargo.toml.original
       mv Cargo.toml.production Cargo.toml
   ```

2. **Runs cargo-cola** with the filtered workspace:
   ```yaml
   - name: Run cargo-cola on production code only
     run: |
       cargo run -p cargo-cola -- \
         --crate-path . \
         --out-dir target/cola \
         --sarif target/cola/cola.sarif \
         --fail-on-findings false
   ```

3. **Restores the original workspace** (always runs, even on failure):
   ```yaml
   - name: Restore original workspace configuration
     if: always()
     run: |
       mv Cargo.toml.original Cargo.toml
   ```

## Verification Results

### Before Fix
Running with full workspace:
```
cargo run -p cargo-cola -- --crate-path mir-extractor
```
- **78 findings** including test example functions:
  - `cstring_freed_with_libc` (from `examples/allocator-mismatch-ffi`)
  - `bad_blocking_sleep_basic` (from `examples/blocking-sleep-async`)
  - Multiple other test crate vulnerabilities

### After Fix
Running with production-only workspace:
```
cargo run -p cargo-cola -- --crate-path .
```
- **5 findings** (all from production code):
  - 1 × RUSTCOLA038 in `cargo-cola/tests/cli.rs` (acceptable test false positive)
  - 4 × RUSTCOLA039 in `cargo-cola/src/main.rs` (false positives from "iv" in variable names like "invocation", "driver")
  
**Zero findings from test examples!** ✅

## Why This Approach Works

1. **cargo metadata only sees 4 workspace members** instead of 14
2. **Test crates are not discovered** during analysis
3. **SARIF output is clean** (no test example findings to upload)
4. **GitHub alerts will clear** once new workflow runs complete
5. **No modification to cargo-cola source** needed

## Comparison with CodeQL

| Aspect | CodeQL | Rust-cola |
|--------|--------|-----------|
| **Filtering method** | Source path filters | Workspace modification |
| **Why different?** | Analyzes compiled code, can filter by source paths | Uses cargo metadata which always discovers workspace |
| **Configuration** | `.github/codeql/codeql-config.yml` with `paths` directive | Temporary `Cargo.toml` swap in CI workflow |
| **Effectiveness** | Works perfectly with path filters | Requires workspace manipulation |

## Alternative Solutions Considered

### ❌ Option 1: Add `--exclude-crate` flag to cargo-cola
- Would require modifying cargo-cola source code
- More complex implementation
- Maintenance burden

### ❌ Option 2: Post-process SARIF to filter findings
- Findings still generated (wasted computation)
- Complex SARIF manipulation
- Risk of breaking SARIF format

### ❌ Option 3: Permanently remove test crates from workspace
- Breaks local development
- Harder to run tests
- Poor developer experience

### ✅ Option 4: Temporary workspace filtering (chosen)
- No source code changes needed
- Clean separation of concerns
- Works with existing cargo-cola
- Easy to understand and maintain

## Related Files

- `.github/workflows/cola-ci.yml` - Workflow with workspace filtering
- `.github/workflows/codeql.yml` - CodeQL workflow (uses path filters instead)
- `.github/codeql/codeql-config.yml` - CodeQL path configuration
- `.github/codeql/README.md` - Documentation of both approaches
- `cargo-cola/src/main.rs` - Source of `resolve_crate_roots()` function

## Future Improvements

If this becomes a common need, cargo-cola could be enhanced with:

1. **`--exclude-crate` flag** to filter discovered workspace members
2. **`--workspace-members` flag** to explicitly list crates to analyze
3. **Environment variable** to control workspace discovery behavior

For now, the temporary workspace modification is the simplest and most effective solution.

## Testing Locally

To reproduce the fix locally:

```bash
# Create production-only workspace
cat > Cargo.toml.production <<'EOF'
[workspace]
members = ["cargo-cola", "mir-extractor", "examples/simple", "examples/hir-typeck-repro"]
resolver = "2"
EOF
cp Cargo.toml Cargo.toml.backup
cp Cargo.toml.production Cargo.toml

# Run cargo-cola
cargo run -p cargo-cola -- --crate-path . --out-dir target/verify --sarif target/verify/cola.sarif

# Check results (should be ~5 findings, not 78)
cat target/verify/findings.json | python3 -c "import sys, json; print(len(json.load(sys.stdin)))"

# Restore original workspace
mv Cargo.toml.backup Cargo.toml
```

## Credits

- **Issue discovered**: cargo metadata workspace discovery behavior
- **Solution implemented**: Temporary workspace filtering in CI
- **Date**: November 8, 2025
- **Verification**: Reduced from 78 findings to 5 (production only)
