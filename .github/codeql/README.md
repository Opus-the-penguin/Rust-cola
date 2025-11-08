# CodeQL Configuration for Rust-cola

This directory contains CodeQL configuration to handle intentional test vulnerabilities in the `examples/` directory.

## Problem

Rust-cola includes test examples that contain **intentional security vulnerabilities** to validate the security scanner's detection capabilities. CodeQL was flagging these test patterns as actual security issues.

## Solution

We use an **explicit include list** approach to ensure only production code is scanned:

### 1. Explicit Path Inclusion (Primary Method)

**File:** `codeql-config.yml`

Lists only the paths that should be scanned (production code):

```yaml
paths:
  - mir-extractor      # Production rule engine
  - cargo-cola         # Production CLI tool
  - docs               # Documentation
  - examples/simple    # Safe example crate
  - examples/hir-typeck-repro  # Safe example crate
```

**All other paths are excluded by default**, including all test crates with intentional vulnerabilities.

This approach is superior to `paths-ignore` because:
- ✅ **No conflicts**: `paths` acts as a whitelist; unlisted paths are automatically excluded
- ✅ **Simpler logic**: Easy to understand what gets scanned
- ✅ **Future-proof**: New test crates are automatically excluded
- ✅ **Self-documenting**: Clear separation of production vs. test code

### 2. Workflow Integration

**File:** `.github/workflows/codeql.yml`

The CodeQL workflow references the configuration file:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: rust
    config-file: ./.github/codeql/codeql-config.yml
```

**Note:** We previously had two identical CodeQL workflows (`codeql.yml` and `codeql-advanced.yml`). The duplicate has been removed to avoid redundant scans.

### 3. In-Code Suppression Comments

All test examples include:

- **File-level banners** explaining intentional vulnerabilities
- **NOSEC tags** for general security scanners
- **CodeQL-specific suppressions** like `codeql[query-id]: explanation`
- **Inline comments** on each vulnerable line

Example:
```rust
/// NOSEC: Intentional vulnerability for testing
/// codeql[cpp/use-after-free]: Intentional test pattern
pub unsafe fn bad_cstring_unwrap_as_ptr(s: &str) -> *const c_char {
    CString::new(s).unwrap().as_ptr() // NOSEC - Dangling pointer (test case)
}
```

### 4. README Documentation

Each example crate includes a `README.md` with prominent warnings:

```markdown
⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.
```

## Test Examples Overview

The following crates contain **intentional vulnerabilities** and are excluded from CodeQL scanning:

| Example Crate | Rule Tested | Vulnerability Type |
|--------------|-------------|-------------------|
| `allocator-mismatch-ffi` | RUSTCOLA017 | Mixed allocator/deallocator usage |
| `blocking-sleep-async` | RUSTCOLA037 | Blocking sleep in async functions |
| `cstring-pointer-use` | RUSTCOLA036 | Dangling CString pointers |
| `hardcoded-crypto-keys` | RUSTCOLA039 | Hard-coded cryptographic secrets |
| `openoptions-truncate` | RUSTCOLA032 | Missing truncate() flag |
| `packed-field-reference` | RUSTCOLA035 | Unaligned references to packed fields |
| `panic-in-drop` | RUSTCOLA040 | Panic in Drop implementations |
| `send-sync-bounds` | RUSTCOLA015 | Unsafe Send/Sync without bounds |
| `unsafe-cstring-pointer` | RUSTCOLA036 | Dangling CString pointers |
| `vec-set-len-misuse` | RUSTCOLA038 | Uninitialized Vec memory access |

## Verification

After applying these configurations, CodeQL should:

- ✅ **Not flag** any issues in `examples/*/src/**` directories
- ✅ **Continue scanning** production code in `mir-extractor/`, `cargo-cola/`, etc.
- ✅ **Report** any real security issues in non-test code

## Alternative Suppression Methods

If path exclusion doesn't work, you can also use:

### Query Filters

Add to `codeql-config.yml`:

```yaml
query-filters:
  - exclude:
      id: cpp/unaligned-pointer
      paths:
        - examples/**
  - exclude:
      id: rust/dangling-pointer
      paths:
        - examples/**
```

### Per-File Suppressions

Use `# codeql-suppress` comments in individual files:

```rust
// codeql-suppress [query-id] Intentional test vulnerability
```

## Testing the Configuration

To verify the suppression is working:

1. Push changes to GitHub
2. Wait for CodeQL action to complete
3. Check Security tab → Code scanning alerts
4. Verify no alerts from `examples/` directories

## Updating Suppressions

When adding new test examples:

1. Create the crate under `examples/`
2. **Do NOT** add it to the `paths` list in `codeql-config.yml` (it will be excluded by default)
3. Include suppression comments in the source code (NOSEC tags, file banners)
4. Add a README with warning banner
5. Update the test examples table in this documentation

The crate will be automatically excluded since only paths listed in `codeql-config.yml` are scanned.

## Common Issues

### Issue: CodeQL still flagging test examples

**Diagnosis:** The test crate might be accidentally listed in the `paths` section.

**Fix:** Remove the crate from the `paths` list in `codeql-config.yml`. Only production code should be listed.

### Issue: Using `paths-ignore` together with `paths`

**Diagnosis:** Having both creates conflicts. CodeQL processes `paths` (include) first, making `paths-ignore` redundant.

**Fix:** Remove the `paths-ignore` section entirely. The `paths` directive acts as a whitelist.

## References

- [CodeQL Configuration Reference](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning)
- [CodeQL Query Filters](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning#using-query-filters)
- [Excluding Paths](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning#excluding-specific-files-and-folders)
