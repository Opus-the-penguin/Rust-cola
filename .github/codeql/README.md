# CodeQL Configuration for Rust-cola

This directory contains CodeQL configuration to handle intentional test vulnerabilities in the `examples/` directory.

## Problem

Rust-cola includes test examples that contain **intentional security vulnerabilities** to validate the security scanner's detection capabilities. CodeQL was flagging these test patterns as actual security issues.

## Solution

We've implemented multiple layers of suppression to ensure CodeQL understands these are test cases:

### 1. Path-Based Exclusion (Primary Method)

**File:** `codeql-config.yml`

Excludes the entire `examples/*/src/**` directory from CodeQL analysis:

```yaml
paths-ignore:
  - examples/allocator-mismatch-ffi/src/**
  - examples/openoptions-truncate/src/**
  - examples/send-sync-bounds/src/**
  - examples/packed-field-reference/src/**
  - examples/unsafe-cstring-pointer/src/**
  - examples/cstring-pointer-use/src/**
  - examples/blocking-sleep-async/src/**
```

This is the **most effective** approach as it completely excludes test code from scanning.

### 2. Workflow Integration

**Files:** `.github/workflows/codeql.yml`, `.github/workflows/codeql-advanced.yml`

Both CodeQL workflows reference the configuration:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: rust
    config-file: ./.github/codeql/codeql-config.yml
```

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

| Example Crate | Rule Tested | Vulnerability Type |
|--------------|-------------|-------------------|
| `allocator-mismatch-ffi` | RUSTCOLA017 | Mixed allocator/deallocator |
| `openoptions-truncate` | RUSTCOLA032 | Missing truncate flag |
| `send-sync-bounds` | RUSTCOLA015 | Unsafe Send/Sync impls |
| `packed-field-reference` | RUSTCOLA035 | Unaligned references |
| `unsafe-cstring-pointer` | RUSTCOLA036 | Dangling CString pointers |
| `cstring-pointer-use` | RUSTCOLA036 | Dangling CString pointers |
| `blocking-sleep-async` | RUSTCOLA037 | Blocking in async context |

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

1. Add the path to `.github/codeql/codeql-config.yml`
2. Include suppression comments in the source code
3. Add a README with warning banner
4. Update this documentation

## References

- [CodeQL Configuration Reference](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning)
- [CodeQL Query Filters](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning#using-query-filters)
- [Excluding Paths](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning#excluding-specific-files-and-folders)
