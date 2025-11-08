# OpenOptions Missing Truncate Test Cases

⚠️ **SECURITY SCANNER NOTICE** ⚠️

This directory contains **INTENTIONAL VULNERABILITIES** for testing purposes.

## Purpose

Test cases for **RUSTCOLA032** (OpenOptions missing truncate) rule detection. These functions deliberately omit `.truncate(true)` or `.append(true)` when creating writable files to verify the security scanner correctly identifies potential stale data disclosure issues.

## Test Functions

### Bad Examples (Should be flagged)
- `create_log_file_bad()` - write(true) + create(true) without truncate/append
- `create_config_file_bad()` - Multiline builder missing truncate/append

### Good Examples (Should NOT be flagged)
- `create_log_file_with_truncate()` - Properly uses truncate(true)
- `append_log_file()` - Properly uses append(true) for logs
- `read_file()` - Read-only access doesn't need truncate
- `create_readonly()` - Create without write doesn't need truncate

## Security Issue

Opening a file with `write(true)` and `create(true)` but without `truncate(true)` or `append(true)` can leave stale data at the end of the file if the new content is shorter than the old content. This can lead to:
- Information disclosure (old data remains readable)
- Data corruption (mixed old and new content)
- Configuration errors (partial config updates)

## DO NOT USE THIS CODE IN PRODUCTION

These patterns are dangerous and can lead to security vulnerabilities. They are for testing only.

## Suppression Comments

All vulnerable functions are marked with:
- `NOSEC` tags for general security scanners
- `CodeQL` suppression comments
- Inline comments explaining the intentional vulnerability

Security scanners should recognize these as test cases and not report them as actual vulnerabilities in the rust-cola codebase.
