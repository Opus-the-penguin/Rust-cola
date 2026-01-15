# Rust-cola Overview

## What It Is

Rust-cola is an experimental security static analyzer for Rust code. It is a proof of concept.

## How It Works

1. Compiles the target Rust crate to extract MIR (Mid-level Intermediate Representation)
2. Runs 126 security rules against the MIR
3. Generates a findings report with optional LLM validation

## Why MIR

Most Rust static analyzers work at the source or AST level. Rust-cola analyzes MIR, which is the compiler's internal representation after macros are expanded, generics are resolved, and types are inferred.

This allows detection of issues that source-level tools cannot see:

- Vulnerabilities hidden in macro-generated code
- Problems in generic code after type resolution
- Memory safety issues visible only with lifetime information
- Data flow across function boundaries
- Issues inside unsafe blocks

## LLM Integration

Raw static analysis produces false positives. Rust-cola optionally sends findings to an LLM (Claude, GPT-4, or local models) to:

- Filter false positives
- Assess exploitability
- Rate severity
- Suggest fixes

This reduces noise and produces actionable reports.

## Rule Coverage

| Category | Count | Examples |
|----------|-------|----------|
| Memory Safety | 24 | transmute misuse, raw pointer escapes, use-after-free |
| Concurrency | 21 | mutex across await, blocking in async, Send/Sync violations |
| Input Validation | 15 | deserialization, integer overflow, regex DoS |
| FFI | 11 | allocator mismatch, CString misuse, WASM bounds |
| Web Security | 14 | TLS validation, passwords in logs, CORS |
| Injection | 10 | SQL, command, path traversal, SSRF |
| Cryptography | 8 | weak hashes, hardcoded keys, PRNG bias |
| Resource Management | 10 | file permissions, unbounded allocations |
| Code Quality | 9 | dead stores, crate-wide allow, unwrap in poll |
| Supply Chain | 4 | RUSTSEC advisories, yanked crates |

## Interprocedural Taint Tracking

Five rules track tainted data across function boundaries to detect injection vulnerabilities where user input enters in one function and reaches a dangerous sink in another.

## Comparison to Other Tools

| Feature | Rust-cola | Source/AST Analyzers |
|---------|-----------|---------------------|
| Sees expanded macros | Yes | No |
| Sees resolved generics | Yes | No |
| Has lifetime/borrow info | Yes | No |
| Cross-function data flow | Yes | Limited |
| Requires compilation | Yes | No |
| LLM-assisted triage | Yes | Typically no |

## Limitations

- Requires the target code to compile
- Requires nightly Rust toolchain
- Experimental and under active development
- LLM validation is optional but recommended for best results

## Status

Proof of concept. Not production-ready.
