# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Rust-cola, please report it responsibly:

1. **GitHub Security Advisories** (Preferred): Open a [private security advisory](https://github.com/Opus-the-penguin/Rust-cola/security/advisories/new) on this repository.

2. **Email**: Contact the maintainers directly if GitHub advisories are not accessible.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity, typically 30-90 days

## Scope

This security policy covers:
- The `cargo-cola` CLI tool
- The `mir-extractor` library
- Security rule implementations

**Out of scope:**
- Example crates in `examples/` (these contain intentional vulnerabilities for testing)
- Documentation-only issues

## Security Features

Rust-cola is a security analysis tool for Rust code. It detects:
- Memory safety issues in unsafe code
- Cryptographic weaknesses
- Input validation vulnerabilities
- Concurrency bugs
- And 85+ other security patterns

See the [README](README.md) for full documentation.
