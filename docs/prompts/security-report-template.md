# LLM Security Analysis Prompt

Template for `cargo-cola --llm-prompt` output.

## Overview

Rust-COLA generates an LLM prompt file (`llm-prompt.md`) that guides AI assistants through security finding analysis. The prompt is designed to produce enterprise-ready security reports with actionable remediation.

## Prompt Structure

The generated prompt includes these sections in order:

### 1. Role & Objective
Establishes the LLM as a senior security engineer producing a report for security team, engineering leads, and leadership.

### 2. Step 1: Aggressive Pruning (FIRST)
Mandatory false positive elimination before analysis:

| Criterion | How to Identify |
|-----------|-----------------|
| Test Code | Path contains `/tests/`, `_test.rs`, `#[test]` |
| Example Code | Path contains `/examples/`, `/demo/` |
| Benchmark Code | Path contains `/benches/`, `_bench.rs` |
| Build Scripts | File is `build.rs` |
| Compile-time Constants | Value is string literal, `const`, `static` |
| Dead Code | Function never called, disabled feature flag |
| Documented Unsafe | Has `// SAFETY:` comment |

### 3. Step 2: Reachability Classification

| Reachability | Definition | Severity Impact |
|--------------|------------|-----------------|
| EXPOSED | Direct path from untrusted input | Full severity |
| INDIRECT | Reachable via call chain | -1 if sanitized |
| AUTHENTICATED | Behind auth checks | -1 level |
| INTERNAL | Only internal callers | -2 levels |
| CONFIG-DRIVEN | From config files | Context-dependent |

### 4. Step 3: Impact Taxonomy

| Impact Type | Code | Typical Severity |
|-------------|------|------------------|
| Remote Code Execution | RCE | Critical |
| Authentication Bypass | AUTH | Critical |
| Memory Corruption | MEM | Critical |
| SQL/Command Injection | INJ | Critical-High |
| Privilege Escalation | PRIV | High |
| Sensitive Data Exposure | DATA | High |
| Path Traversal | PATH | High-Medium |
| SSRF | SSRF | High-Medium |
| Denial of Service | DOS | Medium |
| Information Disclosure | INFO | Low |

### 5. Step 4: Contextual Severity Model

```
Final Severity = Base Severity + Reachability Modifier + Context Modifier
```

Replaces raw CVSS with context-aware severity that considers:
- Base impact type
- Reachability (exposed vs internal)
- Existing controls (auth, rate limiting)

### 6. Step 5: Remediation with Code

Each true positive requires:
- Vulnerable code snippet
- Fixed code snippet (compilable Rust)
- Recommended libraries
- Effort estimate
- Breaking change notes

### 7. Required Output Format

Enterprise-ready report structure:

```markdown
# Security Assessment Report: {PROJECT}

## Executive Summary
- Risk Rating
- 2-3 sentence summary
- Findings overview table

## Critical & High Severity Findings
[Detailed analysis with attack paths and code fixes]

## Medium Severity Findings
[Analysis with remediation]

## Low Severity Findings
[Summary table]

## Remediation Roadmap
| Priority | Finding | Effort | Target |
|----------|---------|--------|--------|
| P0 | ... | ... | Immediate |
| P1 | ... | ... | Sprint |

## Appendix A: False Positives Dismissed
[Evidence-backed dismissals]

## Appendix B: Methodology
```

### 8. Findings Data

Findings are presented with:
- Rule ID and severity
- Function and file location
- Context hints (test code, example, etc.)
- Code evidence

### 9. Final Checklist

Verification checklist before report submission.

## Usage

```bash
cargo-cola --crate-path ./project
# Output: out/cola/llm-prompt.md
```

Copy the contents of `llm-prompt.md` into your AI assistant (Copilot, Claude, ChatGPT) to generate the security report.

## Customization

The prompt can be customized by modifying `generate_llm_prompt()` in `cargo-cola/src/main.rs`.
