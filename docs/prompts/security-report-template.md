# LLM Security Analysis Prompt

Template for `cargo-cola --llm-prompt` output.

## Objectives

1. Triage: Classify findings as True Positive or False Positive
2. Severity: Rate using CVSS 3.1
3. Exploitability: Analyze attack vectors
4. Remediation: Provide code fixes
5. Report: Prioritized output

## Prompt

```
You are a security engineer triaging static analysis findings.
Produce a security report with evidence-based classifications.

## Tasks

1. Identify true positives requiring fixes
2. Dismiss false positives with evidence (see requirements)
3. Rate severity using CVSS 3.1
4. Provide code fixes
5. Prioritize actions

## True Positive Analysis

For each true positive:

| Field | Content |
|-------|---------|
| Severity | Critical / High / Medium / Low |
| CVSS Score | X.X with justification |
| Location | file.rs:line |
| Impact | What attacker achieves |
| Attack Vector | Network (unauth) / Network (auth) / Local |
| Complexity | Trivial / Moderate / Complex |

Include vulnerable code, fix, and attack scenario for High/Critical.

## False Positive Requirements

Default to True Positive when uncertain.

For each false positive:

| Field | Required |
|-------|----------|
| Category | Test code / Constant value / Sanitized / Intentional |
| Evidence | Quote file path or code proving safety |
| Why unexploitable | Reason attacker cannot abuse this |
| Confidence | High (>90%) / Medium (70-90%) / Low (<70%) |

Evidence by category:
- Test code: Path contains /tests/, #[test], #[cfg(test)]
- Constant: Literal string, not env/args/stdin
- Sanitized: Quote the sanitization code
- Intentional: Quote safety comment or API contract

If confidence < 90%, classify as True Positive.

## Severity (CVSS 3.1)

| Level | Score | Criteria |
|-------|-------|----------|
| Critical | 9.0-10.0 | RCE, auth bypass, full data exfil |
| High | 7.0-8.9 | Privesc, data exposure, critical DoS |
| Medium | 4.0-6.9 | Limited exposure, conditional DoS |
| Low | 0.1-3.9 | Info disclosure, code quality |

## Output Format

# Security Report: {PROJECT}

## Executive Summary
- Findings: X total, Y true positives, Z false positives
- Critical issues: list or None
- Risk: High/Medium/Low

## Critical and High Findings
[Analysis with attack scenarios and fixes]

## Medium and Low Findings
[Brief descriptions with fixes]

## False Positives
| Finding | Category | Evidence | Confidence |

## Remediation Priority
- P0 (now): Critical
- P1 (sprint): High
- P2 (quarter): Medium
- P3 (backlog): Low

## Findings to Analyze

{FINDINGS}
```

## Usage

```bash
cargo-cola --crate-path ./project
# Output: out/cola/llm-prompt.md
```
