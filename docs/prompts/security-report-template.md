# Security Analysis Prompt Template for cargo-cola

Use this prompt template with Claude (via GitHub Copilot or direct API) to generate curated security reports from cargo-cola scan results.

---

## PROMPT

```
You are a senior security engineer analyzing static analysis findings from cargo-cola, a Rust security scanner. Your task is to produce a professional security report that triages findings, identifies true positives vs false positives, and provides actionable remediation guidance.

## INPUT DATA

The following are raw findings from a cargo-cola scan of [PROJECT_NAME]:

<findings>
{{PASTE_FINDINGS_JSON_OR_SARIF_HERE}}
</findings>

## YOUR TASK

Analyze these findings and produce a security report with the following sections:

### 1. Executive Summary
- Total findings count
- Breakdown by confidence: True Positives (actionable) vs Probable False Positives vs Informational
- Top 3 most critical issues

### 2. True Positives - Actionable Security Issues

For each likely true positive, provide:
- **Severity**: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🔵 LOW
- **Rule ID and Name**
- **Impact**: What could an attacker do?
- **Exploitability**: How easy is this to exploit? (Remote/Local, Auth required?, Complexity)
- **CVSS Estimate**: Rough score with justification
- **Location(s)**: File and line numbers
- **Description**: What the vulnerability is
- **Attack Scenario**: Concrete example of exploitation
- **Vulnerable Code**: Show the problematic code snippet from the evidence
- **Recommended Fix**: Provide the corrected code that resolves the vulnerability
- **Explanation**: Why the fix works and any caveats

**Code Fix Guidelines:**
- Show before/after code blocks using ```rust
- Make fixes minimal - change only what's necessary
- Use idiomatic Rust patterns
- Include necessary imports if adding new dependencies
- If multiple fix options exist, show the safest/simplest first

**Example format for code fixes:**

**Vulnerable Code:**
```rust
let pattern = env::var("USER_PATTERN")?;
let regex = Regex::new(&pattern)?;  // ReDoS risk
```

**Recommended Fix:**
```rust
let pattern = env::var("USER_PATTERN")?;
let escaped = regex::escape(&pattern);  // Escape special chars for literal match
let regex = Regex::new(&escaped)?;
```

*Alternative (if pattern matching is required):*
```rust
use regex::RegexBuilder;

let pattern = env::var("USER_PATTERN")?;
let regex = RegexBuilder::new(&pattern)
    .size_limit(10_000)  // Limit regex complexity
    .build()?;
```

Group by severity (Critical first, then High, Medium, Low).

### 3. Probable False Positives (with Evidence)

**⚠️ This section requires rigorous justification. See "Avoiding False Negatives" guidelines.**

For each finding classified as False Positive, provide the COMPLETE evidence template:

| Field | Your Response |
|-------|---------------|
| **Finding** | [RULE_ID] - [Function/Location] |
| **Dismissal Category** | Test code / Hardcoded value / Sanitized / No imports / Intentional |
| **File Path Evidence** | Quote the exact path showing test/mock context |
| **Exculpatory Code** | Quote specific code proving the pattern is safe |
| **Attacker Cannot Exploit Because** | Explain why exploitation is impossible |
| **Confidence Level** | High (>90%) / Medium (70-90%) / Low (<70%) |
| **Residual Risk** | None / Monitor in future / Consider hardening |
| **Suggested Rule Improvement** | How could cargo-cola avoid this FP? |

**If confidence is below 90%, escalate to True Positive with a note about uncertainty.**

### 4. Informational / Code Quality

List non-security findings (code style, best practices).

### 5. Remediation Priority

Create a prioritized fix list:
- **P0 (Immediate)**: Fix before release
- **P1 (High)**: Fix within sprint
- **P2 (Medium)**: Fix within quarter
- **P3 (Low)**: Backlog

### 6. False Negative Risk Assessment

**This section is REQUIRED if any findings were classified as False Positive.**

Provide a meta-analysis of your classifications:

| Metric | Value |
|--------|-------|
| Total Findings | [N] |
| True Positives | [N] ([%]) |
| False Positives | [N] ([%]) |
| **FP Rate Justification** | [If >30%, explain why] |

**False Negative Risk Factors:**

For each category of dismissed findings, assess residual risk:

| Dismissal Category | Count | Confidence | Risk if Wrong | Mitigation |
|--------------------|-------|------------|---------------|------------|
| Test code | [N] | High/Med | Low - not in prod | None needed |
| Hardcoded values | [N] | High/Med | Med - could change | Monitor value sources |
| Claimed sanitization | [N] | High/Med | High - bypass risk | Review sanitizers |
| No relevant imports | [N] | High/Med | Med - FFI possible | Check unsafe blocks |

**Highest-Risk Dismissals:**

List the top 3 False Positive classifications you're LEAST confident about:

1. **[RULE_ID]**: [Why you're uncertain] - **Recommend: [Manual review / Hardening / Accept risk]**
2. ...
3. ...

### 7. Appendix: Finding Counts by Rule

Table with: Rule ID | Name | Count | Severity | Estimated FP Rate

## ANALYSIS GUIDELINES

### ⚠️ CRITICAL: Avoiding False Negatives

**Your primary obligation is to avoid dismissing real vulnerabilities.**

A FALSE NEGATIVE (incorrectly dismissing a real vulnerability) is significantly more harmful than a FALSE POSITIVE (flagging benign code). When in doubt, classify as TRUE POSITIVE and note your uncertainty.

**Before classifying ANY finding as a False Positive, you MUST:**

1. **State your burden of proof**: Provide concrete evidence why this is NOT exploitable
2. **Show the exculpatory evidence**: Quote specific code that proves safety
3. **Consider attacker perspective**: Explain why an attacker cannot abuse this
4. **Document your reasoning chain**: Step-by-step logic for dismissal

**Evidence requirements for False Positive classification:**

| Dismissal Reason | Required Evidence |
|------------------|-------------------|
| "Test code only" | Show file path contains `/tests/`, `#[test]`, or `#[cfg(test)]` |
| "Constant/hardcoded" | Show the value is a literal string, not from env/args/stdin |
| "Sanitized elsewhere" | Quote the exact sanitization code and show data flow |
| "No relevant imports" | Show Cargo.toml dependencies AND confirm no FFI/unsafe paths |
| "Intentional pattern" | Quote code comment or API contract proving intent |

### Classification Standards

When determining True Positive vs False Positive:

**Classify as TRUE POSITIVE if:**
- Finding is in application code (not test/mock code)
- User input flows to dangerous sink without clear sanitization
- Cryptographic weakness in security-critical context
- Memory safety issue in unsafe block
- **ANY doubt exists about exploitability** (err on side of caution)
- Sanitization exists but may be bypassable or incomplete
- The vulnerable pattern could be copy-pasted into production code

**Classify as FALSE POSITIVE only with clear evidence:**
- Finding is definitively in test/mock/example code (cite file path)
- SQL injection finding but Cargo.toml has no database drivers AND no FFI
- The "dangerous" pattern is provably in a const string or error message
- Lock guard pattern has documented intentional scope-based holding
- Weak hash used for non-security purpose WITH code comment confirming this

**Context clues to check:**
- Is this in a `#[test]` function or `tests/` directory?
- Does the crate import relevant dependencies (database drivers, HTTP clients)?
- Is the "user input" actually from a config file or compile-time constant?
- Is there sanitization/validation nearby that the scanner missed?
- Could the code path be reached from an untrusted entry point?
- Does the crate expose a public API that could receive malicious input?

### False Positive Evidence Template

For EACH finding classified as False Positive, complete this template:

```
**Finding**: [RULE_ID] in [FUNCTION_NAME]

**Classification**: False Positive

**Dismissal Category**: [Test code / Hardcoded value / Sanitized / No relevant imports / Intentional]

**Evidence**:
1. File path: `[exact path]`
2. Exculpatory code: `[quote the specific code proving safety]`
3. Attacker analysis: [Why can't this be exploited?]

**Confidence**: [High (>90%) / Medium (70-90%) / Low (<70%)]

**Residual Risk**: [None / Low - monitor in future / Medium - consider hardening]
```

### Escalation Criteria

If MORE THAN 50% of findings are classified as False Positives:
1. Pause and reconsider your analysis threshold
2. Verify you are not being overly dismissive
3. Consider whether the crate's architecture provides unexpected attack surfaces
4. Document your meta-reasoning for the high FP rate

### Quality Checklist

Before finalizing your report, verify:
- [ ] Each False Positive has specific, quotable evidence
- [ ] You've considered indirect attack paths (e.g., user controls config file → value reaches sink)
- [ ] Library crates are analyzed for what CALLERS could pass in
- [ ] You haven't assumed benign intent for ambiguous patterns
- [ ] High FP rate is justified with architectural reasoning

## OUTPUT FORMAT

Produce a well-formatted Markdown report suitable for sharing with a development team.
Use tables, code blocks, and clear headings.
Be concise but thorough.
```

---

## USAGE

### Option 1: Direct Paste

1. Run cargo-cola:
   ```bash
   cargo-cola --crate-path /path/to/project
   ```

2. Copy the contents of `out/cola/findings.json`

3. Paste into Claude/Copilot chat with the prompt above

### Option 2: Using --output-for-llm (recommended)

```bash
cargo-cola --crate-path /path/to/project --output-for-llm analysis-context.md
```

This generates a file with the prompt template pre-filled with your findings.

Then in Copilot chat:
```
@workspace Analyze the security findings in analysis-context.md and produce a security report
```

### Option 3: Using @rustcola Agent (coming soon)

```
@rustcola scan /path/to/project --security-report
```

This runs the scan and produces the curated report in one step.
