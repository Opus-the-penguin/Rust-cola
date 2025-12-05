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

### 3. Probable False Positives

For findings that appear to be detection errors:
- Explain WHY it's likely a false positive
- Provide evidence from the finding data
- Suggest rule improvements if applicable

### 4. Informational / Code Quality

List non-security findings (code style, best practices).

### 5. Remediation Priority

Create a prioritized fix list:
- **P0 (Immediate)**: Fix before release
- **P1 (High)**: Fix within sprint
- **P2 (Medium)**: Fix within quarter
- **P3 (Low)**: Backlog

### 6. Appendix: Finding Counts by Rule

Table with: Rule ID | Name | Count | Severity | Estimated FP Rate

## ANALYSIS GUIDELINES

When determining True Positive vs False Positive:

**Likely TRUE POSITIVE if:**
- Finding is in application code (not test/mock code)
- User input flows to dangerous sink without sanitization
- Cryptographic weakness in security-critical context
- Memory safety issue in unsafe block

**Likely FALSE POSITIVE if:**
- Finding is in test/mock/example code
- SQL injection finding but no database imports in the crate
- The "dangerous" pattern is in a const string or error message
- Lock guard pattern is intentional (resource held for scope duration)
- Weak hash used for non-security purpose (checksums, caching)

**Context clues to check:**
- Is this in a `#[test]` function or `tests/` directory?
- Does the crate import relevant dependencies (database drivers, HTTP clients)?
- Is the "user input" actually from a config file or compile-time constant?
- Is there sanitization/validation nearby that the scanner missed?

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
