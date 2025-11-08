# Clearing GitHub Code Scanning Alerts

## Current Situation

**Problem:** 72 open Code Scanning alerts from rust-cola, all marked "Detected by rust-cola" in test examples or cargo-cola, even though we've fixed the workflows.

**Status as of Nov 8, 2025 10:27 AM:**
- ✅ Fixed cola-ci workflow (commit 389aaa0) - now uses production-only workspace
- ✅ Improved RUSTCOLA039 rule (commit 2034ff9) - eliminated false positives
- ✅ Both workflows ran successfully at 10:27 AM
- ❌ Alerts still showing as open in GitHub UI

## Why Alerts Aren't Auto-Clearing

GitHub Code Scanning alerts don't automatically dismiss when code changes. They only clear when:

1. **New SARIF upload explicitly removes them** - Same tool, same category, matching location
2. **Alert fingerprint matches** - GitHub uses `file_path + line + rule_id + tool` to match alerts
3. **Location no longer exists** - File deleted or line significantly changed

### The Problem: Category Mismatch

**Old alerts** (before commit 8db7c92):
```yaml
# No category specified - defaults to tool name
upload-sarif:
  sarif_file: target/cola/cola.sarif
  # category: (not set)
```

**New workflow** (after commit 8db7c92):
```yaml
upload-sarif:
  sarif_file: target/cola/cola.sarif
  category: rust-cola-findings  # ← Added this
```

**Result:** GitHub treats these as **different analysis runs** and doesn't match old alerts to new ones!

## Solution Options

### Option 1: Manual Dismissal (Fastest - 5 minutes)

**When to use:** If you need clean alerts immediately

**Steps:**
1. Go to https://github.com/Opus-the-penguin/Rust-cola/security/code-scanning
2. Filter alerts by "Detected by rust-cola"
3. Bulk select all 72 alerts
4. Dismiss as: **"False positive - Test code with intentional vulnerabilities"**
5. Add comment: "These are from test examples that are now excluded from analysis via workspace filtering (see commit 389aaa0)"

**Pros:**
- ✅ Immediate cleanup
- ✅ Clear audit trail
- ✅ Works regardless of category mismatch

**Cons:**
- ❌ Manual process
- ❌ Doesn't verify new workflow is working correctly

### Option 2: Trigger New Upload Without Category (Recommended)

**When to use:** If you want alerts to auto-clear and verify the fix works

**The issue:** We added a category, which GitHub treats as a new analysis stream. We need to upload once MORE without the category to clear the old alerts.

**Steps:**

1. **Temporarily remove category from workflow:**

```yaml
# .github/workflows/cola-ci.yml
- name: Upload SARIF results from Rust-cola
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: target/cola/cola.sarif
    # category: rust-cola-findings  # ← Comment this out temporarily
```

2. **Commit and push:**
```bash
git add .github/workflows/cola-ci.yml
git commit -m "Temporarily remove category to clear old alerts"
git push origin main
```

3. **Wait for workflow to complete** (~5-10 minutes)

4. **Verify alerts cleared** - Check GitHub Security tab

5. **Restore category and push again:**
```yaml
# .github/workflows/cola-ci.yml
- name: Upload SARIF results from Rust-cola
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: target/cola/cola.sarif
    category: rust-cola-findings  # ← Restore this
```

**Pros:**
- ✅ Alerts auto-clear (verifies GitHub matching works)
- ✅ Confirms new workflow produces clean results
- ✅ Future alerts will use proper category

**Cons:**
- ❌ Takes 2 commits and ~20 minutes total
- ❌ Slightly hacky (category on/off)

### Option 3: Wait and Manually Dismiss (Hybrid)

**When to use:** If you're unsure whether alerts will eventually clear

**Steps:**
1. Wait 24 hours to see if GitHub eventually matches the alerts
2. If they don't clear, manually dismiss them (Option 1)

**Pros:**
- ✅ Minimal work
- ✅ Gives GitHub time to process

**Cons:**
- ❌ Alerts stay open for a day
- ❌ Likely won't work (category mismatch is definitive)

### Option 4: Script-Based Bulk Dismissal (Advanced)

**When to use:** If you have many alerts and want automation

**Requirements:**
- GitHub CLI installed and authenticated
- `gh` command with `security` extensions

**Script:**
```bash
#!/bin/bash
# Bulk dismiss all rust-cola alerts in test examples

# Get all open alerts with rust-cola
gh api "/repos/Opus-the-penguin/Rust-cola/code-scanning/alerts?state=open&tool_name=rust-cola" \
  | jq -r '.[] | select(.most_recent_instance.location.path | startswith("examples/")) | .number' \
  | while read alert_num; do
    echo "Dismissing alert #$alert_num"
    gh api -X PATCH "/repos/Opus-the-penguin/Rust-cola/code-scanning/alerts/$alert_num" \
      -f state='dismissed' \
      -f dismissed_reason='false positive' \
      -f dismissed_comment='Test code with intentional vulnerabilities - excluded from analysis since commit 389aaa0'
  done
```

**Pros:**
- ✅ Automated bulk dismissal
- ✅ Can filter by path (examples/* only)
- ✅ Audit trail via API

**Cons:**
- ❌ Requires GitHub CLI setup
- ❌ More complex

## My Recommendation

### For immediate cleanup: **Option 1** (Manual Dismissal)
- Takes 5 minutes
- Clean Security tab right away
- No risk

### For verification: **Option 2** (Re-upload without category)
- Takes 20 minutes
- Confirms workflow is actually fixed
- Proper long-term solution

### Best approach: **Do both in sequence**

1. **Now:** Manually dismiss all 72 alerts (Option 1)
   - Gets immediate cleanup
   - Unblocks security review

2. **Then:** Temporarily remove category and re-push (Option 2)
   - Verifies new workflow produces ~1-5 findings (not 72)
   - Confirms production-only workspace filtering works
   - Restores category for future runs

## Verification Steps

After clearing alerts, verify the fix is working:

### 1. Check Latest SARIF Upload

Go to the most recent cola-ci workflow run:
- https://github.com/Opus-the-penguin/Rust-cola/actions/workflows/cola-ci.yml
- Click latest run
- Download artifacts (if available)
- Or check logs for "X findings" count

**Expected:** ~1-5 findings (only from production code)
**Not:** 72+ findings (would indicate test examples still being analyzed)

### 2. Check Findings by Path

In GitHub Security tab, look at remaining alerts:
- ✅ Alerts in `cargo-cola/src/`, `mir-extractor/src/` - OK (production code)
- ❌ Alerts in `examples/allocator-mismatch-ffi/`, etc. - BAD (filtering failed)

### 3. Local Verification

Run the same command CI uses:

```bash
# Use production-only workspace
cat > Cargo.toml.production <<'EOF'
[workspace]
members = ["cargo-cola", "mir-extractor", "examples/simple", "examples/hir-typeck-repro"]
resolver = "2"
EOF

cp Cargo.toml Cargo.toml.backup
cp Cargo.toml.production Cargo.toml

# Run cargo-cola
cargo run -p cargo-cola -- \
  --crate-path . \
  --out-dir target/verify \
  --sarif target/verify/cola.sarif \
  --fail-on-findings false

# Check findings count
cat target/verify/findings.json | python3 -c "import sys, json; print(f'{len(json.load(sys.stdin))} findings')"

# Restore workspace
mv Cargo.toml.backup Cargo.toml
```

**Expected output:** `1 findings` or similar (only RUSTCOLA038 in cargo-cola tests)

## Future Prevention

To avoid this issue in the future:

1. **Always use categories** - Helps GitHub track different analysis tools
   ```yaml
   category: rust-cola-findings
   ```

2. **Test workflow changes locally** - Run cargo-cola with same flags CI uses

3. **Monitor first run** - After workflow changes, check that findings count is expected

4. **Document expected baseline** - Keep a note of acceptable findings count
   ```
   Expected baseline: 1-5 findings in production code
   - RUSTCOLA038 in cargo-cola/tests/cli.rs (acceptable test false positive)
   - RUSTCOLA039 false positives should be 0 after context-aware improvement
   ```

## Related Issues

- GitHub Issue #172: "Hard-coded cryptographic key or IV" - Fixed by commit 2034ff9
- Workspace filtering: Documented in `docs/workspace-filtering-fix.md`
- RUSTCOLA039 improvement: Documented in `docs/RUSTCOLA039-improvement.md`

## References

- [GitHub Code Scanning Alerts API](https://docs.github.com/en/rest/code-scanning)
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CodeQL Upload SARIF Action](https://github.com/github/codeql-action/tree/main/upload-sarif)
