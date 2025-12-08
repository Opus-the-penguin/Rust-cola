# Rust-cola — LLM-Assisted Static Security Analysis for Rust

Rust-cola is an **LLM-integrated static application security testing (SAST)** tool for Rust code. It combines a three-tier hybrid analysis engine (MIR heuristics, source inspection, and rustc HIR semantic analysis) with optional LLM-powered report generation for intelligent false positive filtering, exploitability analysis, and remediation suggestions.

> **Recent Achievement (Dec 2025):** 
> - **LLM Integration:** Added `--llm-report` with "Bring Your Own LLM" support (OpenAI, Anthropic, Ollama). Automated security analysis with false positive filtering, CVSS estimates, attack scenarios, and code fix suggestions.
> - **Standalone Reports:** Added `--report` for human-readable reports without LLM access, with heuristic-based triage.
> - **New Rules:** RUSTCOLA090 (Unbounded read_to_end), RUSTCOLA089 (YAML Deserialization), RUSTCOLA088 (SSRF), RUSTCOLA087 (SQL injection), RUSTCOLA086 (Path traversal) - all with 100% recall via inter-procedural analysis.
> - **Total: 89 security rules**

## Features

- **Three-Tier Analysis Architecture:**
  - **Tier 1 (MIR Heuristics):** 85 rules using pattern matching on compiler-generated MIR
  - **Tier 2 (Source Analysis):** 2 rules using AST inspection for comments and attributes  
  - **Tier 3 (Semantic Analysis):** HIR integration for type-aware rules (type sizes, Send/Sync detection)
- **LLM-Assisted Analysis (Optional):** Integrates with LLMs (Claude, GPT-4, Ollama, or any OpenAI-compatible API) to enhance raw findings with:
  - **Precision improvement:** Intelligent false positive filtering based on code context
  - **Severity organization:** Findings grouped and prioritized by actual risk
  - **Exploitability analysis:** Attack scenarios, CVSS estimates, and real-world impact assessment
  - **Remediation suggestions:** Concrete code fixes for each confirmed vulnerability
  - **Executive reporting:** Polished security reports ready for stakeholders
- **87 Built-in Security Rules** covering:
	- Memory safety issues: `Box::into_raw` leaks, unchecked `transmute`, `Vec::set_len` misuse, premature `MaybeUninit::assume_init`, deprecated zero-initialization functions
	- Unsafe code patterns: unsafe blocks, untrusted environment variable reads, command execution with user-influenced input
	- Cryptography: weak hash algorithms (MD5, SHA-1, RIPEMD, CRC), weak ciphers (DES, RC4, Blowfish), hard-coded cryptographic keys, predictable random seeds
	- Network security: HTTP URLs, disabled TLS certificate validation, SSRF detection
	- Concurrency: unsafe `Send`/`Sync` implementations, mutex guard issues, panic in destructors
	- FFI: allocator mismatches, dangling CString pointers, blocking calls in async contexts
	- Input validation: SQL injection, path traversal, YAML deserialization attacks, untrusted input to commands and file operations
	- Code hygiene: commented-out code, overscoped allow attributes
- Generates findings in JSON format and SARIF format for CI/CD integration
- Supports custom rule extensions via YAML rulepacks
- Includes experimental research prototypes for additional vulnerability patterns

## Architecture

Rust-cola uses a hybrid three-tier detection approach:

```
┌─────────────────────────────────────────────────┐
│           Rust-cola Analysis Engine             │
├─────────────────────────────────────────────────┤
│  Tier 1: MIR        Tier 2: Source    Tier 3:   │
│  Heuristics         Analysis          HIR       │
│  (85 rules)         (2 rules)         ✅ Active │
│  ✅ Pattern          ✅ Comments/      ✅ Type    │
│     matching           Attributes        queries │
│                                       ✅ Send/   │
│                                          Sync   │
└─────────────────────────────────────────────────┘
```

**Tier 1 (MIR Heuristics):** Fast pattern matching on Mid-level Intermediate Representation strings for API misuse, dangerous patterns, and common vulnerabilities. Best for clear-cut security violations.

**Tier 2 (Source Analysis):** AST-based inspection using the `syn` crate for patterns requiring source-level context like comments, attributes, and formatting that don't appear in MIR.

**Tier 3 (Semantic Analysis):** Deep semantic analysis via rustc HIR integration for type-aware rules. Currently supports type size queries (100% accuracy) and Send/Sync trait detection. See `docs/tier3-hir-architecture.md`.

Research prototypes are available in [`mir-extractor/src/prototypes.rs`](mir-extractor/src/prototypes.rs) with documentation in [`docs/research/`](docs/research/).

## Inter-Procedural Taint Analysis

Rust-cola includes **inter-procedural taint analysis** that tracks data flow across function boundaries—not just within a single function. This is critical for detecting real-world vulnerabilities where untrusted input flows through helper functions before reaching dangerous sinks.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                 Inter-Procedural Taint Flow                     │
│                                                                 │
│   get_user_input()     process_data()        execute_query()   │
│        │                    │                      │            │
│        ▼                    ▼                      ▼            │
│   ┌─────────┐          ┌─────────┐           ┌─────────┐       │
│   │ env::var│ ───────► │ helper  │ ────────► │ sqlx::  │       │
│   │ [SOURCE]│  taint   │ fn()    │   taint   │ query() │       │
│   └─────────┘  flows   └─────────┘   flows   │ [SINK]  │       │
│                                              └─────────┘       │
│                                                                 │
│   Detected: SQL injection via 3-function call chain            │
└─────────────────────────────────────────────────────────────────┘
```

**The analysis proceeds in phases:**

1. **Call Graph Construction** — Extract function calls from MIR to build a directed graph of dependencies
2. **Function Summarization** — Analyze each function bottom-up to create summaries describing how taint flows through parameters and return values
3. **Path Finding** — Starting from source functions, explore the call graph to find paths to sink functions
4. **Sanitization Detection** — Identify validation patterns (allowlists, bounds checks, escaping) that break taint flows

### Why This Matters

Consider this vulnerable pattern that intra-procedural analysis would **miss**:

```rust
fn get_user_path() -> String {
    std::env::var("USER_PATH").unwrap()  // Taint source
}

fn process_file() {
    let path = get_user_path();           // Taint flows in
    std::fs::read_to_string(&path);       // Path traversal sink!
}
```

An intra-procedural analyzer only sees:
- `get_user_path()`: Returns a String (no visible taint)
- `process_file()`: Uses that String in a filesystem call

It **cannot** see that the String originates from `env::var`. Rust-cola's inter-procedural analysis detects this because it:
1. Summarizes `get_user_path()` as returning tainted data (`ReturnTaint::FromSource`)
2. Tracks that `process_file()` calls it and uses the result in a sink
3. Reports the full taint path: `env::var → get_user_path → process_file → fs::read_to_string`

### Supported Source → Sink Flows

| Source Type | Examples |
|-------------|----------|
| Environment | `env::var()`, `env::args()` |
| Stdin | `stdin().read_line()`, `stdin().lines()` |
| Files | `fs::read_to_string()` on untrusted paths |
| Network | `TcpStream::read()`, HTTP request bodies |

| Sink Type | Examples |
|-----------|----------|
| Command Execution | `Command::new()`, `Command::arg()` |
| Filesystem | `fs::read_to_string()`, `File::create()`, `fs::remove_file()` |
| SQL | `sqlx::query()`, `diesel::sql_query()`, format strings with SQL keywords |
| HTTP/SSRF | `reqwest::get()`, `ureq::get()` with user-controlled URLs |
| Regex | `Regex::new()` with user-controlled patterns |

### Sanitization Patterns Detected

Rust-cola recognizes common sanitization patterns that break taint flows:

- **Path validation:** `path.canonicalize()?.starts_with(base_dir)`
- **SQL parameterization:** `.bind()`, `?` placeholders
- **Allowlist checks:** `allowed_values.contains(&input)`
- **Input parsing:** Integer parsing for numeric-only fields
- **Escaping:** `regex::escape()`, string replacement

### Current Capabilities

| Metric | Value |
|--------|-------|
| **Call chain depth** | Unlimited (with cycle detection) |
| **Cross-function detection** | ✅ Full support |
| **Closure capture tracking** | ✅ Phase 3.5.2 |
| **Path-sensitive (branching)** | ✅ CFG-based analysis |
| **False positive filtering** | ✅ Validation guard detection |

For implementation details, see [`mir-extractor/src/interprocedural.rs`](mir-extractor/src/interprocedural.rs).

## Why Rust-cola Requires Compilation

Unlike traditional static analysis tools that operate purely on source code or abstract syntax trees (ASTs), Rust-cola requires the target code to be **compiled** by the Rust compiler. This is a deliberate design choice that unlocks significantly deeper analysis capabilities.

### The Compilation Requirement

When you run Rust-cola, it invokes `cargo rustc` with special flags to extract the compiler's internal representations:

- **MIR (Mid-level Intermediate Representation):** A simplified, desugared representation of Rust code after type checking, borrow checking, and monomorphization
- **HIR (High-level Intermediate Representation):** The compiler's typed AST with full semantic information

This means your code must successfully compile before Rust-cola can analyze it. While this adds a prerequisite, the benefits far outweigh the costs.

### Why This Matters for Rust

Rust is uniquely challenging for source-level static analysis. Many other languages (JavaScript, Python, Java) can be effectively analyzed at the source/AST level because their semantics are relatively straightforward. Rust, however, has:

| Rust Feature | Source/AST Challenge | MIR/HIR Solution |
|--------------|---------------------|------------------|
| **Macros** | Unexpanded, opaque tokens | Fully expanded, analyzable code |
| **Generics & Monomorphization** | Abstract type parameters | Concrete instantiated types |
| **Trait resolution** | Unknown impl at call sites | Resolved to specific implementations |
| **Deref coercion** | Implicit, invisible in source | Explicit operations in MIR |
| **Borrow checker semantics** | Complex lifetime inference | Already validated, explicit lifetimes |
| **Pattern matching** | Complex match expressions | Desugared to simple control flow |
| **Closures** | Anonymous types, captures hidden | Explicit struct types with fields |
| **Async/await** | Sugar over state machines | Explicit Future state machines |

### Concrete Examples

**Example 1: Macro Expansion**

```rust
// Source code - what an AST scanner sees
sqlx::query!("SELECT * FROM users WHERE id = {}", user_id);

// MIR - what Rust-cola sees
// The macro is fully expanded, revealing the actual SQL string
// construction and parameter binding, enabling SQL injection detection
```

**Example 2: Generic Monomorphization**

```rust
// Source code
fn process<T: AsRef<[u8]>>(data: T) { ... }
process(user_input);

// MIR - Rust-cola sees the concrete instantiation
// process::<String>(user_input) - enabling taint tracking through generics
```

**Example 3: Trait Method Resolution**

```rust
// Source code - which `read` implementation?
reader.read(&mut buffer)?;

// MIR - Rust-cola knows exactly which impl is called
// <File as std::io::Read>::read - enabling accurate API tracking
```

### Comparison with Source-Level Scanners

| Capability | Source/AST Scanner | Rust-cola (MIR/HIR) |
|------------|-------------------|---------------------|
| Macro-heavy code | ❌ Limited/blind | ✅ Full visibility |
| Generic functions | ❌ Abstract types only | ✅ Concrete instantiations |
| Trait objects | ❌ Cannot resolve impls | ✅ Knows exact types |
| Type sizes (for buffer overflow) | ❌ Must guess | ✅ Exact via rustc |
| Send/Sync safety | ❌ Cannot verify | ✅ Uses trait solver |
| Deref chains | ❌ Misses implicit derefs | ✅ All explicit in MIR |
| False positive rate | Higher | Lower |

### The Trade-off

The compilation requirement means:

- ✅ **Pro:** Much higher detection accuracy and lower false positives
- ✅ **Pro:** Access to compiler's type system, trait solver, and borrow checker results  
- ✅ **Pro:** Analysis of macro-expanded code (critical for Rust ecosystems using `serde`, `tokio`, etc.)
- ⚠️ **Con:** Code must compile successfully before analysis
- ⚠️ **Con:** Requires nightly Rust toolchain (for `-Zunpretty=mir` flag)
- ⚠️ **Con:** Analysis time includes compilation time

For security scanning, we believe the accuracy gains justify the compilation requirement. Rust's deep semantics—macros, traits, generics, lifetimes—make source-level analysis fundamentally limited.

## Getting started

> **Prerequisites**
> - Rust (nightly toolchain) via `rustup`.
> - On Windows, Visual Studio Build Tools with the C++ workload (for `link.exe`).
> - On macOS, install the Xcode Command Line Tools (`xcode-select --install`) for Clang and the system linker.
> - On Linux, install a C/C++ toolchain and linker (for example on Debian/Ubuntu: `sudo apt install build-essential pkg-config libssl-dev`).

Install `rustup` if it is not already present:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install nightly
```

Restart your shell (or source `$HOME/.cargo/env`) so that `cargo` and `rustc` are on your `PATH`.

Run the analysis against the bundled example crate:

```powershell
# Windows PowerShell
cd Rust-cola
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola --sarif out/cola/cola.sarif --fail-on-findings=false
```

```bash
# macOS/Linux (bash/zsh)
cd Rust-cola
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola --sarif out/cola/cola.sarif --fail-on-findings=false
```

This command will:

1. Run `cargo +nightly rustc -- -Zunpretty=mir` to obtain MIR for `examples/simple`.
2. Convert the textual output into `out/cola/mir.json`.
3. Run the security rules, writing `out/cola/findings.json` and a SARIF report (default `out/cola/cola.sarif`).
4. Exit with a non-zero status if findings are present (omit `--fail-on-findings` or set it to `true`).

Inspect the structured MIR directly:

```powershell
# Windows PowerShell
Get-Content out/cola/mir.json | Select-Object -First 40
```

```bash
# macOS/Linux (bash/zsh)
head -n 40 out/cola/mir.json
```

### AI-Powered Security Reports (NEW)

Rust-cola offers flexible reporting options with or without LLM integration:

| Mode | Command | Best For |
|------|---------|----------|
| **Standalone Report** | `--report report.md` | Quick triage without LLM access |
| **LLM Prompt** | `--llm-report prompt.md` | Manual submission to any LLM |
| **Automated LLM** | `--llm-report report.md --llm-endpoint ...` | CI/CD integration |

#### Standalone Reports (No LLM Required)

Generate a human-readable security report with heuristic-based triage:

```bash
cargo-cola --crate-path /path/to/project --report security-report.md
```

The standalone report includes:
- **Automatic triage:** Findings categorized as High Confidence / Needs Review / Likely False Positive
- **False positive detection:** Test files, example code, and mock patterns automatically flagged
- **Severity breakdown:** Findings grouped by severity level
- **Remediation guide:** Quick reference for common fix patterns

#### LLM-Enhanced Reports

For best results, integrate with an LLM to transform raw findings into curated security reports with:

- **Triage & Classification:** Separates true positives from false positives  
- **Severity Assessment:** CVSS estimates, exploitability analysis
- **Attack Scenarios:** Concrete examples of how vulnerabilities could be exploited
- **Code Fixes:** Specific remediation code for each vulnerability
- **Prioritization:** P0-P3 remediation priority ranking

**Option 1: Generate LLM prompt for manual submission**

```bash
cargo-cola --crate-path /path/to/project --llm-report security-context.md
# Then paste content into Claude, GPT-4, or your preferred LLM
```

**Option 2: Automated LLM analysis (Bring Your Own LLM)**

```bash
# With OpenAI
export RUSTCOLA_LLM_API_KEY=sk-...
cargo-cola --crate-path . --llm-report report.md \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4

# With Anthropic Claude  
cargo-cola --crate-path . --llm-report report.md \
  --llm-endpoint https://api.anthropic.com/v1/messages \
  --llm-model claude-3-sonnet-20240229 \
  --llm-api-key $ANTHROPIC_API_KEY

# With local Ollama (no API key needed)
cargo-cola --crate-path . --llm-report report.md \
  --llm-endpoint http://localhost:11434/v1/chat/completions \
  --llm-model llama2
```

**Option 3: VS Code with GitHub Copilot**

1. Generate a prompt file: `cargo-cola --crate-path . --llm-report security-context.md`
2. Open `security-context.md` in VS Code
3. Ask Copilot: "Analyze these security findings and produce a curated report"

#### LLM Options Reference

| Option | Description | Default |
|--------|-------------|---------|
| `--llm-report <PATH>` | Output path for LLM-optimized markdown | - |
| `--llm-endpoint <URL>` | LLM API endpoint (OpenAI-compatible) | - |
| `--llm-model <NAME>` | Model name | `gpt-4` |
| `--llm-api-key <KEY>` | API key (or use `RUSTCOLA_LLM_API_KEY` env var) | - |
| `--llm-max-tokens <N>` | Max response tokens | `4096` |
| `--report <PATH>` | Standalone report (no LLM) | - |

#### Example LLM Output

```markdown
# Security Analysis Report

## Executive Summary
- Total findings: 150
- True Positives (Actionable): ~25 (17%)
- False Positives: ~100 (67%)
- Informational: ~25 (17%)

## 🔴 CRITICAL: RUSTCOLA087 - SQL Injection
**Impact:** Data breach, unauthorized access  
**Exploitability:** HIGH - Remote, unauthenticated  
**Attack Scenario:** `GET /users?id=1 OR 1=1--`

**Vulnerable Code:**
```rust
let query = format!("SELECT * FROM users WHERE id = {}", user_id);
```

**Recommended Fix:**
```rust
let query = sqlx::query("SELECT * FROM users WHERE id = ?")
    .bind(user_id);
```
...
```

#### Recommendation

While Rust-cola works in standalone mode, **LLM integration is strongly recommended** for security reviews. LLMs dramatically improve:

- **False positive filtering:** Typically reduces 1000+ raw findings to 20-30 actionable issues
- **Remediation quality:** Provides specific, copy-paste-ready code fixes
- **Prioritization:** Risk-based ordering vs. flat rule severity
- **Context understanding:** Explains why findings matter in your specific codebase

For air-gapped environments or CI pipelines without LLM access, use `--report` for basic triage, then review high-confidence findings manually.

### Using rulepacks

You can extend the analysis with YAML rulepacks. A starter pack lives at `examples/rulepacks/example-basic.yaml`.

```powershell
# Windows PowerShell
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola --rulepack examples/rulepacks/example-basic.yaml --fail-on-findings=false
```

```bash
# macOS/Linux (bash/zsh)
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola --rulepack examples/rulepacks/example-basic.yaml --fail-on-findings=false
```

Each `--rulepack` flag loads another YAML file. Rulepacks support string matching on MIR function signatures and bodies for organization-specific checks. See the comments inside the example file for the schema.

> **Experimental WASM support**
>
> WASM-based rule plugins are under development. The CLI accepts `.wasm` modules via `--wasm-rule path/to/rule.wasm` and records metadata for future execution.

### Security rule backlog

The backlog in [`docs/security-rule-backlog.md`](docs/security-rule-backlog.md) tracks over 100 candidate security rules with feasibility notes and prototype links.

## Example commands

> Choose the snippet that matches your shell. Forward slashes in paths work on both Windows and Unix-like systems; feel free to use backslashes in PowerShell if you prefer.

- **Quick standalone security report** (no LLM required):

	```bash
	cargo-cola --crate-path . --report security-report.md
	# Opens with automatic triage and heuristic false positive detection
	```

- **LLM-powered security analysis** (recommended for thorough reviews):

	```bash
	# Automated with OpenAI
	export RUSTCOLA_LLM_API_KEY=sk-...
	cargo-cola --crate-path . --llm-report report.md \
	  --llm-endpoint https://api.openai.com/v1/chat/completions

	# Or generate prompt for manual LLM submission
	cargo-cola --crate-path . --llm-report security-context.md
	# Then open in VS Code and ask Copilot to analyze it
	```

- **Scan the current project** (writes MIR, findings, and SARIF to `out/my-project`):

	```powershell
	# Windows PowerShell
	cargo run -p cargo-cola -- --crate-path . --out-dir out/my-project --sarif out/my-project/cola.sarif --fail-on-findings=true
	```

	```bash
	# macOS/Linux (bash/zsh)
	cargo run -p cargo-cola -- --crate-path . --out-dir out/my-project --sarif out/my-project/cola.sarif --fail-on-findings=true
	```

- **Scan another workspace without failing the build**:

	```powershell
	# Windows PowerShell
	cargo run -p cargo-cola -- --crate-path path/to/crate --out-dir out/full-scan --fail-on-findings=false
	```

	```bash
	# macOS/Linux (bash/zsh)
	cargo run -p cargo-cola -- --crate-path path/to/crate --out-dir out/full-scan --fail-on-findings=false
	```

- **Run the extractor CLI directly** (same engine underpinning `cargo cola`):

	```powershell
	# Windows PowerShell
	cargo run -p mir-extractor -- --crate-path examples/simple --out-dir out/mir --sarif out/mir/cola.sarif
	```

	```bash
	# macOS/Linux (bash/zsh)
	cargo run -p mir-extractor -- --crate-path examples/simple --out-dir out/mir --sarif out/mir/cola.sarif
	```

- **Extend the rule set with a YAML rulepack**:

	```powershell
	# Windows PowerShell
	cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/rulepack --rulepack examples/rulepacks/example-basic.yaml --fail-on-findings=false
	```

	```bash
	# macOS/Linux (bash/zsh)
	cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/rulepack --rulepack examples/rulepacks/example-basic.yaml --fail-on-findings=false
	```

All commands accept `--mir-json` and `--findings-json` to override output paths, plus repeatable `--rulepack`/`--wasm-rule` flags for extending the rule set.

## Auditable release builds

Supply-chain metadata is embedded in the release binary using [`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable). The CI workflow installs the plugin, produces an auditable `cargo-cola` binary, and asserts that the artifact includes the metadata marker. To reproduce the same check locally:

```powershell
# Windows PowerShell
cargo install --locked cargo-auditable
cargo auditable build -p cargo-cola --release --target-dir target/auditable
$bytes = [System.IO.File]::ReadAllBytes('target/auditable/release/cargo-cola.exe')
if (-not ([System.Text.Encoding]::ASCII.GetString($bytes).ToLower().Contains('cargo-auditable'))) {
	throw 'cargo-auditable metadata marker not found'
}
```

```bash
# Linux (bash/zsh)
cargo install --locked cargo-auditable
cargo auditable build -p cargo-cola --release --target-dir target/auditable
python - <<'PY'
from pathlib import Path

binary = Path("target/auditable/release/cargo-cola")
data = binary.read_bytes()
if b"cargo-auditable" not in data:
	raise SystemExit("cargo-auditable metadata marker not found")
PY
```

```bash
# macOS (bash/zsh)
cargo install --locked cargo-auditable
cargo auditable build -p cargo-cola --release --target-dir target/auditable
python3 - <<'PY'
from pathlib import Path

binary = Path("target/auditable/release/cargo-cola")
data = binary.read_bytes()
if b"cargo-auditable" not in data:
	raise SystemExit("cargo-auditable metadata marker not found")
PY
```

> Tip: You can inspect the embedded metadata using `readelf --notes target/auditable/release/cargo-cola` (Linux) or `otool -l target/auditable/release/cargo-cola` (macOS).

The generated binary includes provenance metadata for supply-chain analysis tools.

## Roadmap

- Integrate with `rustc_interface` for direct MIR/HIR access
- Promote research prototypes to production rules with full SARIF metadata
- Expand dataflow analysis capabilities  
- Support pluggable rulepacks in native code and WASM
- Add GitHub Action for SARIF publishing and CI integration

## GitHub Action

A workflow example is available in `.github/workflows/cola-ci.yml`. It runs the analysis on each push or pull request, generates SARIF output, and uploads results to GitHub's code scanning dashboard.
