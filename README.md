# Rust-cola# Rust-cola — LLM-Assisted Static Security Analysis for Rust



Static security analysis for Rust. Combines MIR-based detection with optional LLM integration for false positive filtering and remediation suggestions.Rust-cola is an **LLM-integrated static application security testing (SAST)** tool for Rust code. It combines a three-tier hybrid analysis engine (MIR heuristics, source inspection, and rustc HIR semantic analysis) with optional LLM-powered report generation for intelligent false positive filtering, exploitability analysis, and remediation suggestions.



## Quick Start> **Recent Achievement (Dec 2025):** 

> - **LLM Integration:** Added `--llm-report` with "Bring Your Own LLM" support (OpenAI, Anthropic, Ollama). Automated security analysis with false positive filtering, CVSS estimates, attack scenarios, and code fix suggestions.

### Preferred: Use with an AI Agent> - **Standalone Reports:** Added `--report` for human-readable reports without LLM access, with heuristic-based triage.

> - **New Rules:** RUSTCOLA091 (JSON/TOML deserialization), RUSTCOLA090 (Unbounded read_to_end), RUSTCOLA089 (YAML Deserialization), RUSTCOLA088 (SSRF), RUSTCOLA087 (SQL injection), RUSTCOLA086 (Path traversal) - all with 100% recall via inter-procedural analysis.

The recommended way to use Rust-cola is through an AI agent in your IDE (GitHub Copilot, Cursor, or similar) or via direct LLM API access. The agent handles scan result interpretation, false positive pruning, exploitability analysis, and remediation suggestions.> - **Total: 87 security rules**



**Step 1: Run the scan**## Features



```bash- **Three-Tier Analysis Architecture:**

cargo-cola --crate-path /path/to/project --llm-prompt  - **Tier 1 (MIR Heuristics):** 85 rules using pattern matching on compiler-generated MIR

```  - **Tier 2 (Source Analysis):** 2 rules using AST inspection for comments and attributes  

  - **Tier 3 (Semantic Analysis):** HIR integration for type-aware rules (type sizes, Send/Sync detection)

This produces `out/reports/llm-prompt.md` containing the findings formatted for LLM analysis.- **LLM-Assisted Analysis (Optional):** Integrates with LLMs (Claude, GPT-4, Ollama, or any OpenAI-compatible API) to enhance raw findings with:

  - **Precision improvement:** Intelligent false positive filtering based on code context

**Step 2: Submit to your AI agent**  - **Severity organization:** Findings grouped and prioritized by actual risk

  - **Exploitability analysis:** Attack scenarios, CVSS estimates, and real-world impact assessment

Open the prompt file and paste this into your AI agent chat window:  - **Remediation suggestions:** Concrete code fixes for each confirmed vulnerability

  - **Executive reporting:** Polished security reports ready for stakeholders

```- **87 Built-in Security Rules** covering:

Analyze the security findings in this file. For each finding:	- Memory safety issues: `Box::into_raw` leaks, unchecked `transmute`, `Vec::set_len` misuse, premature `MaybeUninit::assume_init`, deprecated zero-initialization functions

1. Determine if it is a true positive or false positive	- Unsafe code patterns: unsafe blocks, untrusted environment variable reads, command execution with user-influenced input

2. For true positives: assess severity (Critical/High/Medium/Low), describe the attack scenario, and provide a code fix	- Cryptography: weak hash algorithms (MD5, SHA-1, RIPEMD, CRC), weak ciphers (DES, RC4, Blowfish), hard-coded cryptographic keys, predictable random seeds

3. Group findings by priority: P0 (fix immediately), P1 (fix this sprint), P2 (fix this quarter)	- Network security: HTTP URLs, disabled TLS certificate validation, SSRF detection

4. Explain why false positives are not exploitable	- Concurrency: unsafe `Send`/`Sync` implementations, mutex guard issues, panic in destructors

	- FFI: allocator mismatches, dangling CString pointers, blocking calls in async contexts

Output a markdown security report.	- Input validation: SQL injection, path traversal, YAML/JSON/TOML deserialization attacks, untrusted input to commands and file operations

```	- Code hygiene: commented-out code, overscoped allow attributes

- Generates findings in JSON format and SARIF format for CI/CD integration

Or if the agent has file access:- Supports custom rule extensions via YAML rulepacks

- Includes experimental research prototypes for additional vulnerability patterns

```

@workspace Review out/reports/llm-prompt.md and produce a security report with triage, severity ranking, and remediation code.## Architecture

```

Rust-cola uses a hybrid three-tier detection approach:

### Alternative: Automated LLM API

```

For CI pipelines or scripted workflows:┌─────────────────────────────────────────────────┐

│           Rust-cola Analysis Engine             │

```bash├─────────────────────────────────────────────────┤

export RUSTCOLA_LLM_API_KEY=sk-...│  Tier 1: MIR        Tier 2: Source    Tier 3:   │

cargo-cola --crate-path . --llm-report report.md \│  Heuristics         Analysis          HIR       │

  --llm-endpoint https://api.openai.com/v1/chat/completions \│  (85 rules)         (2 rules)         ✅ Active │

  --llm-model gpt-4│  ✅ Pattern          ✅ Comments/      ✅ Type    │

```│     matching           Attributes        queries │

│                                       ✅ Send/   │

Supported endpoints:│                                          Sync   │

- OpenAI: `https://api.openai.com/v1/chat/completions`└─────────────────────────────────────────────────┘

- Anthropic: `https://api.anthropic.com/v1/messages````

- Ollama (local): `http://localhost:11434/v1/chat/completions`

**Tier 1 (MIR Heuristics):** Fast pattern matching on Mid-level Intermediate Representation strings for API misuse, dangerous patterns, and common vulnerabilities. Best for clear-cut security violations.

### Standalone Mode (No LLM)

**Tier 2 (Source Analysis):** AST-based inspection using the `syn` crate for patterns requiring source-level context like comments, attributes, and formatting that don't appear in MIR.

For environments without LLM access:

**Tier 3 (Semantic Analysis):** Deep semantic analysis via rustc HIR integration for type-aware rules. Currently supports type size queries (100% accuracy) and Send/Sync trait detection. See `docs/tier3-hir-architecture.md`.

```bash

cargo-cola --crate-path . --report security-report.mdResearch prototypes are available in [`mir-extractor/src/prototypes.rs`](mir-extractor/src/prototypes.rs) with documentation in [`docs/research/`](docs/research/).

```

## Inter-Procedural Taint Analysis

This generates a report with heuristic-based triage. Manual review is required to separate true positives from false positives.

Rust-cola includes **inter-procedural taint analysis** that tracks data flow across function boundaries—not just within a single function. This is critical for detecting real-world vulnerabilities where untrusted input flows through helper functions before reaching dangerous sinks.

## Installation

### How It Works

Requires Rust nightly toolchain.

```

```bash┌─────────────────────────────────────────────────────────────────┐

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh│                 Inter-Procedural Taint Flow                     │

rustup toolchain install nightly│                                                                 │

```│   get_user_input()     process_data()        execute_query()   │

│        │                    │                      │            │

Build from source:│        ▼                    ▼                      ▼            │

│   ┌─────────┐          ┌─────────┐           ┌─────────┐       │

```bash│   │ env::var│ ───────► │ helper  │ ────────► │ sqlx::  │       │

git clone https://github.com/Opus-the-penguin/Rust-cola.git│   │ [SOURCE]│  taint   │ fn()    │   taint   │ query() │       │

cd Rust-cola│   └─────────┘  flows   └─────────┘   flows   │ [SINK]  │       │

cargo build --release│                                              └─────────┘       │

```│                                                                 │

│   Detected: SQL injection via 3-function call chain            │

The binary is at `target/release/cargo-cola`.└─────────────────────────────────────────────────────────────────┘

```

## How It Works

**The analysis proceeds in phases:**

Rust-cola compiles target code and analyzes the compiler's internal representations:

1. **Call Graph Construction** — Extract function calls from MIR to build a directed graph of dependencies

- **MIR (Mid-level IR)**: Pattern matching on desugared code after macro expansion and type checking2. **Function Summarization** — Analyze each function bottom-up to create summaries describing how taint flows through parameters and return values

- **HIR (High-level IR)**: Type-aware analysis using the compiler's semantic information3. **Path Finding** — Starting from source functions, explore the call graph to find paths to sink functions

- **Source analysis**: AST inspection for comments and attributes4. **Sanitization Detection** — Identify validation patterns (allowlists, bounds checks, escaping) that break taint flows



The tool requires successful compilation because Rust's macros, generics, and trait resolution are only fully resolved by the compiler. Source-level scanners cannot see inside macros or resolve trait implementations.### Why This Matters



### Detection CapabilitiesConsider this vulnerable pattern that intra-procedural analysis would **miss**:



97 built-in rules covering:```rust

fn get_user_path() -> String {

- Memory safety: `Box::into_raw` leaks, transmute misuse, uninitialized memory    std::env::var("USER_PATH").unwrap()  // Taint source

- Input validation: SQL injection, path traversal, command injection, SSRF}

- Cryptography: weak hashes (MD5, SHA-1), weak ciphers (DES, RC4), hardcoded keys

- Concurrency: mutex guards held across await, blocking operations in async contextsfn process_file() {

- FFI: allocator mismatches, dangling CString pointers    let path = get_user_path();           // Taint flows in

- Code hygiene: commented-out code, crate-wide allow attributes    std::fs::read_to_string(&path);       // Path traversal sink!

}

### Inter-Procedural Analysis```



Tracks taint flow across function boundaries. Detects vulnerabilities where user input passes through helper functions before reaching dangerous sinks.An intra-procedural analyzer only sees:

- `get_user_path()`: Returns a String (no visible taint)

Example detected pattern:- `process_file()`: Uses that String in a filesystem call



```rustIt **cannot** see that the String originates from `env::var`. Rust-cola's inter-procedural analysis detects this because it:

fn get_user_path() -> String {1. Summarizes `get_user_path()` as returning tainted data (`ReturnTaint::FromSource`)

    std::env::var("USER_PATH").unwrap()  // taint source2. Tracks that `process_file()` calls it and uses the result in a sink

}3. Reports the full taint path: `env::var → get_user_path → process_file → fs::read_to_string`



fn process_file() {### Supported Source → Sink Flows

    let path = get_user_path();           // taint flows through

    std::fs::read_to_string(&path);       // path traversal sink| Source Type | Examples |

}|-------------|----------|

```| Environment | `env::var()`, `env::args()` |

| Stdin | `stdin().read_line()`, `stdin().lines()` |

## Command Reference| Files | `fs::read_to_string()` on untrusted paths |

| Network | `TcpStream::read()`, HTTP request bodies |

```bash

cargo-cola --crate-path <PATH> [OPTIONS]| Sink Type | Examples |

```|-----------|----------|

| Command Execution | `Command::new()`, `Command::arg()` |

| Option | Description || Filesystem | `fs::read_to_string()`, `File::create()`, `fs::remove_file()` |

|--------|-------------|| SQL | `sqlx::query()`, `diesel::sql_query()`, format strings with SQL keywords |

| `--crate-path <PATH>` | Path to crate or workspace to analyze || HTTP/SSRF | `reqwest::get()`, `ureq::get()` with user-controlled URLs |

| `--out-dir <PATH>` | Output directory (default: `out`) || Regex | `Regex::new()` with user-controlled patterns |

| `--llm-prompt [PATH]` | Generate LLM prompt file for manual submission |

| `--llm-report <PATH>` | Generate LLM report (calls API if endpoint provided) |### Sanitization Patterns Detected

| `--llm-endpoint <URL>` | LLM API endpoint |

| `--llm-model <NAME>` | Model name (default: `gpt-4`) |Rust-cola recognizes common sanitization patterns that break taint flows:

| `--llm-api-key <KEY>` | API key (or set `RUSTCOLA_LLM_API_KEY`) |

| `--report <PATH>` | Generate standalone report without LLM |- **Path validation:** `path.canonicalize()?.starts_with(base_dir)`

| `--sarif <PATH>` | Write SARIF output for CI integration |- **SQL parameterization:** `.bind()`, `?` placeholders

| `--fail-on-findings` | Exit non-zero if findings present (default: true) |- **Allowlist checks:** `allowed_values.contains(&input)`

| `--rulepack <PATH>` | Load additional rules from YAML file |- **Input parsing:** Integer parsing for numeric-only fields

- **Escaping:** `regex::escape()`, string replacement

## Output Formats

### Current Capabilities

- `findings.json`: Raw findings with rule IDs, locations, and evidence

- `*.sarif`: SARIF format for GitHub code scanning and CI tools| Metric | Value |

- `llm-prompt.md`: Formatted for LLM submission|--------|-------|

- `report.md`: Human-readable standalone report| **Call chain depth** | Unlimited (with cycle detection) |

| **Cross-function detection** | ✅ Full support |

## Custom Rules| **Closure capture tracking** | ✅ Phase 3.5.2 |

| **Path-sensitive (branching)** | ✅ CFG-based analysis |

Extend detection with YAML rulepacks:| **False positive filtering** | ✅ Validation guard detection |



```bashFor implementation details, see [`mir-extractor/src/interprocedural.rs`](mir-extractor/src/interprocedural.rs).

cargo-cola --crate-path . --rulepack custom-rules.yaml

```## Why Rust-cola Requires Compilation



See `examples/rulepacks/example-basic.yaml` for the schema.Unlike traditional static analysis tools that operate purely on source code or abstract syntax trees (ASTs), Rust-cola requires the target code to be **compiled** by the Rust compiler. This is a deliberate design choice that unlocks significantly deeper analysis capabilities.



## Why Compilation Is Required### The Compilation Requirement



Rust-cola requires target code to compile because:When you run Rust-cola, it invokes `cargo rustc` with special flags to extract the compiler's internal representations:



1. **Macros**: Only visible after expansion by rustc- **MIR (Mid-level Intermediate Representation):** A simplified, desugared representation of Rust code after type checking, borrow checking, and monomorphization

2. **Generics**: Concrete types only known after monomorphization- **HIR (High-level Intermediate Representation):** The compiler's typed AST with full semantic information

3. **Traits**: Implementation resolution requires the trait solver

4. **Closures**: Capture semantics only explicit in MIRThis means your code must successfully compile before Rust-cola can analyze it. While this adds a prerequisite, the benefits far outweigh the costs.



Source-level scanners miss these patterns. The compilation requirement enables accurate analysis at the cost of requiring valid code.### Why This Matters for Rust



## DocumentationRust is uniquely challenging for source-level static analysis. Many other languages (JavaScript, Python, Java) can be effectively analyzed at the source/AST level because their semantics are relatively straightforward. Rust, however, has:



- Rule development: `docs/RULE_DEVELOPMENT_GUIDE.md`| Rust Feature | Source/AST Challenge | MIR/HIR Solution |

- Inter-procedural analysis: `docs/phase3-interprocedural-design.md`|--------------|---------------------|------------------|

- HIR integration: `docs/tier3-hir-architecture.md`| **Macros** | Unexpanded, opaque tokens | Fully expanded, analyzable code |

- Rule backlog: `docs/security-rule-backlog.md`| **Generics & Monomorphization** | Abstract type parameters | Concrete instantiated types |

| **Trait resolution** | Unknown impl at call sites | Resolved to specific implementations |

## License| **Deref coercion** | Implicit, invisible in source | Explicit operations in MIR |

| **Borrow checker semantics** | Complex lifetime inference | Already validated, explicit lifetimes |

MIT| **Pattern matching** | Complex match expressions | Desugared to simple control flow |

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
