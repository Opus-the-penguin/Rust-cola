# Rust-cola

Static security analyzer for Rust. Compiles source code to extract MIR (Mid-level Intermediate Representation) and HIR (High-level Intermediate Representation)—internal compiler formats that reveal issues invisible to source-level scanners.

**Note:** The environment running cargo-cola must be able to compile the target code. This is required to extract the intermediate representations for deep analysis.

Requires the nightly Rust toolchain.

## Usage

### Recommended: LLM-assisted analysis

Rust-cola is designed to work with an LLM for best results. The LLM filters false positives, rates severity, assesses exploitability, and suggests remediations—turning raw findings into an actionable security report.

**Manual Workflow (Recommended):**

1. Run the scan on your target project:
   ```bash
   cargo-cola --crate-path /path/to/project --output-for-llm out/cola/security-analysis.md
   ```

2. Open the generated file `out/cola/security-analysis.md`.

3. Copy the contents into your AI coding assistant (Claude, ChatGPT, Copilot) with a prompt like:
   > "Analyze these security findings and generate a prioritized report."

4. The LLM will classify findings, dismiss false positives, and provide remediation steps.

**Automated:** Call an LLM API directly:

```bash
export RUSTCOLA_LLM_API_KEY=sk-...
cargo-cola --crate-path . --llm-report out/cola/report.md \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4
```

Works with any OpenAI-compatible API (Anthropic, Ollama, local models via Ollama, etc.).

### Standalone (no LLM)

```bash
cargo-cola --crate-path . --report out/cola/report.md
```

Generates a report with heuristic triage. Useful for CI integration or when LLM access is unavailable, but requires manual review of findings.

## Installation

```bash
rustup toolchain install nightly
git clone https://github.com/Opus-the-penguin/Rust-cola.git
cd Rust-cola
cargo build --release
```

Binary: `target/release/cargo-cola`

## Documentation

- [User Guide](docs/USER_GUIDE.md): Detailed instructions on features like False Positive Suppression.
- [Rules Master Plan](docs/RULES_MASTER_PLAN.md): Current status, roadmap, and backlog of security rules.
- [Rule Development Guide](docs/RULE_DEVELOPMENT_GUIDE.md): How to write new security rules.

## Output Artifacts

By default, all artifacts are written to `out/cola/`:

| File | Description |
|------|-------------|
| `manifest.json` | Metadata and paths for all generated artifacts |
| `mir.json` | MIR extraction (functions, blocks, statements) |
| `ast.json` | AST extraction (modules, functions, structs) |
| `hir.json` | HIR extraction (requires `--features hir-driver`) |
| `findings.json` | Raw findings from all rules |
| `cola.sarif` | SARIF 2.1.0 for CI integration |
| `llm-prompt.md` | Prompt file for manual LLM submission |
| `report.md` | Standalone report (when `--report` is used) |

Use `--no-ast`, `--no-hir`, or `--no-llm-prompt` to suppress specific outputs.

## What It Detects

102 rules covering:

- Memory safety (transmute, uninitialized memory, Box leaks, dangling pointer escapes)
- Input validation (SQL injection, path traversal, command injection, SSRF, unsafe JSON/TOML/binary deserialization, template injection, regex catastrophic backtracking)
- Cryptography (weak hashes, weak ciphers, hardcoded keys)
- Concurrency (mutex across await, blocking in async, span guards held across await, non-Send futures crossing executor threads, unsafe data flow in async state machines)
- FFI (allocator mismatch, CString pointer misuse)

Includes inter-procedural taint analysis: tracks data flow across function calls.

## Why It Requires Compilation

Rust-cola analyzes MIR (Mid-level IR) and HIR (High-level IR) from the compiler. This requires the target code to compile, but enables much deeper and more accurate security analysis than source-level or AST-based tools:

- **Expanded macros:** Many vulnerabilities are hidden in macro-generated code. Only MIR/HIR show the fully expanded program.
- **Resolved generics and trait implementations:** Security issues in generic code or trait-based dispatch are visible only after type resolution.
- **Accurate type and lifetime information:** MIR/HIR expose the real types, lifetimes, and borrow checking, allowing detection of memory safety issues, use-after-free, and data races.
- **Control/data flow and interprocedural analysis:** MIR enables tracking of tainted data across function boundaries, async/await, and complex control flow, supporting detection of injection, deserialization, and concurrency bugs.
- **Detection of unsafe code and FFI issues:** MIR reveals low-level operations, pointer manipulation, and FFI boundaries that are invisible in the AST.

Source-level and AST-based scanners can only see the surface structure of the code. They miss vulnerabilities that depend on macro expansion, type inference, trait resolution, or complex data/control flow. By requiring compilation and analyzing MIR/HIR, Rust-cola can detect a broader and more precise set of security issues, including those unique to Rust's type system and memory model.

## Options

| Flag | Description |
|------|-------------|
| `--crate-path <PATH>` | Target crate or workspace (default: `.`) |
| `--out-dir <PATH>` | Output directory (default: `out/cola`) |
| `--output-for-llm <PATH>` | Path for LLM prompt file (alias for `--llm-prompt`) |
| `--llm-prompt <PATH>` | Path for LLM prompt file (default: `out/cola/llm-prompt.md`) |
| `--no-llm-prompt` | Suppress LLM prompt generation |
| `--llm-report <PATH>` | Generate report via LLM API |
| `--llm-endpoint <URL>` | LLM API endpoint |
| `--llm-model <NAME>` | Model name (e.g., gpt-4, llama3) |
| `--report <PATH>` | Generate standalone heuristic report |
| `--no-report` | Suppress standalone report |
| `--with-audit` | Run cargo-audit to check dependencies |
| `--no-ast` | Suppress AST output |
| `--no-hir` | Suppress HIR output (hir-driver feature) |
| `--sarif <PATH>` | Custom SARIF output path |
| `--rulepack <PATH>` | Additional rules from YAML |

## Dependency Auditing

Rust-cola can integrate with [cargo-audit](https://rustsec.org/) to check your dependencies for known vulnerabilities:

```bash
# Install cargo-audit (one-time)
cargo install cargo-audit

# Run rust-cola with dependency audit
cargo-cola --crate-path . --report --with-audit
```

When `--with-audit` is enabled:
- cargo-audit scans `Cargo.lock` against the RustSec Advisory Database
- Known CVEs and security advisories are included in the report
- Findings from both static analysis and dependency audit are merged

This provides comprehensive security coverage:
- **cargo-audit**: Are my dependencies safe?
- **rust-cola**: Is my own code safe?

## Documentation

- `docs/RULE_DEVELOPMENT_GUIDE.md` - Writing rules
- `docs/RULES_MASTER_PLAN.md` - Rules status and roadmap
- `docs/design/phase3-interprocedural-design.md` - Taint analysis

## License

MIT
