# Rust-cola

Static security analyzer for Rust. Compiles source code to access MIR and HIR, enabling detection of issues invisible to source-level scanners (expanded macros, resolved generics, trait implementations). Optionally uses an LLM to filter false positives and suggest fixes.

## Usage

Two methods for LLM analysis:

### Method 1: Manual

Run the scan, paste results into your LLM, copy the response.

```bash
cargo-cola --crate-path /path/to/project --llm-prompt
```

Output: `out/reports/llm-prompt.md`

Paste the contents into your LLM (ChatGPT, Claude, Copilot, etc.). The file includes analysis instructions. Save the LLM's response as your report.

### Method 2: Automated

Calls the LLM API directly and writes the report to a file.

```bash
export RUSTCOLA_LLM_API_KEY=sk-...
cargo-cola --crate-path . --llm-report out/reports/report.md \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4
```

Output: `out/reports/report.md`

### Standalone (no LLM)

```bash
cargo-cola --crate-path . --report report.md
```

Generates a report with heuristic triage. Requires manual review.

## Installation

```bash
rustup toolchain install nightly
git clone https://github.com/Opus-the-penguin/Rust-cola.git
cd Rust-cola
cargo build --release
```

Binary: `target/release/cargo-cola`

## What It Detects

97 rules covering:

- Memory safety (transmute, uninitialized memory, Box leaks)
- Input validation (SQL injection, path traversal, command injection, SSRF)
- Cryptography (weak hashes, weak ciphers, hardcoded keys)
- Concurrency (mutex across await, blocking in async)
- FFI (allocator mismatch, CString pointer misuse)

Includes inter-procedural taint analysis: tracks data flow across function calls.

## Why It Requires Compilation

Rust-cola analyzes MIR (Mid-level IR) and HIR (High-level IR) from the compiler. This requires the target code to compile, but provides:

- Visibility into expanded macros
- Resolved generics and trait implementations
- Accurate type information

Source-level scanners cannot see these.

## Options

| Flag | Description |
|------|-------------|
| `--crate-path <PATH>` | Target crate or workspace |
| `--llm-prompt [PATH]` | Generate prompt file for manual LLM submission |
| `--llm-report <PATH>` | Generate report (calls API if endpoint provided) |
| `--llm-endpoint <URL>` | LLM API endpoint |
| `--llm-model <NAME>` | Model name (default: gpt-4) |
| `--report <PATH>` | Standalone report without LLM |
| `--sarif <PATH>` | SARIF output for CI |
| `--rulepack <PATH>` | Additional rules from YAML |

## Documentation

- `docs/RULE_DEVELOPMENT_GUIDE.md` - Writing rules
- `docs/phase3-interprocedural-design.md` - Taint analysis
- `docs/security-rule-backlog.md` - Planned rules

## License

MIT
