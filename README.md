# Rust-cola

Static security analyzer for Rust. Compiles source code to access MIR and HIR, enabling detection of issues invisible to source-level scanners (expanded macros, resolved generics, trait implementations). Optionally uses an LLM to filter false positives and suggest fixes.

## Usage

Run the scan, then submit results to an LLM for analysis.

**Step 1: Scan**

```bash
cargo-cola --crate-path /path/to/project --llm-prompt
```

Output: `out/reports/llm-prompt.md`

**Step 2: Analyze**

Paste the contents of `out/reports/llm-prompt.md` into your LLM (ChatGPT, Claude, Copilot, etc.). The file includes analysis instructions.

### Automated API

For CI or scripts, call the LLM API directly:

```bash
export RUSTCOLA_LLM_API_KEY=sk-...
cargo-cola --crate-path . --llm-report report.md \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4
```

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
