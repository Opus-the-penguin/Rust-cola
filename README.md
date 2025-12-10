# Rust-cola


Static security analyzer for Rust. Compiles source code to access MIR (Mid-level Intermediate Representation) and HIR (High-level Intermediate Representation), which are internal compiler formats that reveal issues difficult to detect by source-level scanners. Integrates with your favorite Code LLM or Code Assistant to filter false positives and suggest fixes.

Rust's compiler uses several intermediate representations (IRs) to analyze and transform code. HIR (High-level Intermediate Representation) is a structured form of the source code after parsing, while MIR (Mid-level Intermediate Representation) is a simplified, control-flow-oriented version used for borrow checking and optimization. These IRs allow Rust-cola to detect issues that are not visible in raw source code. To use Rust-cola, the environment must be able to compile the target Rust codebase, as analysis depends on successful compilation and extraction of these IRs. Note: Rust-cola requires the nightly Rust toolchain (not stable), as only nightly provides the developer tools needed to extract HIR and MIR for analysis.

## Usage

Two methods for LLM analysis:

### Method 1: Manual

Run the scan, paste results into your LLM, copy the response.

```bash
cargo-cola --crate-path /path/to/project --llm-prompt
```

Output: `out/reports/llm-prompt.md`

Paste the contents of out/reports/llm-prompt.md into your LLM (ChatGPT, Claude, Copilot, etc.). The file includes analysis instructions. Save the LLM's response as your report.

### Method 2: Automated


Calls the LLM API directly and writes the report to a file.

**Note:** The OpenAI endpoint and `gpt-4` model below are just examples. You can use any compatible LLM API, including local models.

Example with OpenAI API:
```bash
export RUSTCOLA_LLM_API_KEY=sk-...
cargo-cola --crate-path . --llm-report out/reports/report.md \
  --llm-endpoint https://api.openai.com/v1/chat/completions \
  --llm-model gpt-4
```

Example with local Ollama LLM:
```bash
cargo-cola --crate-path . --llm-report out/reports/report.md \
  --llm-endpoint http://localhost:11434/v1/chat/completions \
  --llm-model llama3
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

98 rules covering:

- Memory safety (transmute, uninitialized memory, Box leaks, dangling pointer escapes)
- Input validation (SQL injection, path traversal, command injection, SSRF)
- Cryptography (weak hashes, weak ciphers, hardcoded keys)
- Concurrency (mutex across await, blocking in async)
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
| `--crate-path <PATH>` | Target crate or workspace |
| `--llm-prompt [PATH]` | Generate prompt file for manual LLM submission |
| `--llm-report <PATH>` | Generate report (calls API if endpoint provided) |
| `--llm-endpoint <URL>` | LLM API endpoint |
| `--llm-model <NAME>` | Model name (must be specified; e.g., gpt-4, llama3, etc.) |
| `--report <PATH>` | Standalone report without LLM |
| `--sarif <PATH>` | SARIF output for CI |
| `--rulepack <PATH>` | Additional rules from YAML |

## Documentation

- `docs/RULE_DEVELOPMENT_GUIDE.md` - Writing rules
- `docs/phase3-interprocedural-design.md` - Taint analysis
- `docs/security-rule-backlog.md` - Planned rules

## License

MIT
