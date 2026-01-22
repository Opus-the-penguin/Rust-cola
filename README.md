# Rust-cola (Proof of Concept)

Experimental security scanner for Rust. Works by compiling your code and analyzing the compiler's intermediate representation (MIR), which can reveal issues that source-level tools might miss.

**Note:** The environment running cargo-cola must be able to compile the target code. This is required to extract MIR.

Requires the nightly Rust toolchain.

## Usage

### Recommended: LLM-assisted analysis

Rust-cola works best with an LLM. The LLM helps filter false positives, rate severity, and suggest fixes.

**Manual Workflow (Recommended):**

1. Run the scan on your target project:
   ```bash
   cargo-cola --crate-path /path/to/project
   ```

2. Open the generated file `out/cola/llm-prompt.md`.

3. Copy the contents into your AI coding assistant (Claude, ChatGPT, Copilot).

4. Save the LLM's response as `security-report.md` in the same directory (the prompt includes save instructions).

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
cargo-cola --crate-path . --report out/cola/raw-report.md
```

Generates a raw report with heuristic triage. Useful for CI integration or when LLM access is unavailable, but requires manual review of findings.

## Installation

```bash
rustup toolchain install nightly
git clone https://github.com/Opus-the-penguin/Rust-cola.git
cd Rust-cola
cargo build --release
```

Binary: `target/release/cargo-cola`

> **Note:** The `examples/` directory contains intentionally vulnerable code patterns for testing Rust-COLA's detection capabilities. These crates may have unmaintained or vulnerable dependencies by design and are not part of the distributed tool.

## Output Artifacts

By default, all artifacts are written to `out/cola/` **relative to your current working directory** (not the target crate):

| File | Description |
|------|-------------|
| `manifest.json` | Metadata and paths for all generated artifacts |
| `mir.json` | MIR extraction (functions, blocks, statements) |
| `ast.json` | AST extraction (modules, functions, structs) |
| `hir.json` | HIR extraction for researchers (optional, requires `--features hir-driver`) |
| `raw-findings.json` | Raw findings from all rules (pre-LLM validation) |
| `raw-findings.sarif` | Raw SARIF 2.1.0 output (pre-LLM validation) |
| `raw-report.md` | Standalone report without LLM validation |
| `llm-prompt.md` | Prompt file for manual LLM submission |
| `report.md` | LLM-validated report (when `--llm-report` is used) |

**Raw vs Validated:** Files prefixed with `raw-` contain all findings before LLM analysis. Use these for deep investigation or when LLM access is unavailable. The LLM-validated outputs contain only confirmed findings with severity scores and remediation guidance.

Use `--no-ast` or `--no-llm-prompt` to suppress specific outputs.

If an output file already exists, a timestamped version is created to avoid overwriting.

## Rules

126 rules grouped by vulnerability category:

| Category | Rules | Examples |
|----------|-------|----------|
| **Memory Safety** | 24 | Transmute misuse, uninitialized memory, Box leaks, raw pointer escapes, slice safety, self-referential structs, returned refs to locals, UnsafeCell aliasing, lazy init poison, use-after-free |
| **Concurrency** | 21 | Mutex across await, blocking in async, Send/Sync violations, executor starvation, closure escaping refs, cancellation safety, async drop correctness, panic in Drop, task panic propagation |
| **Input Validation** | 15 | Env vars, stdin, unicode, deserialization, division by untrusted, timestamp overflow, binary deser, regex DoS, integer overflow, allocation size |
| **FFI** | 11 | Allocator mismatch, CString pointer misuse, packed fields, panic in FFI, WASM linear memory OOB, WASM host trust, WASM capability leaks |
| **Web Security** | 14 | TLS validation, CORS, cookies, passwords in logs, Content-Length, template injection, unsafe Send across async |
| **Injection** | 10 | SQL injection, command injection, path traversal, SSRF, log injection |
| **Resource Management** | 10 | File permissions, open options, infinite iterators, unbounded allocations |
| **Code Quality** | 9 | Dead stores, assertions, crate-wide allow, RefCell, commented code, unwrap in hot paths |
| **Cryptography** | 8 | Weak hashes (MD5/SHA1), weak ciphers, hardcoded keys, timing attacks, PRNG bias |
| **Supply Chain** | 4 | RUSTSEC advisories, yanked crates, auditable dependencies, proc-macro side effects |

See the **[User Guide](docs/USER_GUIDE.md)** for theory of operation, LLM integration, CI/CD, configuration, and troubleshooting.

See the [Rule Development Guide](docs/RULE_DEVELOPMENT_GUIDE.md) for custom rules, YAML rulepacks, and suppression.

## Why It Requires Compilation

Rust-cola analyzes MIR (Mid-level IR) from the compiler. This requires the target code to compile, but lets it see things source-level tools can't:

- **Expanded macros** — vulnerabilities hidden in macro-generated code become visible
- **Resolved types and generics** — issues in generic code or trait dispatch are caught after type resolution
- **Data flow across functions** — tracks tainted data through call chains, async/await, and complex control flow

## Interprocedural Analysis

Five rules track data flow across function calls to detect injection vulnerabilities:

| Rule | ID |
|------|-----|
| Path Traversal | RUSTCOLA086 |
| SQL Injection | RUSTCOLA087 |
| SSRF | RUSTCOLA088 |
| YAML Injection | RUSTCOLA089 |
| Command Injection | RUSTCOLA098 |

### Depth Limits and Configuration

To prevent memory exhaustion on large codebases, inter-procedural analysis has built-in limits. These can be configured via a YAML configuration file:

```bash
cargo-cola --config cargo-cola.yaml --crate-path .
```

**Example `cargo-cola.yaml`:**

```yaml
analysis:
  max_path_depth: 8          # Maximum call chain depth (default: 8)
  max_flows_per_source: 200  # Flows per source function (default: 200)
  max_visited: 1000          # Functions visited per exploration (default: 1000)
  max_total_flows: 5000      # Total inter-procedural flows (default: 5000)
  max_functions_for_ipa: 10000  # Skip IPA for crates larger than this (default: 10000)
```

See `examples/cargo-cola.yaml` for a complete example.

**Note:** These limits may cause missed findings in codebases with very deep call chains. For most real-world vulnerabilities, the defaults are sufficient.

## Options

| Flag | Description |
|------|-------------|
| `--crate-path <PATH>` | Target crate or workspace (default: `.`) |
| `--out-dir <PATH>` | Output directory (default: `out/cola`) |
| `--config <PATH>` | Path to configuration file (YAML format) |
| `--fail-on-findings <bool>` | Exit with code 1 when findings are produced (default: `true`) |
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
| `--sarif <PATH>` | Custom SARIF output path |
| `--rulepack <PATH>` | Additional rules from YAML |

## Performance

Benchmarks on Apple M1 (8-core, 16GB RAM):

| Crate | LOC | Findings | Time | Memory |
|-------|-----|----------|------|--------|
| ci-test-crate | 39 | 1 | 0.2s | <50MB |
| small-crate | ~500 | 8 | 1.6s | ~100MB |
| medium-crate | ~5,000 | 100+ | 18s | ~500MB |

**Typical analysis rate:** ~300 LOC/second including full interprocedural analysis.

Memory usage scales with crate size. Large workspaces (10K+ functions) may require 1-2GB RAM. Analysis limits are configurable via `cargo-cola.yaml` to control memory usage on constrained systems.

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

## Etymology

**Rust** — The programming language.

**cola** — Two meanings:

1. **Acronym:** **CO**de **L**exical **A**nalyzer

2. **The beverage:** Cola drinks (Coca-Cola, Pepsi, etc.) contain phosphoric acid, which chemically converts iron oxide (rust) into a water-soluble compound that's easy to scrub away. It's a classic life hack for cleaning rusty tools and bolts.

Hence **Rust-cola**: the security analyzer that cleans Rust code of security vulnerabilities.

## Why Rust-cola Was Created

Rust-cola was created to add to the ecosystem of Rust safety and security tools. It is not a complete product. It is still in its inception stage, but it is functional as a static rules engine that discovers vulnerable patterns in Rust code.

There are various depths to which vulnerability detection logic can be iterated upon to improve precision. One way to classify this is the following table from the [User Guide](docs/USER_GUIDE.md#detection-levels):

| Level | Method | Precision | Example |
|-------|--------|-----------|---------|
| **Heuristic** | Pattern matching on MIR text | Good | `transmute`, `into_raw` |
| **Structural** | MIR statement/terminator analysis | Better | Mutex guard across await |
| **Dataflow** | Intra-function value tracking | High | Uninitialized memory use |
| **Interprocedural** | Cross-function taint tracking | Highest | SQL injection chains |

Current distribution of the 126 rules:

| Level | Rules | Percentage |
|-------|-------|------------|
| Heuristic | 63 | 50% |
| Structural | 26 | 21% |
| Dataflow | 32 | 25% |
| Interprocedural | 5 | 4% |

Most rules are at the **Heuristic** level. They will find things, but many will be false positives because Rust-cola does not yet understand enough context. An LLM is employed with a context-enriched prompt to help with triage. It is not perfect, but it is useful.

### Paths for Improvement

**Enhancing rules:** Infrastructure exists for more sophisticated analysis (call graphs, taint propagation, dataflow frameworks) that heuristic rules could leverage. Moving a rule from heuristic to structural or dataflow would reduce false positives at the source. See the [Rule Development Guide](docs/RULE_DEVELOPMENT_GUIDE.md) for details.

**Enriching the LLM prompt:** The quality of the LLM report depends on the context provided. The prompt template (`llm-prompt.md`) can be customized to include domain-specific knowledge about your codebase: threat models, trusted boundaries, deployment context. The more context, the better the report.

### Acknowledgments

This project was written out of respect for the Rust community.

This project would not exist without AI tools: Claude (Opus and Sonnet), ChatGPT, and GitHub Copilot. The human involved is a recovering C++ programmer with a systems engineering background. Enough to guide the architecture and intent, but not enough to build this alone.

There is much that can be iterated upon. I hope it is useful, or at least inspirational. Please [file issues](https://github.com/Opus-the-penguin/Rust-cola/issues).

## License

MIT

