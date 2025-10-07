# Rust-cola — OSS SAST for Rust (prototype)

Rust-cola is an experimental static analysis engine that focuses on deep Rust semantics and learns from the same mid-level IR the compiler uses. Instead of guessing from surface syntax, it follows lifetimes, async state machines, and cross-crate FFI edges the way rustc actually lowers them—exposing subtle issues that simpler linters never see. The current prototype can:

- Extract MIR for a crate/workspace and emit a structured JSON model.
- Run built-in security rules that catch:
	- Memory-safety pitfalls such as leaking `Box` pointers, unchecked `transmute`, risky `Vec::set_len`, and premature `MaybeUninit::assume_init`, plus calls to long-deprecated zero-initialization helpers.
	- Dangerous execution patterns, including unsafe blocks/functions, reading untrusted environment variables, and spawning external commands that can be influenced by user input.
	- Weak crypto and network hygiene issues like MD5/SHA-1 usage, literal `http://` URLs, and toggles that bypass TLS certificate validation.
	- Concurrency and FFI hazards, from unsafe `Send`/`Sync` impls to allocator mismatches across foreign-function boundaries.
	- Supply-chain red flags, highlighting hard-coded home directory paths, yanked or unsound dependencies, and binaries missing `cargo auditable` metadata.
- Emit human-readable findings plus SARIF output suitable for CI integration.

In addition to the shipped rules, we maintain MIR-based research prototypes for RustSec-inspired findings (Content-Length DoS guards, protocol length truncation casts, Tokio broadcast payload unsoundness) in [`mir-extractor/src/prototypes.rs`](mir-extractor/src/prototypes.rs) with write-ups under [`docs/research/`](docs/research/).

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

Run the prototype analysis against the bundled example crate:

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
3. Run the prototype rules, writing `out/cola/findings.json` and a SARIF report (default `out/cola/cola.sarif`).
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

Each `--rulepack` flag loads another YAML file. Rulepacks support simple string matching on MIR function signatures and bodies—perfect for organization-specific hygiene checks (see the comments inside the example file for the schema).

> **Experimental WASM stubs**
>
> We’re laying the foundation for WASM-based rule plugins. You can point the CLI at `.wasm` modules via `--wasm-rule path/to/rule.wasm` today; the engine records metadata for those modules, ready for future execution wiring.

### Security rule backlog

Curious what’s coming next? The living backlog in [`docs/security-rule-backlog.md`](docs/security-rule-backlog.md) tracks 100+ candidate security rules sourced from Semgrep, GitHub CodeQL, SonarSource, Trail of Bits’ Dylint packs, Checkmarx, Snyk, and RustSec advisories, along with feasibility notes and prototype links. Contributions welcome!

## Example commands

> Choose the snippet that matches your shell. Forward slashes in paths work on both Windows and Unix-like systems; feel free to use backslashes in PowerShell if you prefer.

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

## Roadmap (abridged)

- Replace the command-line rustc invocation with an in-process `rustc_interface` harness for richer MIR/HIR data.
- Graduate prototype detectors (Content-Length guards, length truncation casts, Tokio broadcast payloads) into first-class rules with SARIF metadata.
- Expand MIR dataflow (range guards, trusted sources/sinks) and add async misuse & FFI boundary modelling.
- Pluggable rulepacks (native + WASM) and organization-specific configuration.
- First-class SARIF publishing (GitHub Action) with incremental caching for CI-grade latency.

## GitHub Action (experimental)

A starter workflow is available in `.github/workflows/cola-ci.yml`. It runs `cargo cola` on every push/PR, writes SARIF to `target/cola/cola.sarif`, and uploads the results to GitHub’s code scanning dashboard. The workflow keeps the job green by passing `--fail-on-findings=false`, letting GitHub surface findings directly.
