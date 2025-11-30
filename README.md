# Rust-cola — Static Security Analysis for Rust

Rust-cola is a static application security testing tool for Rust code. It employs a three-tier hybrid analysis approach combining MIR heuristics, source-level inspection, and semantic analysis via rustc HIR integration.

> **Recent Achievement (Nov 2025):** Added RUSTCOLA089 (Insecure YAML Deserialization) detecting billion laughs attacks via serde_yaml. Added RUSTCOLA088 (Server-Side Request Forgery detection) with 100% recall/precision via MIR dataflow + inter-procedural analysis. Added RUSTCOLA087 (SQL injection detection) with 100% recall/precision. Improved RUSTCOLA086 (path traversal detection) to 100% recall with inter-procedural analysis support. Added RUSTCOLA085 (AWS S3 unscoped access), RUSTCOLA084 (TLS verification disabled), RUSTCOLA083-080 for memory safety rules plus MIR dataflow rules (RUSTCOLA075-079) for cleartext logging, log injection, division by untrusted input, MaybeUninit misuse, and regex injection. Total: 85 security rules.

## Features

- **Three-Tier Analysis Architecture:**
  - **Tier 1 (MIR Heuristics):** 83 rules using pattern matching on compiler-generated MIR
  - **Tier 2 (Source Analysis):** 2 rules using AST inspection for comments and attributes  
  - **Tier 3 (Semantic Analysis):** HIR integration for type-aware rules (type sizes, Send/Sync detection)
- **85 Built-in Security Rules** covering:
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
│  (80 rules)         (2 rules)         ✅ Active │
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
