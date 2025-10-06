# Rust-cola — OSS SAST for Rust (prototype)

Rust-cola is an experimental static analysis engine that focuses on deep Rust semantics (MIR, async lowering, FFI boundaries) rather than shallow AST matching. The current prototype can:

- Extract MIR for a crate/workspace and emit a structured JSON model.
- Run built-in security rules that flag raw-pointer escapes (`Box::into_raw`), `std::mem::transmute`, unsafe blocks/functions, insecure hashing (MD5/SHA-1), untrusted environment reads, risky `std::process::Command` spawning, `Vec::set_len`, `MaybeUninit::assume_init`, deprecated `mem::uninitialized`/`mem::zeroed`, literal `http://` URLs, TLS bypasses (`danger_accept_invalid_certs`, OpenSSL `VerifyNone`), hard-coded home directory paths, unsafe Send/Sync impls, FFI allocator mismatches, and yanked/unsound dependencies.
- Emit human-readable findings plus SARIF output suitable for CI integration.

In addition to the shipped rules, we maintain MIR-based research prototypes for RustSec-inspired findings (Content-Length DoS guards, protocol length truncation casts, Tokio broadcast payload unsoundness) in [`mir-extractor/src/prototypes.rs`](mir-extractor/src/prototypes.rs) with write-ups under [`docs/research/`](docs/research/).

## Getting started

> **Prerequisites**
> - Rust (nightly toolchain) via `rustup`.
> - On Windows, Visual Studio Build Tools with the C++ workload (for `link.exe`).

Run the prototype analysis against the bundled example crate:

```powershell
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
Get-Content out/cola/mir.json | Select-Object -First 40
```

### Using rulepacks

You can extend the analysis with YAML rulepacks. A starter pack lives at `examples/rulepacks/example-basic.yaml`.

```powershell
cargo run -p cargo-cola -- --crate-path examples/simple --out-dir out/cola --rulepack examples/rulepacks/example-basic.yaml --fail-on-findings=false
```

Each `--rulepack` flag loads another YAML file. Rulepacks support simple string matching on MIR function signatures and bodies—perfect for organization-specific hygiene checks (see the comments inside the example file for the schema).

> **Experimental WASM stubs**
>
> We’re laying the foundation for WASM-based rule plugins. You can point the CLI at `.wasm` modules via `--wasm-rule path/to/rule.wasm` today; the engine records metadata for those modules, ready for future execution wiring.

### Security rule backlog

Curious what’s coming next? The living backlog in [`docs/security-rule-backlog.md`](docs/security-rule-backlog.md) tracks 100+ candidate security rules sourced from Semgrep, GitHub CodeQL, SonarSource, Trail of Bits’ Dylint packs, Checkmarx, Snyk, and RustSec advisories, along with feasibility notes and prototype links. Contributions welcome!

## Example commands

- **Scan the current project** (writes MIR, findings, and SARIF to `out/my-project`):

	```powershell
	cargo run -p cargo-cola -- --crate-path . --out-dir out/my-project --sarif out/my-project/cola.sarif --fail-on-findings=true
	```

- **Scan another workspace without failing the build**:

	```powershell
	cargo run -p cargo-cola -- --crate-path path\to\crate --out-dir out/full-scan --fail-on-findings=false
	```

- **Run the extractor CLI directly** (same engine underpinning `cargo cola`):

	```powershell
	cargo run -p mir-extractor -- --crate-path examples/simple --out-dir out/mir --sarif out/mir/cola.sarif
	```

- **Extend the rule set with a YAML rulepack**:

	```powershell
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
