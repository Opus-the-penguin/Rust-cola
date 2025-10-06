# Rust-cola — OSS SAST for Rust (prototype)

Rust-cola is an experimental static analysis engine that focuses on deep Rust semantics (MIR, async lowering, FFI boundaries) rather than shallow AST matching. The current prototype can:

- Extract MIR for a crate/workspace and emit a structured JSON model.
- Run built-in security rules that flag raw-pointer escapes (`Box::into_raw`), `std::mem::transmute`, unsafe blocks/functions, insecure hashing (MD5/SHA-1), untrusted environment reads, risky `std::process::Command` spawning, `Vec::set_len`, `MaybeUninit::assume_init`, deprecated `mem::uninitialized`/`mem::zeroed`, literal `http://` URLs, TLS bypasses (`danger_accept_invalid_certs`, OpenSSL `VerifyNone`), and hard-coded home directory paths.
- Emit human-readable findings plus SARIF output suitable for CI integration.

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

Curious what’s coming next? The living backlog in [`docs/security-rule-backlog.md`](docs/security-rule-backlog.md) tracks over 70 candidate security rules sourced from Semgrep, GitHub CodeQL, SonarSource, and Trail of Bits’ Dylint packs, along with feasibility notes. Contributions welcome!

## Example commands

- Run the extractor CLI directly (same engine underpinning `cargo cola`):

	```powershell
	cargo run -p mir-extractor -- --crate-path examples/simple --out-dir out/mir --sarif out/mir/cola.sarif
	```

- Analyze another crate and fail the build on findings:

	```powershell
	cargo run -p cargo-cola -- --crate-path path\to\crate --out-dir out/my-crate
	```

- Analyze but continue the pipeline (useful in CI when you still want SARIF uploaded):

	```powershell
	cargo run -p cargo-cola -- --crate-path path\to\crate --out-dir out/my-crate --fail-on-findings=false
	```

## Roadmap (abridged)

- Replace the command-line rustc invocation with an in-process `rustc_interface` harness for richer MIR/HIR data.
- Expand the rule engine (taint tracking, FFI boundary modelling, async misuse).
- Pluggable rulepacks (native + WASM) and org-specific configuration.
- First-class SARIF publishing (GitHub Action) and incremental caching for CI-grade latency.

## GitHub Action (experimental)

A starter workflow is available in `.github/workflows/cola-ci.yml`. It runs `cargo cola` on every push/PR, writes SARIF to `target/cola/cola.sarif`, and uploads the results to GitHub’s code scanning dashboard. The workflow keeps the job green by passing `--fail-on-findings=false`, letting GitHub surface findings directly.
