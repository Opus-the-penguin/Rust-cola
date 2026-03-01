# mir-extractor

A Rust library for extracting MIR (Mid-level Intermediate Representation) from Rust crates and running security analysis rules against the extracted code.

This is the core analysis engine used by [cargo-cola](https://crates.io/crates/cargo-cola).

## Requirements

- Nightly Rust toolchain (MIR extraction uses unstable compiler APIs)
- Target crate must compile successfully

## Installation

```toml
[dependencies]
mir-extractor = "1.0"
```

## Usage

```rust
use mir_extractor::{extract, analyze};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Extract MIR from a crate
    let package = extract(Path::new("path/to/crate"))?;

    // Run security rules against the extracted MIR
    let result = analyze(&package);

    // Process findings
    for finding in &result.findings {
        println!("{}: {} ({})", 
            finding.rule_id, 
            finding.message, 
            finding.severity.label()
        );
    }

    Ok(())
}
```

## Features

### Default

The default configuration provides MIR extraction and analysis without compiler integration.

### `hir-driver`

Enables HIR (High-level Intermediate Representation) capture by linking against rustc internals. This provides richer type information for analysis but requires the exact nightly toolchain version specified in `rust-toolchain.toml`.

```toml
[dependencies]
mir-extractor = { version = "1.0", features = ["hir-driver"] }
```

When enabled, this feature also builds two internal binaries (`hir-driver-wrapper` and `hir-spike`) used for HIR capture. These are not intended for direct use.

## API Overview

- `extract(path)` - Extract MIR from a crate at the given path
- `analyze(package)` - Run built-in security rules against a MIR package
- `analyze_with_engine(engine, package)` - Run custom rules
- `RuleEngine` - Configure and run security rules
- `Finding` - A security finding with severity, location, and message
- `MirPackage` - Extracted MIR data for a crate

## License

MIT
