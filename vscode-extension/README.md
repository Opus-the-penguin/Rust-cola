# Rust-cola VS Code Extension

A VS Code extension for running Rust-cola security scans with GitHub Copilot integration.

## Features

### Commands

- **Rust-cola: Scan Current Workspace** - Run a security scan on the current Rust project
- **Rust-cola: Scan and Generate Security Report** - Scan and generate an LLM-ready report

### Copilot Chat Integration

Use `@rustcola` in Copilot Chat to interact with the security analyzer:

```
@rustcola /scan
```
Runs a security scan on your workspace and provides AI-analyzed results.

```
@rustcola /analyze
```
Analyzes existing scan results and generates a security report.

```
@rustcola /explain RUSTCOLA087
```
Explains a specific security rule or finding.

## Requirements

- VS Code 1.93.0 or later
- GitHub Copilot extension (for chat features)
- `cargo-cola` binary installed and in PATH (or configured via settings)

## Installation

### From Source

```bash
cd vscode-extension
npm install
npm run compile
```

Then press F5 in VS Code to launch the extension in a development host.

### Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| `rustcola.binaryPath` | Path to cargo-cola binary | `cargo-cola` |
| `rustcola.outputDirectory` | Output directory for scan results | `out/cola` |

## Usage

### Basic Scan

1. Open a Rust project in VS Code
2. Run the command "Rust-cola: Scan Current Workspace"
3. View findings in the output

### Using Copilot Chat

1. Open a Rust project in VS Code
2. Open GitHub Copilot Chat
3. Type `@rustcola /scan`
4. Copilot will run the scan and analyze the findings

### Example Output

```
@rustcola /scan

Starting Rust-cola security scan...

Scan complete. Found 42 findings.

Analyzing findings...

## Executive Summary

Total findings: 42
- True Positives (actionable): 8
- Probable False Positives: 28
- Informational: 6

## Critical Issues

### 1. RUSTCOLA021 - Unbounded Content-Length Allocation
- **Location:** src/server.rs:123
- **Impact:** Denial of Service
- **Exploitability:** HIGH - Remote, unauthenticated
...
```

## Development

### Building

```bash
npm install
npm run compile
```

### Testing

```bash
npm test
```

### Publishing

```bash
vsce package
vsce publish
```

## License

MIT
