# Changelog

All notable changes to Rust-COLA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2025-12-12

### Fixed
- **CI/CD Stability**: Removed excessive debug logging that was causing CI build failures.
- **Code Cleanup**: Fixed numerous unused code warnings in `mir-extractor` to ensure clean builds.

### Documentation
- **User Guide**: Added `docs/USER_GUIDE.md` with concise instructions on features like False Positive Suppression.

## [0.2.2] - 2025-12-12

### Added
- **False Positive Suppression**: Added support for `// rust-cola:ignore RuleID` comments to suppress findings. This works by matching the finding's location with the ignore comment on the same or previous line.
- **MIR Span Extraction**: Improved MIR extraction to include source code spans (`-Zmir-include-spans`), enabling accurate mapping of findings to source lines for suppression and reporting.

### Fixed
- **macOS Dynamic Linking**: Resolved `dyld` library path issues when running with the `hir-driver` feature on macOS.

## [0.2.1] - 2025-12-12

### Added
- **Mutable Reference Propagation**: Implemented Phase 3.5.2. The analyzer now correctly tracks taint when a function modifies its arguments (e.g., `dest.push_str(tainted_src)`).
- **ParamToParam Propagation**: Added support for generating and handling `ParamToParam` rules in function summaries, enabling detection of taint flow between function parameters.
- **Standard Library Heuristics**: Added explicit taint propagation models for `String::push_str`, `Vec::push`, and `Vec::append` to handle these common patterns without requiring MIR for std.

### Changed
- **Analysis Engine**: Updated `PathAnalysisResult` to track `final_taint` states of variables at the end of function execution.

## [0.2.0] - 2025-12-12

### Added
- **Async Taint Propagation**: Major improvement to taint analysis (Phase 3.6). Now correctly tracks data flow through `async` functions and generators by resolving state machine aliases. This enables accurate security analysis for async-heavy frameworks like Tokio, Axum, and Actix.
- **ADV009**: Integer Overflow Rule - Detects untrusted input flowing to arithmetic operations without overflow protection.

### Changed
- **Analysis Engine**: Enhanced `path_sensitive.rs` with alias tracking for MIR generator lowering.

## [0.1.1] - 2025-12-12

### Added
- **Inter-procedural Taint Propagation**: Implemented Phase 3.3, enabling taint tracking across function boundaries using function summaries.
- **ADV008**: Uncontrolled Allocation Size Rule (Advanced Dataflow) - Detects untrusted input flowing to allocation APIs without bounds checking.
- **cargo-audit Integration**: New `--with-audit` flag to include dependency vulnerability scanning in reports.
- **LLM Workflow Improvements**: Added `--output-for-llm` alias and enhanced LLM prompt with rigorous false negative prevention guidelines.

### Changed
- **Documentation**: Updated README with correct rule count (102 rules), manual LLM workflow instructions, and updated options table.
- **Rule Count**: Corrected rule count to include 93 core rules + 9 advanced rules.

---

## [0.1.0] - 2025-12-08

First versioned release of Rust-cola, an LLM-integrated static application security testing (SAST) tool for Rust.

### Highlights
- **87 security rules** across memory safety, cryptography, injection, concurrency, and FFI
- **Three-tier analysis architecture**: MIR heuristics (85 rules), source analysis (2 rules), HIR semantic analysis
- **Inter-procedural taint analysis** tracking data flow across function boundaries
- **LLM integration** for intelligent false positive filtering and remediation suggestions
- **SARIF output** for CI/CD integration

### Security Rules by Category
- **Memory Safety**: Box::into_raw leaks, transmute misuse, Vec::set_len, MaybeUninit::assume_init, slice::from_raw_parts
- **Cryptography**: MD5/SHA-1/RIPEMD/CRC detection, weak ciphers (DES/RC4), hardcoded keys, predictable randomness
- **Injection**: SQL injection, path traversal, command injection, regex injection, YAML/JSON/TOML deserialization
- **Network**: SSRF detection, disabled TLS verification, HTTP URLs, unscoped AWS S3 access
- **Concurrency**: Unsafe Send/Sync, mutex guards, panic in Drop, unwrap in Poll
- **FFI**: Allocator mismatches, dangling CString pointers, blocking calls in async

### New Rules (December 2025)
- **RUSTCOLA091**: Insecure JSON/TOML deserialization - 100% recall (10/10)
- **RUSTCOLA090**: Unbounded read_to_end - Memory exhaustion via unlimited reads
- **RUSTCOLA089**: YAML deserialization attacks - Billion laughs, deep nesting
- **RUSTCOLA088**: Server-Side Request Forgery (SSRF) - 100% recall (12/12)
- **RUSTCOLA087**: SQL injection - 100% recall (10/10)
- **RUSTCOLA086**: Path traversal - 100% recall (10/10)

### LLM Integration
- `--llm-report` flag for AI-assisted analysis
- Supports OpenAI, Anthropic Claude, and Ollama
- False positive filtering, CVSS estimates, attack scenarios, code fixes
- `--report` for standalone human-readable reports without LLM

### Output Formats
- JSON findings (default)
- SARIF for GitHub Code Scanning and CI/CD
- LLM-enhanced reports with remediation guidance

---

## [Unreleased]

_No changes yet._

## [0.1.1] - 2025-12-10

### Highlights
- **103 security rules** across memory safety, cryptography, injection, concurrency, and FFI (up from 87 in 0.1.0).
- **Six new advanced MIR rules** (ADV002–ADV007) covering unsafe JSON/TOML and binary deserialization, regex catastrophic backtracking, template injection, async `Send` violations, and span guards held across awaits.
- **30 regression tests** in `mir-advanced-rules`, ensuring coverage for the new analyzers alongside existing flows.

### Added

#### Advanced Rules
- **ADV002 – Insecure JSON/TOML deserialization**: Tracks untrusted sources flowing into `serde_json::from_*` and `toml::from_*` sinks, exempting flows with explicit size checks. Shipped with dedicated MIR analyzer and regression coverage for env-based, constant, and sanitized scenarios.
- **ADV003 – Insecure binary deserialization**: Flags tainted data reaching `bincode::deserialize*` and `postcard::from_bytes*` sinks while recognizing length guards. Includes postcard socket coverage and len-check sanitization tests.
- **ADV004 – Regex denial-of-service**: Detects catastrophic backtracking patterns (nested quantifiers, dot-star loops) compiled via `regex::Regex::new`, with regression tests for `(a+)+` and `(.*)+` cases.
- **ADV005 – Template injection**: Taints environment/request-derived strings through response builders (`warp::reply::html`, `axum::response::Html`) and flags flows lacking HTML escaping, while permitting sanitizers like `html_escape::encode_safe` and constant bodies.
- **ADV006 – Unsafe Send across async boundaries**: Tracks non-Send allocations (Rc/RefCell) flowing into multi-threaded async executors such as `tokio::spawn` / `async_std::task::spawn`, emitting findings when captured values are not sanitized by `Arc` or confined to `spawn_local`.
- **ADV007 – Span guard awaiting**: Flags tracing span guards that remain live across `.await`, ensuring instrumentation scopes end before suspension points while permitting guards dropped prior to awaiting.

#### Testing
- Expanded `mir-advanced-rules` unit suite to **30 tests**, adding coverage for regex DoS, template injection, async Send boundary, and span guard await flows alongside the new JSON/TOML and binary cases (all passing).

#### Documentation
- Updated `README.md` to reflect **103 shipped rules** and highlight unsafe JSON/TOML/binary deserialization, regex DoS, template injection, async Send boundary, and span guard await detection.
- Annotated `advanced_rule_implementation_plan.md` with completion notes for Rules 43–49.
- Marked Rules 43–49 as shipped in `docs/security-rule-backlog.md` (ADV002 – ADV007 entries).

### Added - November 12, 2025

#### New Security Rules (3)
- **RUSTCOLA042**: Cookie without Secure attribute - Detects cookies created without the Secure flag, allowing transmission over unencrypted HTTP (High severity)
- **RUSTCOLA043**: Overly permissive CORS wildcard - Detects CORS configurations allowing any origin (*), enabling CSRF attacks (High severity)
- **RUSTCOLA044**: Observable timing discrepancy in secret comparison - Detects non-constant-time comparisons of passwords, tokens, and HMACs vulnerable to timing attacks (High severity)

**Total Rules: 48** (up from 45)

#### Documentation
- Added `docs/research/rule-detection-levels.md` - Comprehensive taxonomy of detection sophistication levels (Heuristic → Path-Sensitive)
- Updated `docs/real-world-testing-influxdb.md` with Phase 3.3 validation results:
  - Analyzed `influxdb3_processing_engine` (Python processing engine)
  - Found 69 total findings including 43 critical lock guard bugs (RUSTCOLA030)
  - Documented systematic concurrency bug in production InfluxDB code

#### Testing & Validation
- Added `examples/security-rules-demo/` with test cases for new rules
- Validated new rules: 4/4 detections (1 CORS wildcard, 3 timing attacks)
- Zero false positives on safe code patterns
- Real-world validation on InfluxDB production codebase

### Changed - November 12, 2025
- Enhanced real-world testing documentation with detailed lock guard bug analysis
- Expanded Phase 3 validation to include Python processing engine crate

---

## Phase 3.3 - November 11, 2025

### Added - Inter-Procedural Taint Tracking

#### Core Features
- **Inter-procedural dataflow analysis** - Tracks taint across function boundaries
- **Bidirectional exploration** - Backward from sinks, forward verification
- **Multi-hop flow detection** - Detects vulnerabilities spanning 3+ function calls
- **Function summaries** - Caches source/sink/propagation information

#### Performance Improvements
- RUSTCOLA006 (Command Injection) upgraded to inter-procedural analysis
- **Detection Rate**: 100% recall (11/11 vulnerable flows detected)
- **False Positive Rate**: 15.4% (2/13 safe flows flagged)
- **Flow Depth**: Successfully detects 3-level call chains

### Documentation
- Added `docs/phase3-interprocedural-results.md` - Complete Phase 3.3 validation
- Created `docs/research/hir-extraction-plan.md` - HIR integration roadmap
- Updated all Phase 3 progress tracking documents

### Commits
- `895781c` - Phase 3.3: Inter-procedural taint tracking foundation
- `23c0e8e` - Add test cases for multi-hop vulnerabilities
- `7a891bf` - Implement backward exploration from sinks
- `c5d42a9` - Add forward verification pass
- `fca4b14` - Phase 3.3 complete: 100% recall, 15.4% FP rate

---

## Phase 3.2 - November 10, 2025

### Added - Real-World Validation

#### InfluxDB Analysis (influxdb3_authz)
- First production codebase analysis: InfluxDB v3.7.0-nightly
- **Results**: Zero RUSTCOLA006 findings (no command injection vulnerabilities)
- **False Positive Rate**: 0% (no spurious warnings on production code)
- **Analysis Time**: 13 minutes for 427 LOC + dependencies
- **Validation**: Confirms Phase 2 sanitization detection works on real code

#### Toolchain Improvements
- Fixed forced nightly version compatibility issues
- Now respects target project's `rust-toolchain.toml` and `rustup override`
- Works seamlessly with any Rust project regardless of toolchain version

### Documentation
- Created `docs/real-world-testing-influxdb.md` - Complete analysis report
- Documented toolchain compatibility fixes
- Added lessons learned from production analysis

---

## Phase 2 - November 8-9, 2025

### Added - Advanced Sanitization Detection

#### Dataflow Analysis
- Control-flow-aware sanitization tracking
- Loop-based sanitization detection
- Early return pattern recognition
- Escape function detection (Path::canonicalize, shellwords::split, etc.)

#### Performance Improvements
- RUSTCOLA006 (Command Injection):
  - **Before**: 95% false positive rate (19/20 findings were false alarms)
  - **After**: 43% false positive rate (9/21 findings)
  - **Improvement**: 52 percentage point FP reduction

#### Test Coverage
- Added `cargo-cola/tests/cli.rs` - End-to-end CLI testing
- 4 test cases covering vulnerable and safe patterns
- Validation of sanitization detection accuracy

### Documentation
- Created `docs/phase2-cfg-sanitization-results.md` - Complete Phase 2 summary
- Added architecture diagrams for dataflow analysis
- Documented all sanitization patterns detected

### Commits
- `e40c22d` - Phase 2 complete: CFG-based sanitization detection
- Multiple commits implementing loop detection, early returns, escape functions

---

## Phase 1 - November 2025 (Initial Implementation)

### Added - Foundation

#### Core Infrastructure
- MIR (Mid-level Intermediate Representation) extraction via rustc
- Basic taint tracking for command injection (RUSTCOLA006)
- 45 security rules (RUSTCOLA001-045):
  - Memory safety (Box::into_raw, transmute, Vec::set_len, etc.)
  - Unsafe operations (mem::uninitialized, NonNull::new_unchecked)
  - Cryptographic issues (MD5, SHA1, hardcoded keys)
  - TLS/Certificate validation bypasses
  - File system security (world-writable permissions, hardcoded paths)
  - Concurrency bugs (static mut, underscore lock guards, mem::forget guards)
  - Async runtime issues (blocking sleep in async)
  - RustSec-inspired rules (Content-Length DoS, Broadcast !Sync, etc.)

#### CLI Tool
- `cargo-cola` - Cargo subcommand for security analysis
- MIR extraction with caching
- JSON and SARIF output formats
- Rulepack support (YAML-based custom rules)

#### Analysis Engine
- Rule engine with 48 built-in security rules
- Declarative rule support via YAML rulepacks
- Finding deduplication and severity classification
- Source span tracking for precise error locations

### Documentation
- README.md with quickstart guide
- Rule documentation for all 48 rules
- Architecture overview

---

## [0.1.0] - Initial Release (Conceptual)

### Added
- Project structure
- Basic Rust security analysis framework
- MIR-based analysis foundation

---

## Legend

- **Added**: New features, rules, or capabilities
- **Changed**: Modifications to existing functionality
- **Deprecated**: Features marked for removal
- **Removed**: Deleted features
- **Fixed**: Bug fixes
- **Security**: Security-related changes

---

**Note**: This changelog was created retrospectively on November 12, 2025 to track the evolution of Rust-COLA through its development phases. Earlier commits may not have been documented in real-time.
