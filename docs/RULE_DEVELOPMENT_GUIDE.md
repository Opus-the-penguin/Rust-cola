# Rule Development Guide

Two ways to create custom rules: YAML rulepacks (recommended) or Rust code.

---

## Option 1: YAML Rulepacks (Recommended)

Create a `.yaml` file with pattern-based rules. No compilation required.

### Example Rulepack

```yaml
# my-rules.yaml
rules:
  - id: ORG001
    name: no-unwrap
    short_description: Avoid unwrap in production
    full_description: Calls to unwrap() can panic. Handle errors explicitly.
    severity: medium
    message: Replace unwrap() with proper error handling.
    body_contains_any:
      - "unwrap"

  - id: ORG002
    name: no-into-raw
    short_description: Detect Box::into_raw usage
    severity: high
    body_contains_any:
      - "into_raw"
```

### Load the Rulepack

```sh
cargo cola --rulepack my-rules.yaml --crate-path ./my-crate
```

Multiple rulepacks can be loaded:

```sh
cargo cola --rulepack team-rules.yaml --rulepack project-rules.yaml
```

### Available Match Conditions

| Field | Description |
|-------|-------------|
| `body_contains_any` | Match if function body contains any pattern |
| `body_contains_all` | Match if function body contains all patterns |
| `function_name_contains_any` | Match if function name contains any pattern |
| `function_name_contains_all` | Match if function name contains all patterns |

### Required Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (e.g., ORG001) |

### Optional Fields

| Field | Default |
|-------|---------|
| `name` | Same as id |
| `short_description` | Same as id |
| `full_description` | Auto-generated |
| `severity` | medium |
| `message` | Auto-generated |
| `help_uri` | None |

### Severity Values

`critical`, `high`, `medium`, `low`, `note`

---

## Option 2: Rust Rules

For complex logic (taint tracking, type analysis), write a Rust rule.

### Steps

1. Define a struct implementing `Rule` trait in `mir-extractor/src/rules/`
2. Register in `with_builtin_rules()` in `mir-extractor/src/lib.rs`
3. Add tests

### Minimal Example

```rust
use mir_extractor::{Finding, MirPackage, Rule, RuleMetadata, Severity};
use mir_extractor::interprocedural::InterProceduralAnalysis;

pub struct MyRule { metadata: RuleMetadata }

impl MyRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA999".to_string(),
                name: "my-rule".to_string(),
                short_description: "Brief description".to_string(),
                full_description: "Detailed description".to_string(),
                default_severity: Severity::Medium,
                ..Default::default()
            }
        }
    }
}

impl Rule for MyRule {
    fn metadata(&self) -> &RuleMetadata { &self.metadata }
    
    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for function in &package.functions {
            // Pattern matching logic here
        }
        findings
    }
}
```

**Note:** The `inter_analysis` parameter provides access to cross-function taint tracking for injection rules. Most rules can ignore it (use `_inter_analysis`).

### Test

```sh
cargo test -p mir-extractor
```

---

## Suppressing Findings

Two methods: source code comments or YAML configuration.

### Method 1: Source Code Comments

Add `// rust-cola:ignore <RuleID>` on the preceding line or the same line.

```rust
// rust-cola:ignore RUSTCOLA001 Manual verification
unsafe {
    let ptr = buffer.as_mut_ptr();
}
```

Same line:

```rust
let x = unsafe { *ptr }; // rust-cola:ignore RUSTCOLA002 Valid pointer
```

### Method 2: YAML Suppressions

Add a `suppressions` section to a rulepack file:

```yaml
suppressions:
  - rule_id: "RUSTCOLA001"
    file: "src/unsafe_module.rs"  # Optional: substring match
    function: "dangerous_op"      # Optional: substring match
    reason: "Verified safe by audit team"
```

Load with `--rulepack`:

```sh
cargo cola --rulepack suppressions.yaml --crate-path .
```

### Suppression Fields

| Field | Required | Description |
|-------|----------|-------------|
| `rule_id` | Yes | Rule ID to suppress |
| `file` | No | File path substring match |
| `function` | No | Function name substring match |
| `reason` | No | Documentation for audit trail |

---

## Example Rulepack File

See `examples/rulepacks/example-basic.yaml` for a working example.

---

## Built-in Rule Inventory

Run `cargo cola --rules` to print the current rule metadata directly from the analyzer (including any custom rulepacks you load). The table below captures the 126 built-in rules that ship with cargo-cola today.

| ID | Name | Severity | Description |
|-----|------|----------|-------------|
| RUSTCOLA001 | box-into-raw | Medium | Conversion of managed pointer into raw pointer |
| RUSTCOLA002 | std-mem-transmute | High | Usage of std::mem::transmute |
| RUSTCOLA003 | unsafe-usage | High | Unsafe function or block detected |
| RUSTCOLA004 | insecure-hash-md5 | High | Usage of MD5 hashing |
| RUSTCOLA005 | insecure-hash-sha1 | High | Usage of SHA-1 hashing |
| RUSTCOLA006 | untrusted-env-input | Medium | Reads environment-provided input |
| RUSTCOLA007 | process-command-execution | High | Spawns external commands |
| RUSTCOLA008 | vec-set-len | High | Potential misuse of Vec::set_len |
| RUSTCOLA009 | maybeuninit-assume-init | High | MaybeUninit::assume_init usage |
| RUSTCOLA010 | mem-uninit-zeroed | High | Use of mem::uninitialized or mem::zeroed |
| RUSTCOLA011 | modulo-bias-random | Medium | Modulo bias in random number generation |
| RUSTCOLA011 | non-https-url | Medium | HTTP URL usage |
| RUSTCOLA012 | danger-accept-invalid-certs | High | TLS certificate validation disabled |
| RUSTCOLA013 | openssl-verify-none | High | SslContext configured with VerifyNone |
| RUSTCOLA014 | hardcoded-home-path | Low | Hard-coded home directory path detected |
| RUSTCOLA015 | unsafe-send-sync-bounds | High | Unsafe Send/Sync impl without generic bounds |
| RUSTCOLA016 | ffi-buffer-leak-early-return | High | FFI buffer escapes with early return |
| RUSTCOLA017 | allocator-mismatch | High | Mixed allocator/deallocator usage |
| RUSTCOLA018 | rustsec-unsound-dependency | High | Dependency has known RUSTSEC advisory |
| RUSTCOLA019 | yanked-crate-version | Medium | Dependency references a yanked crate version |
| RUSTCOLA020 | cargo-auditable-metadata | Medium | Binary crate missing cargo auditable metadata |
| RUSTCOLA021 | content-length-allocation | High | Allocations sized from untrusted Content-Length header |
| RUSTCOLA022 | length-truncation-cast | High | Payload length cast to narrower integer |
| RUSTCOLA023 | tokio-broadcast-unsync-payload | High | Tokio broadcast carries !Sync payload |
| RUSTCOLA024 | unbounded-allocation | High | Allocation sized from tainted length without guard |
| RUSTCOLA025 | static-mut-global | High | Mutable static global detected |
| RUSTCOLA028 | permissions-set-readonly-false | Medium | Permissions::set_readonly(false) detected |
| RUSTCOLA029 | world-writable-mode | High | World-writable file mode detected |
| RUSTCOLA030 | underscore-lock-guard | High | Lock guard immediately discarded via underscore binding |
| RUSTCOLA031 | command-arg-concatenation | High | Command built with string concatenation or formatting |
| RUSTCOLA032 | openoptions-missing-truncate | Medium | File created with write(true) without truncate or append |
| RUSTCOLA035 | repr-packed-field-reference | High | Reference to packed struct field |
| RUSTCOLA036 | unsafe-cstring-pointer | High | Unsafe CString pointer from temporary |
| RUSTCOLA037 | blocking-sleep-in-async | Medium | Blocking sleep in async function |
| RUSTCOLA038 | vec-set-len-misuse | High | Vec::set_len called on uninitialized vector |
| RUSTCOLA039 | hardcoded-crypto-key | High | Hard-coded cryptographic key or IV |
| RUSTCOLA040 | panic-in-drop | Medium | panic! or unwrap in Drop implementation |
| RUSTCOLA041 | unwrap-in-poll | Medium | unwrap or panic in Future::poll implementation |
| RUSTCOLA042 | cookie-secure-attribute | Medium | Cookie missing Secure attribute |
| RUSTCOLA043 | cors-wildcard | Medium | CORS wildcard origin configured |
| RUSTCOLA044 | timing-attack-secret-comparison | High | Non-constant-time secret comparison |
| RUSTCOLA045 | weak-cipher-usage | High | Weak or deprecated cipher algorithm |
| RUSTCOLA046 | predictable-randomness | High | Predictable random number generation |
| RUSTCOLA047 | env-var-literal | Low | Hardcoded environment variable name |
| RUSTCOLA048 | invisible-unicode | High | Invisible Unicode characters in source |
| RUSTCOLA049 | crate-wide-allow | Low | Crate-wide allow attribute disables lints |
| RUSTCOLA050 | misordered-assert-eq | Low | assert_eq arguments may be misordered |
| RUSTCOLA051 | try-io-result | Low | Try operator (?) used on io::Result |
| RUSTCOLA052 | local-ref-cell | Low | RefCell used for local mutable state |
| RUSTCOLA053 | untrimmed-stdin | Low | Stdin input not trimmed |
| RUSTCOLA054 | infinite-iterator | High | Infinite iterator without termination |
| RUSTCOLA055 | unix-permissions-not-octal | Medium | Unix file permissions not in octal notation |
| RUSTCOLA056 | openoptions-inconsistent-flags | Medium | OpenOptions with inconsistent flag combinations |
| RUSTCOLA057 | unnecessary-borrow-mut | Low | Unnecessary borrow_mut() on RefCell |
| RUSTCOLA058 | absolute-path-in-join | High | Absolute path passed to Path::join() or PathBuf::push() |
| RUSTCOLA059 | ctor-dtor-std-api | Medium | #[ctor]/#[dtor] invoking std APIs |
| RUSTCOLA060 | connection-string-password | High | Password in connection string |
| RUSTCOLA061 | password-field-masking | Medium | Password field not masked |
| RUSTCOLA062 | weak-hashing-extended | High | Usage of weak cryptographic hash algorithms |
| RUSTCOLA063 | null-pointer-transmute | High | Null pointer transmuted to reference or function pointer |
| RUSTCOLA064 | zst-pointer-arithmetic | High | Pointer arithmetic on zero-sized types |
| RUSTCOLA065 | cleartext-env-var | High | Sensitive data in environment variable |
| RUSTCOLA067 | spawned-child-no-wait | Medium | Spawned child process not waited on |
| RUSTCOLA068 | dead-store-array | Low | Dead store in array |
| RUSTCOLA072 | overscoped-allow | Medium | Crate-wide allow attribute suppresses security lints |
| RUSTCOLA073 | nonnull-new-unchecked | High | NonNull::new_unchecked usage without null check |
| RUSTCOLA073 | unsafe-ffi-pointer-return | Medium | FFI function returns raw pointer without safety invariants |
| RUSTCOLA074 | non-thread-safe-test | Medium | Test function uses non-thread-safe types |
| RUSTCOLA075 | cleartext-logging | Medium | Sensitive data in logs |
| RUSTCOLA076 | log-injection | Medium | Untrusted input may enable log injection |
| RUSTCOLA077 | division-by-untrusted | Medium | Division by untrusted input without validation |
| RUSTCOLA078 | mem-forget-guard | High | mem::forget on guard types |
| RUSTCOLA078 | maybeuninit-assume-init-without-write | High | MaybeUninit::assume_init without preceding write |
| RUSTCOLA079 | regex-injection | High | Untrusted input used to construct regex pattern |
| RUSTCOLA080 | unchecked-indexing | Medium | Untrusted input used as array index without bounds check |
| RUSTCOLA081 | serde-length-mismatch | Medium | Serde serialize_* length mismatch |
| RUSTCOLA082 | slice-element-size-mismatch | High | Raw pointer to slice of different element size |
| RUSTCOLA083 | slice-from-raw-parts-length | High | slice::from_raw_parts with potentially invalid length |
| RUSTCOLA084 | tls-verification-disabled | High | TLS certificate verification disabled |
| RUSTCOLA085 | aws-s3-unscoped-access | High | AWS S3 operation with untrusted bucket/key/prefix |
| RUSTCOLA086 | path-traversal | High | Untrusted input used in filesystem path |
| RUSTCOLA087 | sql-injection | High | Untrusted input used in SQL query construction |
| RUSTCOLA088 | server-side-request-forgery | High | Untrusted input used as HTTP request URL |
| RUSTCOLA089 | insecure-yaml-deserialization | Medium | Untrusted input in YAML deserialization |
| RUSTCOLA090 | unbounded-read-to-end | Medium | Unbounded read on untrusted source |
| RUSTCOLA091 | insecure-json-toml-deserialization | Medium | Untrusted input in JSON/TOML deserialization |
| RUSTCOLA092 | commented-out-code | Low | Commented-out code detected |
| RUSTCOLA093 | blocking-ops-in-async | Medium | Blocking operation in async function |
| RUSTCOLA094 | mutex-guard-across-await | High | MutexGuard held across await point |
| RUSTCOLA095 | transmute-lifetime-change | High | Transmute changes reference lifetime |
| RUSTCOLA096 | raw-pointer-escape | High | Raw pointer from local reference escapes function |
| RUSTCOLA097 | build-script-network-access | High | Network access detected in build script |
| RUSTCOLA098 | interprocedural-command-injection | High | Inter-procedural command injection |
| RUSTCOLA100 | oncecell-toctou-race | Medium | Potential TOCTOU race with OnceCell |
| RUSTCOLA101 | variance-transmute-unsound | High | Transmutes violating variance rules |
| RUSTCOLA102 | proc-macro-side-effects | High | Proc-macro with suspicious side effects |
| RUSTCOLA103 | wasm-linear-memory-oob | High | WASM linear memory out-of-bounds risk |
| RUSTCOLA106 | unchecked-timestamp-multiplication | Medium | Unchecked multiplication in timestamp conversion |
| RUSTCOLA107 | embedded-interpreter-usage | Medium | Embedded interpreter creates code injection surface |
| RUSTCOLA109 | async-signal-unsafe-in-handler | High | Async-signal-unsafe operation in signal handler |
| RUSTCOLA111 | missing-sync-bound-on-clone | High | Clone in concurrent context without Sync bound |
| RUSTCOLA112 | pin-contract-violation | High | Potential Pin contract violation through unsplit |
| RUSTCOLA113 | oneshot-race-after-close | High | Potential race condition with oneshot channel close() |
| RUSTCOLA115 | non-cancellation-safe-select | Medium | Potentially non-cancellation-safe future in select! |
| RUSTCOLA116 | panic-in-ffi-boundary | High | Potential panic in extern "C" function |
| RUSTCOLA117 | panic-while-holding-lock | Medium | Potential panic while holding lock |
| RUSTCOLA118 | returned-ref-to-local | High | Reference to local variable returned |
| RUSTCOLA119 | closure-escaping-refs | High | Closure may capture escaping references |
| RUSTCOLA120 | self-referential-struct | High | Potential self-referential struct without Pin |
| RUSTCOLA121 | executor-starvation | Medium | CPU-bound work in async context |
| RUSTCOLA122 | async-drop-correctness | Medium | Async resource may be dropped without cleanup |
| RUSTCOLA123 | unwrap-in-hot-path | Medium | Panic-prone code in performance-critical path |
| RUSTCOLA124 | panic-in-drop-impl | High | Panic-prone code in Drop implementation |
| RUSTCOLA125 | spawned-task-panic-propagation | Medium | Spawned task may silently swallow panics |
| RUSTCOLA126 | wasm-host-function-trust | Medium | Untrusted data from WASM host functions |
| RUSTCOLA127 | wasm-capability-leak | High | WASM component model capability leak |
| RUSTCOLA128 | unsafecell-aliasing-violation | High | Potential UnsafeCell aliasing violation |
| RUSTCOLA129 | lazy-init-panic-poison | Medium | Panic-prone code in lazy initialization |
| RUSTCOLA200 | dangling-pointer-use-after-free | Critical | Detects use of pointers after their memory has been freed |
| RUSTCOLA201 | insecure-binary-deserialization | High | Detects binary deserialization on untrusted input |
| RUSTCOLA202 | regex-backtracking-dos | Medium | Detects regex patterns vulnerable to catastrophic backtracking |
| RUSTCOLA203 | uncontrolled-allocation-size | High | Detects allocations sized from untrusted sources |
| RUSTCOLA204 | integer-overflow-untrusted | Medium | Detects arithmetic on untrusted input without overflow protection |
| RUSTCOLA205 | template-injection | High | Detects unescaped user input in HTML responses |
| RUSTCOLA206 | unsafe-send-across-async | High | Detects non-Send types captured in spawned tasks |
| RUSTCOLA207 | span-guard-across-await | Low | Detects tracing span guards held across await points |
