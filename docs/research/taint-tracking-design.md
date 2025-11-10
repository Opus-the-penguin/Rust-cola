# Taint Tracking Infrastructure Design

**Created:** 2025-11-10  
**Status:** Phase 1 - Design & Implementation  
**Goal:** Build dataflow analysis to track untrusted data from sources → sinks

## Overview

Taint tracking is a dataflow analysis technique that identifies when untrusted data (taint sources) flows to security-sensitive operations (taint sinks) without proper sanitization. This enables precise detection of:

- Command injection (env vars → Command::arg)
- Path traversal (user input → fs operations)
- SQL injection (HTTP params → sql_query)
- Regex DoS (untrusted strings → Regex::new)

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                   TaintAnalysis Engine                  │
├─────────────────────────────────────────────────────────┤
│  1. Source Detection   │  Identify taint origins       │
│  2. Propagation        │  Track through MIR statements │
│  3. Sanitization       │  Detect validation/cleanup    │
│  4. Sink Detection     │  Find dangerous operations    │
│  5. Path Analysis      │  Report taint flows           │
└─────────────────────────────────────────────────────────┘
         ↓                    ↓                    ↓
    ┌─────────┐        ┌──────────┐        ┌──────────┐
    │ Sources │        │  Sinks   │        │ Sanitize │
    │ Registry│        │ Registry │        │ Patterns │
    └─────────┘        └──────────┘        └──────────┘
```

### Data Structures

```rust
// Core taint tracking types
pub struct TaintAnalysis {
    sources: SourceRegistry,
    sinks: SinkRegistry,
    sanitizers: SanitizerRegistry,
    state: TaintState,
}

pub struct TaintValue {
    pub origin: TaintSource,
    pub propagation_path: Vec<String>, // For debugging/reporting
    pub sanitized: bool,
}

pub struct TaintSource {
    pub kind: SourceKind,
    pub location: SourceSpan,
    pub confidence: Confidence,
}

pub enum SourceKind {
    EnvironmentVariable,    // env::var, env::var_os
    NetworkInput,           // TCP read, HTTP request
    FileInput,              // fs::read, File::read
    CommandOutput,          // Command::output
    UserInput,              // stdin, readline
}

pub struct TaintSink {
    pub kind: SinkKind,
    pub severity: Severity,
    pub requires_sanitization: Vec<SanitizationType>,
}

pub enum SinkKind {
    CommandExecution,       // Command::new, Command::arg
    FileSystemOp,           // fs::write, fs::remove, Path::join
    SqlQuery,               // diesel::sql_query, sqlx::query
    RegexCompile,           // Regex::new
    NetworkWrite,           // TcpStream::write
    Eval,                   // Rarely in Rust, but some DSLs
}

pub enum SanitizationType {
    Allowlist,              // chars().all(allowed_set)
    RegexValidation,        // matches!(input, SAFE_PATTERN)
    TypeConversion,         // parse::<i32>(), PathBuf::from
    PathCanonicalization,   // fs::canonicalize
    SqlParameterization,    // Prepared statements (not string concat)
}

pub struct TaintState {
    // Maps MIR local (variable) to its taint status
    locals: HashMap<LocalId, Option<TaintValue>>,
    // Tracks function arguments (for interprocedural analysis later)
    args: HashMap<FunctionId, Vec<Option<TaintValue>>>,
}
```

## Taint Source Detection

### Phase 1: Environment Variables (RUSTCOLA006)

**Sources to detect:**
```rust
// Direct sources
std::env::var("KEY")           // Returns Result<String>
std::env::var_os("KEY")        // Returns Option<OsString>
std::env::vars()               // Returns iterator of (String, String)
std::env::vars_os()            // Returns iterator of (OsString, OsString)

// Convenience wrappers
env!("KEY")                    // Compile-time, not runtime taint
option_env!("KEY")             // Compile-time, not runtime taint
```

**Detection strategy:**
1. Scan MIR for function calls matching `std::env::*` patterns
2. Identify the MIR local that receives the result
3. Mark that local as tainted with `SourceKind::EnvironmentVariable`
4. Record source location for error reporting

**Example MIR pattern:**
```
bb0: {
    _3 = const std::env::var(move _4) -> [return: bb1, unwind: bb5];
}
bb1: {
    _2 = Result::unwrap(move _3) -> [return: bb2, unwind: bb5];
}
// _2 is now tainted
```

### Future Sources (Phase 2+)

- **Network:** `TcpStream::read`, `HttpRequest::body`
- **Files:** `fs::read_to_string`, `File::read`
- **User Input:** `io::stdin().read_line`
- **Command Output:** `Command::output().stdout`

## Taint Propagation

### Propagation Rules

Taint flows through MIR statements according to these rules:

#### 1. Assignment (Copy/Move)
```rust
let tainted = env::var("USER")?;
let alias = tainted;              // alias inherits taint
```

**MIR:**
```
_2 = _1;  // If _1 is tainted, _2 becomes tainted
```

#### 2. Field/Index Access
```rust
let tainted = env::var("USER")?;
let first_char = tainted.chars().next();  // Taint propagates through field access
```

**MIR:**
```
_3 = (_1.0: Field);  // Taint propagates to field
_4 = _2[_3];         // Taint propagates to index result
```

#### 3. Function Calls (Conservative)
```rust
let tainted = env::var("USER")?;
let upper = tainted.to_uppercase();  // Taint propagates through transformation
```

**Strategy:**
- If any argument is tainted, assume return value is tainted
- Exception: Known sanitizers (see Sanitization section)
- Future: Interprocedural analysis to track through function bodies

#### 4. String Operations
```rust
let tainted = env::var("USER")?;
let cmd = format!("Hello {}", tainted);  // cmd is tainted
let concat = tainted + " suffix";        // concat is tainted
```

**Pattern recognition:**
- `format!()`, `concat!()` - If any arg tainted, result tainted
- `String::push_str()` - Taints receiver
- `+` operator on strings - Result is tainted if either side is

#### 5. Control Flow (Phi Nodes)
```rust
let value = if condition {
    env::var("A")?     // Tainted
} else {
    "safe".to_string()  // Not tainted
};
// value is conditionally tainted (conservative: treat as tainted)
```

**Strategy:** If any branch produces taint, merge point is tainted

### Non-Propagation Cases

Taint does NOT propagate through:
- Length/size queries: `tainted.len()` → Not tainted (just a number)
- Existence checks: `tainted.is_empty()` → Not tainted (boolean)
- Comparisons: `tainted == "test"` → Not tainted (boolean)

## Sanitization Detection

### Validation Patterns

Sanitization removes taint when code proves the data is safe:

#### 1. Allowlist Validation
```rust
let input = env::var("USER")?;
if input.chars().all(|c| c.is_alphanumeric() || c == '_') {
    // input is now sanitized for this scope
    use_safe_string(&input);  // OK
}
```

**Detection:**
- Look for `.chars().all(predicate)` returning true
- Recognize predicates: `is_alphanumeric`, `is_ascii_digit`, custom allowlists
- Mark variable as sanitized within the dominated scope

#### 2. Regex Validation
```rust
let input = env::var("USER")?;
let pattern = Regex::new(r"^[a-zA-Z0-9_]+$")?;
if pattern.is_match(&input) {
    // input is sanitized
    use_safe_string(&input);  // OK
}
```

**Detection:**
- Recognize `Regex::is_match` with `is_match()` result
- If result is checked (if condition), mark variable sanitized in true branch

#### 3. Type Conversion (Parse)
```rust
let input = env::var("PORT")?;
let port: u16 = input.parse()?;  // port is NOT tainted (numeric type)
```

**Detection:**
- `.parse::<T>()` where T is numeric → Result is not tainted
- Type system provides safety guarantee

#### 4. Path Canonicalization
```rust
let input = env::var("PATH")?;
let safe_path = fs::canonicalize(&input)?;  // Resolves .. and symlinks
// Still tainted but canonicalized (reduced risk)
```

**Detection:**
- `fs::canonicalize` reduces taint severity but doesn't eliminate
- Mark as "sanitized for traversal" but still tainted

#### 5. SQL Parameterization
```rust
let user = env::var("USER")?;
sqlx::query("SELECT * FROM users WHERE name = $1")
    .bind(&user)  // Safe: parameterized query
    .fetch_all(&pool).await?;
```

**Detection:**
- Recognize `.bind()` pattern → Marks sink as safe
- Distinguish from string concatenation

### Anti-Patterns (NOT Sanitization)

These do NOT sanitize:
```rust
// ❌ Insufficient validation
if !input.is_empty() { ... }       // Just checks non-empty
if input.len() < 100 { ... }       // Just checks length
if input.contains("safe") { ... }  // Substring check is not allowlist

// ❌ Encoding is not sanitization
let encoded = input.replace("'", "\\'");  // Still tainted!
let escaped = html_escape(&input);        // Still tainted!
```

## Taint Sink Detection

### Phase 1: Command Execution

**Sinks:**
```rust
std::process::Command::new(arg)     // If arg is tainted
std::process::Command::arg(arg)     // If arg is tainted
std::process::Command::args(args)   // If any arg is tainted
```

**Special case - Shell invocation (CRITICAL):**
```rust
Command::new("sh").arg("-c").arg(tainted)   // Highest severity
Command::new("bash").arg("-c").arg(tainted)
Command::new("cmd").arg("/c").arg(tainted)  // Windows
```

**Detection strategy:**
1. Find calls to `Command::new`, `Command::arg`, `Command::args`
2. Check if argument local is tainted
3. If tainted and unsanitized → Report finding
4. Extra severity if shell invocation pattern detected

### Phase 1: File System Operations

**Sinks:**
```rust
std::fs::write(path, ...)        // If path is tainted
std::fs::remove_file(path)       // If path is tainted
std::fs::remove_dir_all(path)    // If path is tainted (CRITICAL)
std::path::Path::join(component)  // If component is tainted
std::path::PathBuf::push(component)
```

**Example vulnerability:**
```rust
let user_file = env::var("FILE")?;
fs::remove_file(&user_file)?;  // ❌ Path traversal risk
// User could set FILE="../../../etc/passwd"
```

### Future Sinks (Phase 2+)

- **SQL:** `diesel::sql_query()`, `sqlx::query()` (non-parameterized)
- **Regex:** `Regex::new()` (ReDoS risk)
- **Network:** `TcpStream::write()` (injection into network protocols)
- **Eval:** Any DSL evaluation (rare in Rust)

## Path Analysis & Reporting

### Flow Path Tracking

For each tainted sink, report:
1. **Source:** Where taint originated
2. **Sink:** Where taint reached dangerous operation
3. **Path:** Intermediate steps (assignments, function calls)
4. **Sanitization status:** Was it sanitized? By what?

**Example report:**
```
RUSTCOLA006: Untrusted environment variable flows to command execution

Source:
  env::var("USER_COMMAND") at src/main.rs:10:17
  ↓
  Assigned to `cmd` at src/main.rs:10:13
  ↓
  Passed to Command::arg() at src/main.rs:12:22

Sink:
  Command::arg() at src/main.rs:12:5
  Severity: High (no sanitization detected)

Recommendation:
  Validate input before use:
    if cmd.chars().all(|c| c.is_alphanumeric()) {
        Command::new("tool").arg(&cmd).spawn()?;
    }
```

## Implementation Plan

### Step 1: Data Structures (Week 6, Day 1-2)
- [ ] Create `mir-extractor/src/dataflow/taint.rs`
- [ ] Define `TaintAnalysis`, `TaintSource`, `TaintSink`, `TaintValue` structs
- [ ] Add unit tests for data structure creation

### Step 2: Source Detection (Week 6, Day 3-4)
- [ ] Implement `SourceRegistry` with env::var patterns
- [ ] Add function to scan MIR for source calls
- [ ] Tag return values with `TaintValue`
- [ ] Test on examples/taint-tracking

### Step 3: Propagation Engine (Week 6, Day 5-7)
- [ ] Implement `propagate_through_statement()`
- [ ] Handle assignment, field access, function calls
- [ ] Track taint through control flow merges
- [ ] Test propagation with unit tests

### Step 4: Sink Detection (Week 7, Day 1-2)
- [ ] Implement `SinkRegistry` with Command, fs patterns
- [ ] Add function to check if tainted local reaches sink
- [ ] Generate warnings with source→sink paths
- [ ] Test on examples/taint-tracking

### Step 5: Sanitization (Week 7, Day 3-4)
- [ ] Implement `SanitizerRegistry`
- [ ] Detect validation patterns (chars().all, regex, parse)
- [ ] Mark taint as sanitized when dominated by checks
- [ ] Test with sanitized examples

### Step 6: Integration (Week 7, Day 5)
- [ ] Replace RUSTCOLA006 heuristic with taint analysis
- [ ] Add `--enable-taint-tracking` flag (feature gate)
- [ ] Run on test suite, validate findings
- [ ] Measure false positive rate

### Step 7: Documentation (Week 7, Day 6-7)
- [ ] Write contributor guide for adding sources/sinks
- [ ] Document architecture with diagrams
- [ ] Update security-rule-backlog.md
- [ ] Create example test cases with explanations

## Test Suite

### examples/taint-tracking Structure

```
examples/taint-tracking/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                    # Module exports
    ├── positive_cases.rs         # Should be detected
    │   ├── env_to_command()      # Direct flow
    │   ├── env_to_fs()           # Path traversal
    │   ├── env_through_format()  # Via string ops
    │   └── env_through_assign()  # Via aliasing
    ├── negative_cases.rs         # Should NOT be detected
    │   ├── sanitized_allowlist() # Validated before use
    │   ├── sanitized_parse()     # Type conversion
    │   ├── hardcoded_safe()      # Not from env
    │   └── validated_regex()     # Regex check
    └── edge_cases.rs             # Tricky scenarios
        ├── partial_taint()       # Only part tainted
        ├── conditional_taint()   # Branch-dependent
        └── dropped_taint()       # Taint then sanitize
```

### Expected Detections

**Positive Cases (4 findings):**
1. `env_to_command`: env::var → Command::arg (no sanitization)
2. `env_to_fs`: env::var → fs::write (no sanitization)
3. `env_through_format`: env::var → format! → Command::arg
4. `env_through_assign`: env::var → alias → Command::arg

**Negative Cases (0 findings):**
- All cases should pass without warnings

**Success Criteria:**
- Precision: 100% (no false positives on negative cases)
- Recall: 100% (all positive cases detected)

## Performance Considerations

### Complexity Analysis

- **Source detection:** O(n) where n = number of function calls
- **Propagation:** O(n * m) where n = statements, m = locals
- **Sink detection:** O(n) where n = function calls
- **Total:** O(n²) worst case, O(n) average case

### Optimization Strategies

1. **Early termination:** Stop propagating when taint reaches sink
2. **Local scope:** Only track within function boundaries (Phase 1)
3. **Sparse tracking:** Only track locals that are ever tainted
4. **Caching:** Memoize sanitization checks

### Memory Budget

- Track ~1000 tainted locals per function max
- Path history limited to 10 steps (for reporting)
- Estimated: <10MB overhead per analyzed crate

## Future Enhancements (Post-Phase 1)

### Phase 2: Advanced Propagation
- Interprocedural analysis (track through function calls)
- Field-sensitive tracking (struct fields independently tainted)
- Container tracking (Vec, HashMap elements)

### Phase 3: More Sources & Sinks
- Network input (HTTP, TCP)
- File input (fs::read)
- SQL sinks (diesel, sqlx)
- Regex sinks (ReDoS)

### Phase 4: Alias Analysis
- Handle references and borrows
- Track taint through `&mut` modifications
- Handle lifetime-dependent taint

### Phase 5: Context-Sensitive Analysis
- Different taint rules per context (CLI vs web server)
- User-configurable source/sink policies
- Integration with security annotations

## References

- **OWASP:** [Taint Analysis](https://owasp.org/www-community/vulnerabilities/Taint_Analysis)
- **Semgrep:** [Taint mode documentation](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/)
- **CodeQL:** [Modeling data flow](https://codeql.github.com/docs/codeql-language-guides/modeling-data-flow/)
- **Rust MIR:** [MIR documentation](https://rustc-dev-guide.rust-lang.org/mir/index.html)

---

_Last updated: 2025-11-10_
