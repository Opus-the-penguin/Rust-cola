# Advanced Rule Implementation Plan

This plan outlines the approach for implementing the remaining advanced rules in Rust-cola, as identified in the security-rule-backlog. Each rule includes a brief description, technical notes, and dependencies.

## Advanced Rules To Implement

### Memory Safety & Unsafe Usage
- **6. Dangling pointer use-after-free**
  - Detect use of pointers after the memory they reference has been freed.
  - *Technical*: Requires lifetime and alias analysis, MIR dataflow, and tracking of drop/reallocation events.
- **7. Access of invalid pointer**
  - Catch dereferences of null or misaligned pointers.
  - *Technical*: Needs pointer provenance and alignment tracking.
- **14. ptr::copy overlap**
  - Ensure non-overlapping regions for `copy_nonoverlapping`.
  - *Technical*: Requires memory region analysis and pointer arithmetic reasoning.

### Data Exposure & Logging
- **31. Cleartext storage in databases**
  - Detect inserts of sensitive data without encryption.
  - *Technical*: Taint tracking from sensitive sources to DB sinks, with context on encryption usage.
- **32. Cleartext transmission**
  - Identify writes of sensitive data to non-TLS channels.
  - *Technical*: Taint tracking to network sinks, protocol detection.

### Input Validation & Injection
- **43. TOML/JSON deserialization** *(implemented 2025-12-10)*
  - Detect unsafe deserialization of untrusted data.
  - *Technical*: Taint tracking to serde/json/toml sinks, sanitizer detection.
  - *Status notes*: Added `InsecureJsonTomlDeserializationRule` in `mir-advanced-rules`, covering env-based JSON inflow, constant-safe cases, and length-check sanitization with regression tests.
- **44. bincode / postcard deserialization** *(implemented 2025-12-10)*
  - Highlight binary format parsing on tainted input.
  - *Technical*: Similar to above, but for binary formats.
  - *Status notes*: Added `InsecureBinaryDeserializationRule` covering `bincode` and `postcard` sinks with len-check sanitizer support and regression tests.
- **45. Regex denial-of-service** *(implemented 2025-12-10)*
  - Flag regex patterns with nested quantifiers that cause catastrophic backtracking.
  - *Technical*: Pattern analysis with nested quantifier detection.
  - *Status notes*: Added `RegexBacktrackingDosRule` (ADV004) identifying nested quantifier/dot-star loops in regex compilation with regression coverage.
- **46. Template injection in web responses** *(implemented 2025-12-10)*
  - Detect tainted data rendered directly into HTML/template response builders.
  - *Technical*: Uses MIR taint tracking from env/request sources through aliasing into templating sinks with sanitizer allowlist for HTML escaping and constant literals.
  - *Status notes*: Added `TemplateInjectionRule` covering `warp::reply::html` and similar templating sinks, recognizing sanitizers like `html_escape::encode_safe` and constant bodies. Regression tests ensure tainted env var flows are flagged while escaped and constant cases are allowed.

### Concurrency & Async
- **48. Unsafe Send across async boundaries** *(implemented 2025-12-10)*
  - Detect `Send` requirements violated in futures.
  - *Technical*: MIR-based tracking of non-Send allocations (Rc/RefCell) propagating into multi-threaded executor spawns.
  - *Status notes*: Added `UnsafeSendAcrossAsyncBoundaryRule` (ADV006) flagging `tokio::spawn` / `async_std::task::spawn` calls that capture `Rc`/`RefCell` inputs while allowing safe patterns like `Arc` and `spawn_local`. Regression tests cover Rc, Arc, and spawn_local scenarios.
- **49. Await while holding span guard** *(implemented 2025-12-10)*
  - Avoid locking instrumentation across `.await`.
  - *Technical*: MIR analysis tracking tracing span guard lifetimes relative to await points.
  - *Status notes*: Added `AwaitSpanGuardRule` (ADV007) to detect `tracing::Span::enter()` guards that remain live across `.await` calls, while allowing cases where guards are dropped before the await. Regression coverage includes positive (guard held) and negative (guard dropped) scenarios.
- **50. Mutex guard dropped prematurely**
  - Detect premature dropping of mutex guards.
  - *Technical*: Lifetime analysis, drop tracking.
- **53. Await missing in async return**
  - Detect missing await in async returns.
  - *Technical*: Control flow analysis in async functions.

### Resource Management & DoS
- **54. Uncontrolled allocation size**
  - Taint to `Vec::with_capacity` etc.
  - *Technical*: Taint tracking from untrusted sources to allocation APIs.
- **56. I/O buffers not fully processed**
  - Detect incomplete buffer processing.
  - *Technical*: Dataflow analysis on buffer usage.
- **61. File operations on tainted paths**
  - Strengthen path traversal detection.
  - *Technical*: Taint tracking, path sanitizer detection.

### Web & Framework Specific
- **64. warp filters leaking request body**
  - Ensure request body not logged verbatim.
  - *Technical*: Taint tracking from request body to log sinks.
- **65. actix-web responses with interpolated input**
  - Taint to HTML body formatting.
  - *Technical*: Taint tracking to response formatting APIs.
- **66. Axum extractors without validation**
  - Flag `Form`/`Json` usage without explicit validation.
  - *Technical*: Source tracking, validation detection.

### Testing & Infrastructure Hygiene
- **69. Non-local effect before panic in tests**
  - Detect side effects before panics in test code.
  - *Technical*: Control/dataflow analysis in test functions.
- **75. Non-thread-safe call in async context**
  - Extend non-thread-safe call detection to async tasks.
  - *Technical*: Type and context analysis in async code.

### External Tool Findings – Rudra
- **82. Unsafe closure panic guard**
  - Flag unsafe routines that duplicate ownership and invoke user-supplied closures without panic guards.
  - *Technical*: MIR dataflow, panic-safety analysis.
- **83. Borrow contract invariant**
  - Detect code that caches raw pointers across trait method calls.
  - *Technical*: Dataflow and aliasing analysis.

### External Tool Findings – MirChecker
- **85. Unchecked index arithmetic panic**
  - Surface integer arithmetic that feeds slice/array indexing without bounds checks.
  - *Technical*: MIR dataflow, range analysis.
- **86. Unsafe deallocation of borrowed storage**
  - Catch lifetime-corruption patterns where unsafe code drops/frees memory reachable through active borrows.
  - *Technical*: Lifetime and borrow checker emulation.

### External Tool Findings – FFIChecker
- **89. FFI panic-safe drop guard**
  - Flag unsafe FFI stubs that leave state inconsistent if a Rust panic unwinds across the boundary.
  - *Technical*: Panic-safety and drop guard analysis.

### Analysis Infrastructure
- **108. Add HIR extraction pipeline**
  - Add HIR capture to enable richer type/trait/attribute analysis.
  - *Technical*: Integrate rustc_interface, persist HIR snapshot, correlate with MIR.

## Sequencing & Dependencies
- Start with rules that require only MIR dataflow and taint tracking (e.g., 43, 44, 54, 61, 85).
- Progress to rules needing lifetime/alias analysis and async context (e.g., 6, 7, 14, 48, 49, 50, 56, 86, 89).
- Infrastructure (108) can be developed in parallel if needed for HIR-dependent rules.

---

**Next Step:** Begin with Rule 43 (TOML/JSON deserialization) as it is a common, high-impact pattern and leverages existing taint tracking infrastructure.
