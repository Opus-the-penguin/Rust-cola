# Security Rule Backlog

This backlog consolidates security-focused rule ideas for Rust-cola compiled from public advisories and vulnerability pattern documentation published by various security research teams and tools, including Semgrep, GitHub CodeQL, SonarSource/SonarQube, Trail of Bits' Dylint examples, Checkmarx, Snyk, and RustSec. Each entry captures the rationale, the primary analysis signal we expect to leverage, and a rough feasibility tier.

Feasibility legend:

- **Heuristic** – String or signature matching with minimal context.
- **MIR dataflow** – Requires MIR-aware taint tracking or control/data-flow reasoning.
- **Advanced** – Demands deeper semantic modelling (lifetimes, aliasing, interprocedural analysis) or significant new infrastructure.

## Memory Safety & Unsafe Usage

1. **Box::into_raw escape** *(shipped)* – Detect raw pointer escapes via `Box::into_raw`. **Feasibility:** Heuristic.
2. **std::mem::transmute usage** *(shipped)* – Flag calls to `std::mem::transmute`. **Feasibility:** Heuristic.
3. **Vec::set_len misuse** – Identify `Vec::set_len` when the vector is not fully initialized. **Feasibility:** MIR dataflow.
4. **MaybeUninit::assume_init before initialization** – Detect `assume_init` without a preceding `write`. **Feasibility:** MIR dataflow.
5. **mem::uninitialized / mem::zeroed** *(shipped — RUSTCOLA010)* – Flag usage of deprecated zero-init APIs on non-zero types. **Feasibility:** Heuristic.
6. **Dangling pointer use-after-free** – Ensure no access after `drop` or reallocation. **Feasibility:** Advanced.
7. **Access of invalid pointer** – Catch derefs of null or misaligned pointers. **Feasibility:** Advanced.
8. **Unsafe Send/Sync impls** *(RUSTCOLA015 shipped for missing generic bounds; doc commentary lint pending)* – Highlight `unsafe impl Send/Sync` without safety commentary. **Feasibility:** Heuristic (doc-aware).
9. **static mut globals** *(shipped — RUSTCOLA025)* – Warn about mutable statics that break thread safety. **Feasibility:** Heuristic.
10. **NonNull::new_unchecked misuse** *(shipped — RUSTCOLA026)* – Ensure null checks before `new_unchecked`. **Feasibility:** Heuristic.
11. **mem::forget on guards** *(shipped — RUSTCOLA027)* – Catch forgetting RAII guards that release locks/resources. **Feasibility:** MIR dataflow.
12. **repr(packed) field references** – Avoid taking references to packed struct fields. **Feasibility:** Heuristic.
13. **slice::from_raw_parts length inflation** – Validate slice length when constructed from raw pointers. **Feasibility:** Advanced.
14. **ptr::copy overlap** – Ensure non-overlapping regions for `copy_nonoverlapping`. **Feasibility:** Advanced.
15. **Unsafe FFI pointer returns** – Require invariants when `extern "C"` returns raw pointers. **Feasibility:** Heuristic.
16. **Null pointer transmutes** – Flag `transmute` of null pointers or to function pointers. **Feasibility:** Heuristic.
17. **Raw pointer to slice of different element size** – Detect mismatched slice casts. **Feasibility:** MIR dataflow.
18. **Pointer arithmetic on zero-sized types** – Sonar RSPEC-7412 parity. **Feasibility:** Heuristic.

## Secrets & Cryptography

19. **Insecure hashing MD5/SHA-1** *(shipped)* – Detect use of MD5/SHA-1. **Feasibility:** Heuristic.
20. **Weak ciphers (DES/RC4/etc.)** – Pattern match legacy crypto crate usage. **Feasibility:** Heuristic.
21. **Hard-coded cryptographic values** – Spot embedded keys or IVs. **Feasibility:** MIR dataflow.
22. **Predictable randomness** – Warn on constant seeds for RNG. **Feasibility:** Heuristic.
23. **Modulo bias on random outputs** – Identify `% n` on random values in crypto context. **Feasibility:** Advanced.
24. **Danger accept invalid certs** – Flag `danger_accept_invalid_certs(true)`. **Feasibility:** Heuristic.
25. **OpenSSL VerifyNone** *(shipped)* – Detect `set_verify(VerifyNone)`. **Feasibility:** Heuristic.
26. **Non-HTTPS URLs** – Spot HTTP URLs in network clients. **Feasibility:** Heuristic.
27. **TLS verification disabled in custom clients** – Extend detection beyond reqwest (e.g., hyper). **Feasibility:** MIR dataflow.
28. **Weak hashing beyond MD5/SHA-1** – Include RIPEMD, CRC for sensitive data. **Feasibility:** Heuristic.
29. **Cleartext env var exposure** – Identify `env::set_var` with sensitive values. **Feasibility:** Heuristic.

## Data Exposure & Logging

30. **Cleartext logging of secrets** – Taint track secret sources into log macros. **Feasibility:** MIR dataflow.
31. **Cleartext storage in databases** – Detect inserts of sensitive data without encryption. **Feasibility:** Advanced.
32. **Cleartext transmission** – Identify writes of sensitive data to non-TLS channels. **Feasibility:** Advanced.
33. **Log injection** – Taint newline-containing input to logging calls. **Feasibility:** MIR dataflow.
34. **Hard-coded home directory paths** – Prevent absolute home paths (Dylint `abs_home_path`). **Feasibility:** Heuristic.
35. **Invisible Unicode characters** – Borrow Sonar RSPEC-2479 to avoid spoofing. **Feasibility:** Heuristic.

## Input Validation & Injection

36. **SQL injection** – Track untrusted input to `diesel::sql_query` and raw SQL builders. **Feasibility:** Advanced.
37. **Path traversal** – Detect tainted paths passed to filesystem APIs. **Feasibility:** Advanced.
38. **Regular expression injection** – Taint to `Regex::new` or `RegexBuilder`. **Feasibility:** MIR dataflow.
39. **Server-side request forgery** – Taint external URLs used in HTTP clients. **Feasibility:** Advanced.
40. **Command injection (process::Command)** *(shipped)* – Track execution of external commands. **Feasibility:** Heuristic.
41. **Command argument taint** – Ensure user input passed to `Command::arg` is sanitized. **Feasibility:** MIR dataflow.
42. **YAML deserialization of untrusted data** – Guard `serde_yaml::from_*`. **Feasibility:** Advanced.
43. **TOML/JSON deserialization** – Similar to YAML for other formats. **Feasibility:** Advanced.
44. **bincode / postcard deserialization** – Highlight binary format parsing on tainted input. **Feasibility:** Advanced.
45. **Regex denial-of-service** – Flag untrusted patterns compiled with catastrophic backtracking. **Feasibility:** Advanced.
46. **Template injection in web responses** – Taint tracking into response body builders. **Feasibility:** Advanced.

## Concurrency & Async

47. **Non-thread-safe calls in tests** – Dylint parity for `#[test]` using non-`Send` APIs. **Feasibility:** Heuristic.
48. **Unsafe `Send` across async boundaries** – Detect `Send` requirements violated in futures. **Feasibility:** Advanced.
49. **Await while holding span guard** – Avoid locking instrumentation across `.await`. **Feasibility:** Advanced.
50. **Mutex guard dropped prematurely** – Sonar RSPEC-7450. **Feasibility:** Advanced.
51. **panic! inside Drop** – Prevent unwinding in destructors. **Feasibility:** Heuristic.
52. **unwrap in Drop/Poll** – Avoid `unwrap()` in critical lifecycle methods. **Feasibility:** Heuristic.
53. **Await missing in async return** – Sonar RSPEC-7413 parity. **Feasibility:** Heuristic.

## Resource Management & DoS

54. **Uncontrolled allocation size** – Taint to `Vec::with_capacity` etc. **Feasibility:** Advanced.
55. **Unbounded read_to_end** – Detect reading arbitrary streams into memory. **Feasibility:** Advanced.
56. **I/O buffers not fully processed** – Sonar RSPEC-7419 parity. **Feasibility:** Advanced.
57. **Lines from stdin not trimmed** – Sonar RSPEC-7441, to avoid injection. **Feasibility:** Heuristic.
58. **Infinite iterators without termination** – Sonar RSPEC-7464; potential DoS. **Feasibility:** Heuristic.

## Configuration & Platform Issues

59. **Unix permissions not octal** – Sonar RSPEC-7448. **Feasibility:** Heuristic.
60. **OpenOptions inconsistent flags** – Sonar RSPEC-7447. **Feasibility:** Heuristic.
61. **File operations on tainted paths** – Strengthen path traversal detection (#37). **Feasibility:** Advanced.
62. **env::var literals in code** – Dylint `env_literal`; ensures configuration via constants. **Feasibility:** Heuristic.
63. **crate-wide allow attributes** – Dylint `crate_wide_allow`; highlight disabled lint coverage. **Feasibility:** Heuristic.

## Web & Framework Specific

64. **warp filters leaking request body** – Ensure request body not logged verbatim. **Feasibility:** Advanced.
65. **actix-web responses with interpolated input** – Taint to HTML body formatting. **Feasibility:** Advanced.
66. **Axum extractors without validation** – Flag `Form`/`Json` usage without explicit validation. **Feasibility:** Advanced.

## Testing & Infrastructure Hygiene

67. **Commented out code** – Dylint `commented_out_code`; maintain clean code for analysis clarity. **Feasibility:** Heuristic.
68. **Dead stores in arrays** – Dylint `basic_dead_store`; prevent stale security-critical state. **Feasibility:** Heuristic.
69. **Non-local effect before panic in tests** – Variation of Dylint `non_local_effect_before_error_return`. **Feasibility:** Advanced.
70. **Misordered assert_eq arguments** – Dylint `assert_eq_arg_misordering`; avoids misleading failures. **Feasibility:** Heuristic.
71. **Try operator on io::Result** – Dylint `try_io_result`; enforce explicit error handling. **Feasibility:** Heuristic.
72. **Overscoped allow attributes** – Dylint `overscoped_allow`; keep lints active. **Feasibility:** Heuristic.
73. **Local RefCell usage** – Dylint `local_ref_cell`; prefer safer concurrency primitives. **Feasibility:** Heuristic.
74. **Unnecessary borrow_mut** – Dylint `unnecessary_borrow_mut`; reduce RefCell churn. **Feasibility:** Heuristic.
75. **Non-thread-safe call in async context** – Extend Dylint test lint to async tasks. **Feasibility:** Advanced.

## External Tool Findings – Clippy

76. **OpenOptions missing truncate** *(quick win)* – Lift Clippy `suspicious_open_options`; prevent stale file contents when creating writable files without `truncate(true)` or `append(true)`. **Signal:** Builder chains on `std::fs::OpenOptions` that set `write(true)` and `create(true)` but never set truncate/append. **Feasibility:** Heuristic.
77. **Command argument concatenation** *(quick win)* – From Clippy `suspicious_command_arg_space`; catch single string arguments containing spaces passed to `Command::arg`/`args` which bypass proper shell escaping. **Signal:** String literal (or obvious constant) with embedded whitespace passed to process builders. **Feasibility:** Heuristic.
78. **Underscore-assigned lock guard** – Clippy `let_underscore_lock`; disallow binding mutex/RwLock guards to `_` which immediately drops the lock. **Signal:** Pattern bindings like `let _ = mutex.lock()` for locking APIs. **Feasibility:** Heuristic.
79. **Absolute component in join** – Clippy `join_absolute_paths`; flag `Path::join`/`PathBuf::push` receiving an absolute path segment that nullifies the sanitized base path. **Signal:** Call where the joined argument is known absolute (literal or `Path::is_absolute`-provable). **Feasibility:** MIR dataflow.
80. **set_readonly(false) permission downgrade** *(shipped — RUSTCOLA028)* – Clippy `permissions_set_readonly_false`; surface calls making files world-writable on Unix. **Signal:** Direct invocation of `std::fs::Permissions::set_readonly(false)`. **Feasibility:** Heuristic.
81. **Spawned child without wait** – Clippy `zombie_processes`; ensure every spawned `std::process::Child` is awaited or dropped via `wait()`. **Signal:** Track `Command::spawn` results to verify a subsequent unconditional `wait()`/`status()`. **Feasibility:** MIR dataflow.

## External Tool Findings – Rudra

82. **Unsafe closure panic guard** – Flag unsafe routines that duplicate ownership via `ptr::read`/`copy_nonoverlapping` and then invoke user-supplied closures or trait callbacks without shielding against panics (Rudra’s panic-safety bug class). **Signal:** In an `unsafe` block, raw pointer reads followed by a call to a higher-order argument without surrounding `catch_unwind` or restoring ownership before the call. **Feasibility:** Advanced.
83. **Borrow contract invariant** – Detect higher-order code that assumes repeated trait method calls (e.g., `Borrow::borrow`, `Deref::deref`) return the same reference and cache raw pointers across calls, risking aliasing bugs (Rudra higher-order invariant). **Signal:** MIR dataflow proving a pointer derived from a trait object is stored and reused after an intervening call that may mutate the source. **Feasibility:** Advanced.
84. **Generic Send/Sync bounds** *(quick win)* – Highlight `unsafe impl Send/Sync for Foo<T>` that omit trait bounds ensuring `T: Send`/`T: Sync`, echoing Rudra’s Send/Sync variance findings. **Signal:** Pattern match on unsafe impl blocks where generic parameters appear without the matching auto-trait constraint. **Feasibility:** Heuristic.

## External Tool Findings – MirChecker

85. **Unchecked index arithmetic panic** – Surface integer arithmetic that feeds slice/array indexing without proving the offset fits the container, mirroring MirChecker’s runtime panic detections. **Signal:** MIR range analysis spotting `len - offset`, `offset + start`, or scaled loop counters used as indices absent dominating `<=` guards. **Feasibility:** MIR dataflow.
86. **Unsafe deallocation of borrowed storage** – Catch lifetime-corruption patterns where unsafe code drops or frees memory reachable through active borrows (MirChecker lifetime corruption bugs). **Signal:** Track raw pointers derived from references that flow into `free`, `drop_in_place`, or manual RAII teardown before the borrow scope ends. **Feasibility:** Advanced.
87. **Division by unchecked denominator** – Warn when arithmetic divisions/modulos consume untrusted or data-dependent denominators without checked zero guards, preventing MirChecker’s reported panic class. **Signal:** Identify denominators sourced from inputs or arithmetic expressions lacking preceding `!= 0` / `checked_div` validation. **Feasibility:** MIR dataflow.

## External Tool Findings – FFIChecker

88. **FFI buffer leak on early return** – Ensure FFI marshalling code that allocates heap buffers (e.g., `Vec::with_capacity`, `Box::into_raw`) installs defer-style cleanup when `?` propagation can short-circuit before freeing (FFIChecker memory-corruption findings). **Signal:** In `extern`/FFI helpers, detect manual allocation whose pointer escapes while `?`-based error paths exit prior to cleanup. **Feasibility:** MIR dataflow.
89. **FFI panic-safe drop guard** – Flag unsafe FFI stubs that leave partially initialised buffers or state inconsistent if a Rust panic unwinds across the boundary, echoing FFIChecker’s exception-safety bugs. **Signal:** Look for `unsafe` blocks preparing raw structures without `Drop` guards or `catch_unwind` before invoking external code that may unwind. **Feasibility:** Advanced.
90. **Allocator mismatch across FFI** *(quick win)* – Prevent mixing Rust allocators with `libc::free`/foreign deallocators on pointers created by `Box`/`CString`, matching FFIChecker’s mixed-allocation UB class. **Signal:** Detect raw pointers produced by Rust allocation APIs later freed via non-matching deallocators (or vice versa). **Feasibility:** Heuristic.

## External Tool Findings – Cargo Audit

91. **RustSec unsound dependency** *(quick win)* – Mirror `cargo audit` informational warnings by flagging dependency versions listed in the RustSec DB as `informational = "unsound"`, so consumers patch or sandbox them. **Signal:** Cross-reference `Cargo.lock` packages against curated RustSec unsound advisories and alert even when builds succeed. **Feasibility:** Heuristic.
92. **Yanked crate version in lockfile** – Surface dependencies that `cargo audit` would mark as yanked, prompting upgrades before the registry drops them. **Signal:** Enrich lockfile analysis with crates.io index metadata (or local cache) to report yanked versions during review. **Feasibility:** Heuristic.
93. **Release binaries missing auditable metadata** – Encourage projects shipping binaries to embed `cargo auditable` metadata so `cargo audit bin` can produce complete reports. **Signal:** Inspect release automation for `cargo auditable` integration (feature flag, build script, or CI job) and suggest adoption when missing. **Feasibility:** Heuristic. **Severity:** Informational (policy) – highlight for teams that opt into supply-chain attestation profiles while keeping it ignorable for others.

## Additional CodeQL Candidates (Apr 2024 sweep)

94. **Cookie without `Secure` attribute** – Surface builders from the `cookie` or framework helpers where the `secure` flag is absent or explicitly false, mirroring CodeQL `rust/insecure-cookie` (severity 7.5). **Signal:** Track cookie builder instances and ensure a call to `secure(true)`/`set_secure(true)` dominates the use site. **Feasibility:** MIR dataflow.
95. **`#[ctor]`/`#[dtor]` invoking std APIs** – Flag functions annotated with `#[ctor]` or `#[dtor]` that call into `std::` APIs before `main`, aligning with CodeQL `rust/ctor-initialization`. **Signal:** Walk macro-expanded bodies for call expressions whose fully qualified path begins with `std::`. **Feasibility:** Heuristic.

## RustRover Inspectopedia Candidates

96. **Unsafe CString pointer use** – JetBrains [Inspectopedia: Unsafe CString pointer](https://www.jetbrains.com/help/inspectopedia/RsCStringPointer.html) flags call chains like `CString::new(...).unwrap().as_ptr()` where the temporary is dropped before the pointer escapes, creating dangling references. **Signal:** Recognize `CString::new` results whose `.as_ptr()` return value is used outside the lifetime of the owning `CString` (stored, returned, or passed onward) without preserving the backing allocation. **Feasibility:** Heuristic.
97. **Blocking sleep inside async** – JetBrains [Inspectopedia: Blocking `sleep` function cannot be used in `async` context](https://www.jetbrains.com/help/inspectopedia/RsSleepInsideAsyncFunction.html) highlights `std::thread::sleep` and similar blocking calls inside async functions that can stall executors and enable denial-of-service conditions. **Signal:** Flag synchronous sleep APIs invoked within `async fn` bodies, futures, or sections awaiting completion without yielding back to the runtime. **Feasibility:** Heuristic.

## Additional Dylint Candidates (Oct 2025 sweep)

98. **Serde `serialize_*` length mismatch** – Trail of Bits Dylint [wrong_serialize_struct_arg](https://trailofbits.github.io/dylint/examples/#general) ensures `serialize_struct`/`serialize_tuple*` `len` arguments match the number of `serialize_field`/`serialize_element` calls, preventing receivers from misparsing truncated data. **Signal:** Count serialization helper invocations under each Serde serializer call and flag mismatched arity in the same block. **Feasibility:** MIR dataflow.

## Snyk Rust coverage follow-ups (Nov 2025)

99. **Overly permissive CORS allowlist** – Extend Snyk’s `TooPermissiveCors` finding for Rust web stacks by flagging `CorsLayer::new()` / `warp::cors()` chains that end up with `allow_origin("*")`, wildcard `AllowOrigin::any()`, or regexes that effectively accept every origin. Unrestricted origins enable credential theft when browsers happily forward cookies or Authorization headers to attacker-controlled sites. Snyk’s `rust-vulnerable-apps` repo demonstrates the issue in `cors/cors_003_bad_axum_tower_http/src/main.rs`, where `CorsLayer::new().allow_origin("*")` is annotated as the vulnerability hotspot and allows a malicious page to read JSON responses ([Snyk rust-vulnerable-apps](https://raw.githubusercontent.com/snyk/rust-vulnerable-apps/main/cors/cors_003_bad_axum_tower_http/src/main.rs)). **Signal:** Heuristic – inspect CORS builder calls from `tower_http::cors`, `warp::cors`, and similar abstractions for wildcard origins or trivially bypassable pattern checks. **Feasibility:** Heuristic.

100. **Observable timing-based secret comparison** – Mirror Snyk Code’s `Observable Timing Discrepancy` rule for Rust (`CWE-208`) noted in the official rule index ([Snyk Code rules table](https://github.com/snyk/user-docs/blob/main/docs/scan-with-snyk/snyk-code/snyk-code-security-rules/README.md)). Timing leaks surface when credential checks or signature verifications return early on the first mismatching byte rather than using constant-time comparison. **Signal:** MIR dataflow – detect equality checks, `starts_with`, byte-wise loops, or guard clauses inside auth/crypto helpers that branch or return as soon as a mismatch is found on attacker-influenced data, and prefer flagging when the routine deals with secrets (naming heuristics like `token`, `secret`, `hmac`). **Feasibility:** MIR dataflow.

101. **World-writable file permission defaults** *(shipped — RUSTCOLA029)* – Snyk’s Rust rule set also covers `Insecure File Permissions` for Rust (`CWE-732`) in the same security rule index ([Snyk Code rules table](https://github.com/snyk/user-docs/blob/main/docs/scan-with-snyk/snyk-code-security-rules/README.md)). Replicate that coverage by flagging calls that deliberately create or relax permissions to `0o77x`, such as `PermissionsExt::set_mode(0o777)`, `OpenOptionsExt::mode(0o777)`, or helper wrappers that pass world-writable flags on Unix targets. Highlight builder chains that combine `create(true)`/`write(true)` with explicit `mode` arguments granting group/other write bits. **Signal:** Heuristic – search for suspicious octal literals (`0o666`, `0o777`) or `set_readonly(false)` in proximity to file creation, and on Windows look for `SecurityDescriptor` ACLs granting `GENERIC_ALL` to `Everyone`. **Feasibility:** Heuristic.

## Checkmarx SAST coverage follow-ups (Aug 2025)

102. **AWS S3 access without resource scoping** – Mirror Checkmarx Engine Pack 9.6.4’s `Rust_Medium_Threat.Unrestricted_*_S3` queries by detecting AWS SDK calls that perform `list_objects`, `delete_objects`, or `put_object` against buckets where the bucket or key prefix comes directly from user input or uses wildcards like `"*"`. These operations can exfiltrate or destroy arbitrary data when exposed endpoints forward attacker-controlled paths to S3. **Signal:** MIR dataflow – taint the `bucket`, `key`, or `prefix` arguments on `aws_sdk_s3::Client` calls and flag flows that lack validation or confinement to an allowlist. **Feasibility:** MIR dataflow.
103. **Connection strings with empty or hardcoded passwords** – Checkmarx adds `Empty_Password_In_Connection_String` and `Hardcoded_Password_in_Connection_String` detections for Rust. We can surface similar cases by flagging database or message-broker DSNs embedded in code or configuration with `password=` segments set to empty strings or literal secrets, nudging teams toward pulling credentials from secret stores. **Signal:** Heuristic – search string literals that look like connection URIs (`postgres://`, `mysql://`, `redis://`, `amqp://`) and inspect the password component for emptiness or obvious literals. **Feasibility:** Heuristic.
104. **Missing password field masking in web forms** – Checkmarx’s `Rust_Low_Visibility.Missing_Password_Field_Masking` highlights UI paths that echo secrets. For Rust web frameworks (Axum, Actix), audit templating and form builders for inputs representing passwords that render back to clients without obfuscation (e.g., `type="text"`, or displaying the submitted value in flash messages). **Signal:** Heuristic – identify HTML templates or server responses that interpolate variables tagged or named like `password`, `pass`, `token`, and ensure they’re either redacted or rendered with `type="password"`. **Feasibility:** Heuristic.

## RustSec advisory coverage follow-ups (Oct 2025)

105. **Protocol length truncation in SQL clients** – RustSec advisories [RUSTSEC-2024-0363](https://rustsec.org/advisories/RUSTSEC-2024-0363.html) (SQLx) and [RUSTSEC-2024-0365](https://rustsec.org/advisories/RUSTSEC-2024-0365.html) show that casting request payload lengths to 32-bit integers lets >4 GiB inputs overflow PostgreSQL protocol frames and smuggle additional commands. Spot builder code that serializes protocol messages and downcasts `usize`/`u64` lengths to smaller integer widths without bounds checks, especially right before writing to network buffers. **Signal:** Heuristic – flag `as i32`/`as u32` casts or `.try_into::<u32>()` style conversions on variables named like `len`, `size`, or `payload_len`, and highlight when the narrowed value flows into serialization sinks such as `BufMut::put_*` / `write_*` helpers unless dominated by range assertions. **Feasibility:** Heuristic. **Prototype:** `detect_truncating_len_casts` in `mir-extractor/src/prototypes.rs`; research notes in `docs/research/rustsec-length-truncation-prototype.md`.
106. **Tokio broadcast with !Sync payloads** – [RUSTSEC-2025-0023](https://rustsec.org/advisories/RUSTSEC-2025-0023.html) documents unsoundness when `tokio::sync::broadcast` clones values concurrently while only requiring `Send`. Encourage safer usage by warning when the payload type lacks an obvious `Sync` bound (e.g., channels instantiated for `Rc`, `RefCell`, or other single-thread types) or when custom broadcast wrappers forward `Send` but not `Sync` requirements. **Signal:** Heuristic – inspect `broadcast::channel` constructors (including `Sender`/`Receiver` helpers) for `!Sync` markers, propagate taint through reassignments, and report downstream `send`/`subscribe` sites that reuse the tainted handle. **Feasibility:** Heuristic. **Prototype:** `detect_broadcast_unsync_payloads` in `mir-extractor/src/prototypes.rs`; research notes in `docs/research/rustsec-broadcast-unsync-prototype.md`.
107. **Trusting remote Content-Length for allocations** – [RUSTSEC-2025-0015](https://rustsec.org/advisories/RUSTSEC-2025-0015.html) shows `web-push` DoS when clients preallocate buffers using untrusted `Content-Length`. Generalize by looking for HTTP client code that reads `Response::content_length()` (or header lookups) to size `Vec::with_capacity`/`BytesMut::with_capacity` without upper bounds or streaming safeguards. **Signal:** MIR dataflow – track tainted header-derived lengths (including `HeaderName::from_static("content-length")`, `HeaderValue::from_static`, `from_bytes(b"content-length")`, and `CONTENT_LENGTH` constants) into allocation APIs and require explicit clamping (`min`, config limits) or fall back to chunked streaming. **Feasibility:** MIR dataflow. **Prototype:** `mir-extractor/src/prototypes.rs` with notes in `docs/research/rustsec-content-length-prototype.md` (now handling tuple/Option flows and range guards).

## Analysis Infrastructure

108. **Add HIR extraction pipeline** – Introduce an optional HIR capture step alongside MIR so rules that require richer type/trait context, attribute inspection, or macro expansion metadata can operate without reimplementing `rustc` queries, giving us the best balance of high-level Rust semantics with manageable complexity. **Signal:** Compiler integration – invoke `rustc_interface` to materialize `TyCtxt`, persist a structured HIR snapshot, and correlate it with existing MIR artifacts. **Feasibility:** Advanced.

---

This list is a living document. As rules graduate from “backlog” into the shipping rule set, annotate them with *(shipped)* and link to the implementation.
