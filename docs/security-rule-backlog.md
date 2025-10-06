# Security Rule Backlog

This backlog consolidates security-focused rule ideas for Rust-cola drawn from Semgrep, GitHub CodeQL, SonarSource/SonarQube, and Trail of Bits' Dylint examples. Each entry captures the rationale, the primary analysis signal we expect to leverage, and a rough feasibility tier.

Feasibility legend:

- **Heuristic** – String or signature matching with minimal context.
- **MIR dataflow** – Requires MIR-aware taint tracking or control/data-flow reasoning.
- **Advanced** – Demands deeper semantic modelling (lifetimes, aliasing, interprocedural analysis) or significant new infrastructure.

## Memory Safety & Unsafe Usage

1. **Box::into_raw escape** *(shipped)* – Detect raw pointer escapes via `Box::into_raw`. **Feasibility:** Heuristic.
2. **std::mem::transmute usage** *(shipped)* – Flag calls to `std::mem::transmute`. **Feasibility:** Heuristic.
3. **Vec::set_len misuse** – Identify `Vec::set_len` when the vector is not fully initialized. **Feasibility:** MIR dataflow.
4. **MaybeUninit::assume_init before initialization** – Detect `assume_init` without a preceding `write`. **Feasibility:** MIR dataflow.
5. **mem::uninitialized / mem::zeroed** *(quick win)* – Flag usage of deprecated zero-init APIs on non-zero types. **Feasibility:** Heuristic.
6. **Dangling pointer use-after-free** – Ensure no access after `drop` or reallocation. **Feasibility:** Advanced.
7. **Access of invalid pointer** – Catch derefs of null or misaligned pointers. **Feasibility:** Advanced.
8. **Unsafe Send/Sync impls** – Highlight `unsafe impl Send/Sync` without safety commentary. **Feasibility:** Heuristic (doc-aware).
9. **static mut globals** – Warn about mutable statics that break thread safety. **Feasibility:** Heuristic.
10. **NonNull::new_unchecked misuse** – Ensure null checks before `new_unchecked`. **Feasibility:** Heuristic.
11. **mem::forget on guards** – Catch forgetting RAII guards that release locks/resources. **Feasibility:** MIR dataflow.
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
25. **OpenSSL VerifyNone** – Detect `set_verify(VerifyNone)`. **Feasibility:** Heuristic.
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
80. **set_readonly(false) permission downgrade** *(quick win)* – Clippy `permissions_set_readonly_false`; surface calls making files world-writable on Unix. **Signal:** Direct invocation of `std::fs::Permissions::set_readonly(false)`. **Feasibility:** Heuristic.
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
93. **Release binaries missing auditable metadata** – Encourage projects shipping binaries to embed `cargo auditable` metadata so `cargo audit bin` can produce complete reports. **Signal:** Inspect release automation for `cargo auditable` integration (feature flag, build script, or CI job) and suggest adoption when missing. **Feasibility:** Heuristic.

---

This list is a living document. As rules graduate from “backlog” into the shipping rule set, annotate them with *(shipped)* and link to the implementation.
