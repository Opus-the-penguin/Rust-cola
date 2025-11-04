# Phase 1 Rule Priorities

Quick-win rules that can be implemented with heuristic (text pattern matching) approaches.

## Scoring Methodology

Each rule rated on:
- **Impact**: Security severity (High=3, Medium=2, Low=1)
- **Difficulty**: Implementation complexity (Easy=3, Medium=2, Hard=1)
- **Priority Score**: Impact × Difficulty

## Top 10 Quick Wins

### 1. **OpenOptions Missing Truncate** (Score: 9)
- **Rule ID**: RUSTCOLA032 (planned)
- **Impact**: High (3) - Stale data disclosure
- **Difficulty**: Easy (3) - Builder pattern detection
- **Pattern**: `OpenOptions::new().write(true).create(true)` without `.truncate(true)` or `.append(true)`
- **Example**:
  ```rust
  // BAD: Creates file but doesn't truncate, leaving old data
  OpenOptions::new().write(true).create(true).open("secrets.txt")
  
  // GOOD: Explicitly truncates
  OpenOptions::new().write(true).create(true).truncate(true).open("secrets.txt")
  ```
- **References**: Clippy `suspicious_open_options`, Backlog #76

### 2. **Allocator Mismatch Across FFI** (Score: 9)
- **Rule ID**: RUSTCOLA033 (planned)
- **Impact**: High (3) - Memory corruption, UB
- **Difficulty**: Easy (3) - Pattern matching on allocation/deallocation pairs
- **Pattern**: `Box::into_raw` / `CString::into_raw` followed by `libc::free`, or vice versa
- **Example**:
  ```rust
  // BAD: Rust allocator → libc deallocator
  let ptr = Box::into_raw(Box::new(42));
  unsafe { libc::free(ptr as *mut c_void); }  // UB!
  
  // GOOD: Matching allocators
  let ptr = Box::into_raw(Box::new(42));
  unsafe { drop(Box::from_raw(ptr)); }
  ```
- **References**: FFIChecker findings, Backlog #90

### 3. **Generic Send/Sync Without Bounds** (Score: 9)
- **Rule ID**: RUSTCOLA034 (planned)
- **Impact**: High (3) - Thread safety violations
- **Difficulty**: Easy (3) - AST pattern on unsafe impl
- **Pattern**: `unsafe impl Send for Foo<T>` without `where T: Send`
- **Example**:
  ```rust
  // BAD: Missing bounds
  unsafe impl<T> Send for MyWrapper<T> {}
  
  // GOOD: Proper bounds
  unsafe impl<T: Send> Send for MyWrapper<T> {}
  ```
- **References**: Rudra findings, Backlog #84, RUSTCOLA015 precedent

### 4. **Unsafe CString Pointer Use** (Score: 9)
- **Rule ID**: RUSTCOLA035 (planned)
- **Impact**: High (3) - Dangling pointer use
- **Difficulty**: Easy (3) - Call chain pattern
- **Pattern**: `CString::new(...).unwrap().as_ptr()` where temporary drops
- **Example**:
  ```rust
  // BAD: CString dropped before use
  let ptr = CString::new("hello").unwrap().as_ptr();
  unsafe { libc::puts(ptr); }  // Dangling!
  
  // GOOD: Keep CString alive
  let cstr = CString::new("hello").unwrap();
  unsafe { libc::puts(cstr.as_ptr()); }
  ```
- **References**: RustRover Inspectopedia, Backlog #96

### 5. **Blocking Sleep in Async** (Score: 9)
- **Rule ID**: RUSTCOLA036 (planned)
- **Impact**: High (3) - Executor starvation, DoS
- **Difficulty**: Easy (3) - Detect `std::thread::sleep` in `async fn`
- **Pattern**: `thread::sleep` inside async function body
- **Example**:
  ```rust
  // BAD: Blocks executor
  async fn handler() {
      std::thread::sleep(Duration::from_secs(1));  // DoS!
  }
  
  // GOOD: Use async sleep
  async fn handler() {
      tokio::time::sleep(Duration::from_secs(1)).await;
  }
  ```
- **References**: RustRover Inspectopedia, Backlog #97

### 6. **Overly Permissive CORS** (Score: 8)
- **Rule ID**: RUSTCOLA037 (planned)
- **Impact**: High (3) - Credential theft, CSRF
- **Difficulty**: Medium (2.5) - Framework-specific patterns
- **Pattern**: `.allow_origin("*")` or `AllowOrigin::any()`
- **Example**:
  ```rust
  // BAD: Allows all origins
  let cors = CorsLayer::new().allow_origin("*");
  
  // GOOD: Explicit allowlist
  let cors = CorsLayer::new()
      .allow_origin("https://trusted.example.com".parse::<HeaderValue>().unwrap());
  ```
- **References**: Snyk rust-vulnerable-apps, Backlog #99

### 7. **repr(packed) Field References** (Score: 8)
- **Rule ID**: RUSTCOLA038 (planned)
- **Impact**: High (3) - Undefined behavior (misaligned access)
- **Difficulty**: Medium (2.5) - Detect `&packed.field` patterns
- **Pattern**: Taking references to fields of `#[repr(packed)]` structs
- **Example**:
  ```rust
  #[repr(packed)]
  struct Packed { x: u32 }
  
  // BAD: Creates misaligned reference
  let p = Packed { x: 42 };
  let r = &p.x;  // UB!
  
  // GOOD: Copy the value
  let val = { p.x };  // No reference
  ```
- **References**: Backlog #12

### 8. **Hard-coded Cryptographic Keys** (Score: 6)
- **Rule ID**: RUSTCOLA039 (planned)
- **Impact**: High (3) - Complete security bypass
- **Difficulty**: Medium (2) - Taint tracking to crypto APIs
- **Pattern**: Literal byte arrays passed to key derivation or cipher initialization
- **Example**:
  ```rust
  // BAD: Embedded key
  let key = b"my_secret_key_123456789012345";
  let cipher = Aes256Gcm::new(key.into());
  
  // GOOD: Load from secure storage
  let key = load_from_env_or_keychain();
  let cipher = Aes256Gcm::new(key);
  ```
- **References**: Backlog #21

### 9. **Connection Strings with Empty Passwords** (Score: 6)
- **Rule ID**: RUSTCOLA040 (planned)
- **Impact**: High (3) - Unauthorized access
- **Difficulty**: Medium (2) - Regex on connection string literals
- **Pattern**: DSN with `password=` or `:@` (empty)
- **Example**:
  ```rust
  // BAD: Empty password
  let dsn = "postgres://user:@localhost/db";
  
  // GOOD: Use environment variable
  let dsn = format!("postgres://user:{}@localhost/db", env::var("DB_PASS")?);
  ```
- **References**: Checkmarx Engine Pack, Backlog #103

### 10. **Non-HTTPS URLs** (Score: 6)
- **Rule ID**: RUSTCOLA041 (planned)
- **Impact**: Medium (2) - MITM, data exposure
- **Difficulty**: Easy (3) - String literal detection
- **Pattern**: `http://` URLs in HTTP client calls
- **Example**:
  ```rust
  // BAD: Cleartext
  reqwest::get("http://api.example.com/secrets").await?;
  
  // GOOD: Encrypted
  reqwest::get("https://api.example.com/secrets").await?;
  ```
- **References**: Backlog #26

## Next Tier (11-20)

11. **Weak Ciphers (DES/RC4)** - Impact: High, Difficulty: Easy
12. **`panic!` in Drop** - Impact: High, Difficulty: Easy
13. **`unwrap` in Drop/Poll** - Impact: Medium, Difficulty: Easy
14. **Unix Permissions Not Octal** - Impact: Low, Difficulty: Easy (Sonar RSPEC-7448)
15. **OpenOptions Inconsistent Flags** - Impact: Medium, Difficulty: Easy (Sonar RSPEC-7447)
16. **env::var Literals** - Impact: Low, Difficulty: Easy (Dylint)
17. **Crate-wide Allow Attributes** - Impact: Low, Difficulty: Easy (Dylint)
18. **Commented Out Code** - Impact: Low, Difficulty: Easy (Dylint)
19. **Dead Stores in Arrays** - Impact: Low, Difficulty: Easy (Dylint)
20. **Misordered assert_eq Arguments** - Impact: Low, Difficulty: Easy (Dylint)

## Implementation Order

Week 2 Focus (3-5 rules):
1. RUSTCOLA032 - OpenOptions missing truncate
2. RUSTCOLA033 - Allocator mismatch FFI
3. RUSTCOLA034 - Generic Send/Sync bounds

Week 3 Focus (3-5 rules):
4. RUSTCOLA035 - Unsafe CString pointer
5. RUSTCOLA036 - Blocking sleep in async
6. RUSTCOLA037 - Overly permissive CORS

---

**Last Updated**: January 2025
