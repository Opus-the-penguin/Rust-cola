# RUSTCOLA052: Local RefCell Usage

## Problem

Using `RefCell<T>` for purely local mutable state adds unnecessary complexity and runtime overhead. `RefCell` is designed for **interior mutability** in specific scenarios like:

- Shared ownership with `Rc<RefCell<T>>`
- Trait methods that need `&self` but must mutate
- Callback closures with shared state
- Graph structures and complex data structures

When you have local state in a single function, a plain `mut` variable is:
- **Simpler**: No `borrow()` or `borrow_mut()` calls
- **Safer**: Compile-time borrow checking instead of runtime panics
- **Faster**: No runtime borrow tracking overhead
- **Clearer**: Intent is obvious

## Example

### ❌ Problematic (unnecessary RefCell)

```rust
pub fn count_items(items: &[i32]) -> i32 {
    let counter = RefCell::new(0);
    
    for item in items {
        if *item > 0 {
            *counter.borrow_mut() += 1;  // Runtime borrow check!
        }
    }
    
    *counter.borrow()  // Can panic if still borrowed
}
```

**Problems:**
- Runtime borrow checking overhead
- Can panic if borrow rules violated
- Verbose with `.borrow()` and `.borrow_mut()`
- Confusing for readers (why RefCell here?)

### ✅ Better (plain mut variable)

```rust
pub fn count_items(items: &[i32]) -> i32 {
    let mut counter = 0;
    
    for item in items {
        if *item > 0 {
            counter += 1;  // Simple, safe, fast
        }
    }
    
    counter
}
```

**Benefits:**
- Compile-time borrow checking
- No runtime overhead
- Clear and simple
- Can't panic from borrow violations

## When RefCell IS Appropriate

### ✅ Shared ownership with Rc

```rust
use std::rc::Rc;
use std::cell::RefCell;

pub struct Node {
    value: i32,
    children: Vec<Rc<RefCell<Node>>>,  // Multiple owners, need mutation
}
```

### ✅ Interior mutability for trait implementations

```rust
pub trait Cache {
    fn get(&self, key: &str) -> Option<String>;  // Immutable interface
}

pub struct InMemoryCache {
    data: RefCell<HashMap<String, String>>,  // Need to mutate with &self
}

impl Cache for InMemoryCache {
    fn get(&self, key: &str) -> Option<String> {
        self.data.borrow_mut().entry(key.to_string())
            .or_insert_with(|| expensive_computation(key))
            .clone()
    }
}
```

### ✅ Closures with shared mutable state

```rust
fn process_with_callback<F>(items: &[i32], mut callback: F) 
where 
    F: FnMut(i32)
{
    for &item in items {
        callback(item);
    }
}

pub fn sum_items(items: &[i32]) -> i32 {
    let sum = RefCell::new(0);
    
    process_with_callback(items, |x| {
        *sum.borrow_mut() += x;  // Closure needs to mutate captured variable
    });
    
    sum.into_inner()
}
```

## Detection

This rule detects functions that:
1. Create a `RefCell::new()` within the function
2. Call `borrow()` or `borrow_mut()` on it in the same function
3. Don't have patterns suggesting shared ownership or trait constraints

## How to Fix

Replace `RefCell<T>` with `let mut` variable:

1. `RefCell::new(value)` → `let mut var = value`
2. `*cell.borrow_mut() = x` → `var = x`
3. `*cell.borrow_mut() += x` → `var += x`
4. `*cell.borrow()` → `var`

## Parity

- Dylint: `local_ref_cell`
- Clippy: No equivalent

## Severity

**Low** - This is a code quality/performance issue. RefCell still works correctly, but adds unnecessary complexity and risk.
