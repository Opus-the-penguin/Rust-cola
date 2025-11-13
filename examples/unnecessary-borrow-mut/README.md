# Unnecessary borrow_mut Test Cases

This example demonstrates detection of unnecessary `RefCell::borrow_mut()` calls where `borrow()` would suffice.

## The Problem

`RefCell` provides interior mutability through runtime-checked borrowing. It offers two methods:
- `borrow()` - returns `Ref<T>` for read-only access
- `borrow_mut()` - returns `RefMut<T>` for mutable access

Using `borrow_mut()` when you only need read-only access:
1. **Adds unnecessary overhead** - mutable borrows have stricter runtime checks
2. **Increases panic risk** - can't have any other borrow (mutable or immutable) active
3. **Obscures intent** - readers assume mutation will occur
4. **Reduces performance** - prevents concurrent immutable borrows

## Common Mistakes

### Pattern 1: Read-only access with borrow_mut()

```rust
// WRONG: Using borrow_mut() just to read
let data = RefCell::new(42);
let borrowed = data.borrow_mut();
println!("{}", *borrowed);  // Only reading!

// CORRECT: Use borrow() for read-only access
let borrowed = data.borrow();
println!("{}", *borrowed);
```

### Pattern 2: Checking conditions with borrow_mut()

```rust
// WRONG: Using borrow_mut() to check a condition
let data = RefCell::new(vec![1, 2, 3]);
let borrowed = data.borrow_mut();
if borrowed.len() > 0 {  // Only reading length
    // ...
}

// CORRECT: Use borrow() for inspection
let borrowed = data.borrow();
if borrowed.len() > 0 {
    // ...
}
```

### Pattern 3: Iteration without mutation

```rust
// WRONG: Using borrow_mut() to iterate
let data = RefCell::new(vec![1, 2, 3]);
let borrowed = data.borrow_mut();
for item in borrowed.iter() {  // Read-only iteration
    println!("{}", item);
}

// CORRECT: Use borrow() for read-only iteration
let borrowed = data.borrow();
for item in borrowed.iter() {
    println!("{}", item);
}
```

## When borrow_mut() IS Necessary

```rust
// Modifying values
let mut borrowed = data.borrow_mut();
borrowed.push(4);
borrowed[0] = 10;
borrowed.clear();

// Sorting or reversing
borrowed.sort();
borrowed.reverse();

// Extending or draining
borrowed.extend(vec![5, 6]);
borrowed.drain(..);
```

## Detection Strategy

RUSTCOLA057 uses a heuristic approach:

1. **Identify borrow_mut() calls**: Look for `RefCell::borrow_mut()` in MIR
2. **Check for mutation patterns**: Look for common mutation operations:
   - Assignments to fields
   - Calls to mutating methods (`push`, `insert`, `clear`, `sort`, etc.)
   - Dereferencing and writing
3. **Flag if missing**: Report when borrow_mut() lacks clear mutation

## Limitations

This is a heuristic rule with limitations:

- **May miss complex mutations**: Some mutations might not match patterns
- **Conservative**: May not flag all unnecessary borrow_mut() calls
- **Cannot track across statements**: If mutation happens in a separate statement

Despite limitations, this rule catches the most common mistake: using borrow_mut() for simple read operations.

## References

- Dylint lint: `unnecessary_borrow_mut`
- Rust Book: Interior Mutability pattern
- std::cell::RefCell documentation
