# ctor-dtor-std Test Suite

This example tests detection of `#[ctor]` and `#[dtor]` functions that call standard library APIs.

## Problem

The `ctor` crate allows functions to run before `main()` (constructors) or after `main()` (destructors).
Calling `std::` APIs in these contexts can cause:

1. **Initialization ordering issues**: The Rust standard library may not be fully initialized
2. **Deadlocks**: Mutex/lock initialization order is undefined  
3. **Undefined behavior**: Program teardown state is unpredictable
4. **Panics**: Runtime may not be ready to handle panics

## Test Cases

### Problematic (5 functions)

1. `ctor_with_println` - Uses `std::io` APIs (`println!`)
2. `ctor_with_mutex` - Uses `std::sync::Mutex` in constructor
3. `ctor_with_vec` - Uses `std::vec` and `std::mem` APIs
4. `dtor_with_println` - Uses `std::io` APIs in destructor
5. `dtor_with_filesystem` - Uses `std::fs` APIs during teardown

### Safe (7 functions)

1. `regular_function_with_std` - Regular function (no `#[ctor]/#[dtor]`)
2. `ctor_without_std` - Constructor with only primitive operations
3. `dtor_without_std` - Destructor with only primitive operations
4. `ctor_with_safe_helper` - Constructor calling non-std function
5. `ctor_empty` - Empty constructor
6. `dtor_empty` - Empty destructor
7. `helper_safe` - Helper function (not a ctor/dtor)

## Detection Strategy

The rule looks for:
1. Functions with `__ctor`, `__dtor`, `.ctor.`, `.dtor.`, `_ctor_`, or `_dtor_` in their mangled names
2. Calls to `std::` APIs within those functions

## Expected Results

- **Recall**: 5/5 = 100% (all problematic cases should be detected)
- **Precision**: Should have minimal false positives
