use std::marker::PhantomData;

// ============================================================================
// SECURITY SCANNER NOTICE:
// This file contains INTENTIONAL VULNERABILITIES for testing purposes.
// These are test cases for RUSTCOLA015 (unsafe Send/Sync bounds) detection.
// DO NOT flag these as actual security issues.
// ============================================================================
// NOSEC: Entire file contains intentional test vulnerabilities
// CodeQL: False positive - test cases for security rule validation
// Semgrep: suppress - intentional vulnerable patterns for testing

// BAD: unsafe impl Send without T: Send bound
// RUSTCOLA015 should flag this
// NOSEC: Intentional vulnerability for testing RUSTCOLA015
pub struct WrapperBad<T> {
    data: *mut T,
}

// NOSEC: Intentional test case - missing T: Send bound
unsafe impl<T> Send for WrapperBad<T> {}

// BAD: unsafe impl Sync without T: Sync bound
// RUSTCOLA015 should flag this
// NOSEC: Intentional test case - missing T: Sync bound
unsafe impl<T> Sync for WrapperBad<T> {}

// GOOD: unsafe impl Send with proper T: Send bound
pub struct WrapperGood<T> {
    data: *mut T,
}

unsafe impl<T: Send> Send for WrapperGood<T> {}

// GOOD: unsafe impl Sync with proper T: Sync bound
unsafe impl<T: Sync> Sync for WrapperGood<T> {}

// BAD: Multiple generic parameters, missing bounds
// RUSTCOLA015 should flag this
// NOSEC: Intentional vulnerability for testing RUSTCOLA015
pub struct MultiWrapper<T, U> {
    t_data: *mut T,
    u_data: *mut U,
}

// NOSEC: Intentional test case - missing bounds
unsafe impl<T, U> Send for MultiWrapper<T, U> {}

// GOOD: Multiple generic parameters with proper bounds
pub struct MultiWrapperGood<T, U> {
    t_data: *mut T,
    u_data: *mut U,
}

unsafe impl<T: Send, U: Send> Send for MultiWrapperGood<T, U> {}

// EDGE CASE: PhantomData usage (should still require bounds)
// RUSTCOLA015 should flag this
// NOSEC: Intentional vulnerability for testing RUSTCOLA015
pub struct PhantomWrapper<T> {
    _phantom: PhantomData<T>,
    data: *mut u8,
}

// NOSEC: Intentional test case - missing T: Send bound even with PhantomData
unsafe impl<T> Send for PhantomWrapper<T> {}

// GOOD: No generics, so no bounds needed
pub struct NoGenerics {
    data: *mut u8,
}

unsafe impl Send for NoGenerics {}
unsafe impl Sync for NoGenerics {}
