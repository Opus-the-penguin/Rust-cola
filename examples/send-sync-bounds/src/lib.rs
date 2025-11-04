use std::marker::PhantomData;

// BAD: unsafe impl Send without T: Send bound
pub struct WrapperBad<T> {
    data: *mut T,
}

unsafe impl<T> Send for WrapperBad<T> {}

// BAD: unsafe impl Sync without T: Sync bound
unsafe impl<T> Sync for WrapperBad<T> {}

// GOOD: unsafe impl Send with proper T: Send bound
pub struct WrapperGood<T> {
    data: *mut T,
}

unsafe impl<T: Send> Send for WrapperGood<T> {}

// GOOD: unsafe impl Sync with proper T: Sync bound
unsafe impl<T: Sync> Sync for WrapperGood<T> {}

// BAD: Multiple generic parameters, missing bounds
pub struct MultiWrapper<T, U> {
    t_data: *mut T,
    u_data: *mut U,
}

unsafe impl<T, U> Send for MultiWrapper<T, U> {}

// GOOD: Multiple generic parameters with proper bounds
pub struct MultiWrapperGood<T, U> {
    t_data: *mut T,
    u_data: *mut U,
}

unsafe impl<T: Send, U: Send> Send for MultiWrapperGood<T, U> {}

// EDGE CASE: PhantomData usage (should still require bounds)
pub struct PhantomWrapper<T> {
    _phantom: PhantomData<T>,
    data: *mut u8,
}

unsafe impl<T> Send for PhantomWrapper<T> {}

// GOOD: No generics, so no bounds needed
pub struct NoGenerics {
    data: *mut u8,
}

unsafe impl Send for NoGenerics {}
unsafe impl Sync for NoGenerics {}
