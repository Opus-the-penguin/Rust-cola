// Test suite for RUSTCOLA063: Null pointer transmutes
// Tests detection of transmute calls involving null pointers which cause undefined behavior
// Reference: Public security rule guidance on null pointer transmutation

use std::mem::transmute;

// ==============================================================================
// PROBLEMATIC CASES - Should trigger RUSTCOLA063
// ==============================================================================

/// PROBLEMATIC: Transmuting null pointer (0) to a reference
pub unsafe fn null_to_ref_transmute() -> &'static i32 {
    transmute(0usize)
}

/// PROBLEMATIC: Transmuting null pointer to mutable reference
pub unsafe fn null_to_mut_ref_transmute() -> &'static mut String {
    transmute(0usize)
}

/// PROBLEMATIC: Transmuting std::ptr::null() to reference
pub unsafe fn std_null_to_ref() -> &'static u8 {
    transmute(std::ptr::null::<u8>())
}

/// PROBLEMATIC: Transmuting null to function pointer
pub unsafe fn null_to_fn_pointer() -> fn() -> i32 {
    transmute(0usize)
}

/// PROBLEMATIC: Transmuting null_mut to reference
pub unsafe fn null_mut_to_ref() -> &'static mut i32 {
    transmute(std::ptr::null_mut::<i32>())
}

/// PROBLEMATIC: Creating null function pointer via transmute
pub unsafe fn create_null_fn_ptr() -> extern "C" fn(i32) -> i32 {
    transmute(0usize)
}

/// PROBLEMATIC: Transmute 0 to raw pointer (while less dangerous, still suspicious)
pub unsafe fn zero_to_raw_pointer() -> *const u8 {
    transmute(0usize)
}

// ==============================================================================
// SAFE CASES - Should NOT trigger RUSTCOLA063
// ==============================================================================

/// SAFE: Transmuting between same-sized types (not involving null)
pub unsafe fn transmute_int_to_float(x: u32) -> f32 {
    transmute(x)
}

/// SAFE: Transmuting non-null pointer
pub unsafe fn non_null_ptr_transmute(ptr: *const i32) -> usize {
    transmute(ptr)
}

/// SAFE: Using proper null pointer creation (not transmute)
pub fn proper_null_creation() -> *const i32 {
    std::ptr::null()
}

/// SAFE: Transmuting between pointer types (not from/to null literal)
pub unsafe fn ptr_to_ptr_transmute(ptr: *const u8) -> *const i32 {
    transmute(ptr)
}

/// SAFE: Transmuting array to different representation
pub unsafe fn array_transmute(arr: [u8; 4]) -> u32 {
    transmute(arr)
}

/// SAFE: NonNull usage (type system prevents null)
pub fn non_null_usage(x: i32) -> std::ptr::NonNull<i32> {
    std::ptr::NonNull::new(&x as *const i32 as *mut i32).unwrap()
}

/// SAFE: Using as cast instead of transmute
pub fn cast_to_usize(ptr: *const i32) -> usize {
    ptr as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problematic_functions_compile() {
        unsafe {
            // These are intentionally unsafe - testing detection only
            let _r1 = null_to_ref_transmute();
            let _r2 = null_to_mut_ref_transmute();
            let _r3 = std_null_to_ref();
            let _r4 = null_to_fn_pointer();
            let _r5 = null_mut_to_ref();
            let _r6 = create_null_fn_ptr();
            let _r7 = zero_to_raw_pointer();
        }
    }

    #[test]
    fn test_safe_functions_compile() {
        unsafe {
            let x = 42u32;
            let _f = transmute_int_to_float(x);

            let val = 100i32;
            let ptr = &val as *const i32;
            let _u = non_null_ptr_transmute(ptr);
            let _p = ptr_to_ptr_transmute(ptr as *const u8);

            let arr = [1u8, 2, 3, 4];
            let _n = array_transmute(arr);
        }

        let _null = proper_null_creation();
        let val = 42;
        let _nn = non_null_usage(val);
        let ptr = &val as *const i32;
        let _u = cast_to_usize(ptr);
    }
}
