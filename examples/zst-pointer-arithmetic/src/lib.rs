// Test suite for RUSTCOLA064: Pointer arithmetic on zero-sized types
// 
// Zero-sized types (ZST) have size_of::<T>() == 0
// Pointer arithmetic on ZSTs causes undefined behavior because:
// - offset() assumes stride of size_of::<T>()  
// - For ZSTs, this means all offsets point to the same address
// - This violates pointer aliasing rules and provenance
//
// This provides Sonar RSPEC-7412 parity

// Test type definitions
pub struct EmptyStruct;

pub struct StructWithData {
    pub value: u64,
}

// ===== PROBLEMATIC PATTERNS (7 functions) =====
// These perform pointer arithmetic on zero-sized types

pub fn offset_on_unit_type() -> *const () {
    let ptr: *const () = std::ptr::null();
    unsafe { ptr.offset(10) } // NOSEC - UB: ZST arithmetic
}

pub fn add_on_empty_struct() -> *const EmptyStruct {
    let ptr: *const EmptyStruct = std::ptr::null();
    unsafe { ptr.add(5) } // NOSEC - UB: ZST arithmetic
}

pub fn sub_on_phantom_data() -> *const std::marker::PhantomData<i32> {
    use std::marker::PhantomData;
    let ptr: *const PhantomData<i32> = std::ptr::null();
    unsafe { ptr.sub(3) } // NOSEC - UB: ZST arithmetic
}

pub fn wrapping_offset_on_unit() -> *mut () {
    let mut val = ();
    let ptr: *mut () = &mut val;
    ptr.wrapping_offset(100) // NOSEC - UB: ZST arithmetic (doesn't require unsafe)
}

pub fn wrapping_add_on_empty_enum() {
    enum EmptyEnum {}
    let ptr: *const EmptyEnum = 0x1000 as *const EmptyEnum;
    let _ = ptr.wrapping_add(50); // NOSEC - UB: ZST arithmetic (doesn't require unsafe)
}

pub fn offset_from_on_unit() -> isize {
    let ptr1: *const () = 0x100 as *const ();
    let ptr2: *const () = 0x200 as *const ();
    unsafe { ptr2.offset_from(ptr1) } // NOSEC - UB: ZST arithmetic
}

pub fn array_indexing_zst() -> *const () {
    let arr: [(); 10] = [(); 10];
    let ptr: *const () = arr.as_ptr();
    unsafe { ptr.add(5) } // NOSEC - UB: ZST arithmetic
}

// ===== SAFE PATTERNS (7 functions) =====
// These either avoid pointer arithmetic or use proper sized types

pub fn offset_on_sized_type() -> *const i32 {
    let val = 42i32;
    let ptr: *const i32 = &val;
    unsafe { ptr.offset(1) } // Safe: i32 is sized
}

pub fn add_on_struct_with_fields() -> *const StructWithData {
    let data = StructWithData { value: 123 };
    let ptr: *const StructWithData = &data;
    unsafe { ptr.add(0) } // Safe: StructWithData is sized
}

pub fn no_arithmetic_on_zst() -> *const () {
    let val = ();
    let ptr: *const () = &val;
    ptr // Safe: No arithmetic performed
}

pub fn wrapping_offset_on_byte_array() -> *const u8 {
    let arr = [0u8; 10];
    let ptr: *const u8 = arr.as_ptr();
    ptr.wrapping_offset(5) // Safe: u8 is sized (doesn't require unsafe)
}

pub fn sub_on_string() -> *const String {
    let s = String::from("test");
    let ptr: *const String = &s;
    unsafe { ptr.sub(0) } // Safe: String is sized
}

pub fn proper_zst_handling() {
    // Safe: Using references instead of raw pointers
    let val = ();
    let _ref = &val;
    // No pointer arithmetic
}

pub fn offset_from_on_vec() -> isize {
    let vec = vec![1, 2, 3, 4, 5];
    let ptr1: *const i32 = &vec[0];
    let ptr2: *const i32 = &vec[4];
    unsafe { ptr2.offset_from(ptr1) } // Safe: i32 is sized
}
