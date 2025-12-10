#![allow(dead_code)]

pub unsafe fn null_deref() -> i32 {
    let p = std::ptr::null::<i32>();
    *p
}

pub unsafe fn zero_addr_deref() -> i32 {
    let p = 0usize as *const i32;
    *p
}

pub unsafe fn misaligned_deref() -> u16 {
    let ptr = 0x1001usize as *const u16;
    *ptr
}

pub unsafe fn aligned_deref() -> u16 {
    let ptr = 0x1000usize as *const u16;
    *ptr
}
