#![allow(dead_code)]

pub unsafe fn overlap_copy(p: *mut u8) {
    std::ptr::copy_nonoverlapping(p.add(1), p.add(2), 4);
    std::ptr::copy_nonoverlapping(p, p, 4);
}

pub unsafe fn disjoint_copy(dst: *mut u8, src: *const u8) {
    std::ptr::copy_nonoverlapping(src, dst, 4);
}

fn main() {}
