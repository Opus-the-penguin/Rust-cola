#[no_mangle]
pub extern "C" fn ffi_create(x: i32) -> *mut i32 {
    let b = Box::new(x);
    Box::into_raw(b)
}

pub async fn async_add(a: i32, b: i32) -> i32 {
    let x = a + b;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke() {
        let _ = ffi_create(3);
    }
}
