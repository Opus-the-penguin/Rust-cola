use std::process::Command;

pub fn test_suppression() {
    let arg = std::env::var("ARG").unwrap();
    // rust-cola:ignore RUSTCOLA006, RUSTCOLA047
    Command::new("sh").arg("-c").arg(arg).output().unwrap();
}
