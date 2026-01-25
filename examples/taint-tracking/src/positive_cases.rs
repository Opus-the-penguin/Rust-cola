//! Positive test cases - These SHOULD be detected by taint tracking
//! All functions here have taint flows from env vars to sinks without proper sanitization.

use std::env;
use std::fs;
use std::process::Command;

/// RUSTCOLA006: Direct flow from env::var to Command::arg
/// This is the most basic command injection vulnerability
pub fn env_to_command() -> std::io::Result<()> {
    // NOSEC: Intentional vulnerability for testing
    let user_cmd = env::var("USER_COMMAND").expect("USER_COMMAND not set");

    Command::new("echo")
        .arg(&user_cmd) // ❌ Tainted data flows to command execution
        .spawn()?;

    Ok(())
}

/// RUSTCOLA006: Flow from env::var to fs::write (path traversal risk)
/// User could set OUTPUT_PATH="../../../etc/passwd" to overwrite system files
pub fn env_to_fs() -> std::io::Result<()> {
    // NOSEC: Intentional vulnerability for testing
    let output_path = env::var("OUTPUT_PATH").expect("OUTPUT_PATH not set");

    fs::write(&output_path, b"data")?; // ❌ Tainted path

    Ok(())
}

/// RUSTCOLA006: Taint propagates through string formatting
/// format! does not sanitize - taint flows through concatenation
pub fn env_through_format() -> std::io::Result<()> {
    // NOSEC: Intentional vulnerability for testing
    let user_name = env::var("USER").unwrap_or_default();
    let message = format!("Hello, {}!", user_name); // Still tainted

    Command::new("echo")
        .arg(&message) // ❌ Tainted via format!
        .spawn()?;

    Ok(())
}

/// RUSTCOLA006: Taint propagates through variable assignment
/// Aliasing doesn't remove taint
pub fn env_through_assign() -> std::io::Result<()> {
    // NOSEC: Intentional vulnerability for testing
    let original = env::var("COMMAND").unwrap_or_default();
    let alias = original; // alias is now also tainted
    let another_alias = alias.clone(); // Still tainted

    Command::new("sh")
        .arg("-c")
        .arg(&another_alias) // ❌ Tainted through multiple assignments
        .spawn()?;

    Ok(())
}

/// RUSTCOLA006: Taint through method calls
/// String transformations preserve taint
pub fn env_through_transform() -> std::io::Result<()> {
    // NOSEC: Intentional vulnerability for testing
    let input = env::var("INPUT").unwrap_or_default();
    let upper = input.to_uppercase(); // Still tainted
    let trimmed = upper.trim(); // Still tainted

    fs::remove_file(trimmed)?; // ❌ Tainted path to dangerous fs operation

    Ok(())
}
