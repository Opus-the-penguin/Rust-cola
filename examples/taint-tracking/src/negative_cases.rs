//! Negative test cases - These should NOT be detected
//! All functions here properly sanitize inputs or don't use tainted data

use std::env;
use std::fs;
use std::process::Command;

/// Safe: Using hardcoded strings, not env vars
/// No taint source, so no taint to track
pub fn hardcoded_safe() -> std::io::Result<()> {
    Command::new("echo")
        .arg("Hello, World!") // ✅ Hardcoded string
        .spawn()?;

    Ok(())
}

/// Safe: Type conversion via parse sanitizes for command use
/// Parsing to u16 proves the value is a valid port number
pub fn sanitized_parse() -> std::io::Result<()> {
    let port_str = env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    // parse::<u16>() sanitizes - only valid numbers pass through
    let port: u16 = port_str.parse().unwrap_or(8080);

    Command::new("server")
        .arg("--port")
        .arg(port.to_string()) // ✅ Sanitized via type conversion
        .spawn()?;

    Ok(())
}

/// Safe: Allowlist validation before use
/// chars().all() proves the string only contains safe characters
pub fn sanitized_allowlist() -> std::io::Result<()> {
    let user_name = env::var("USERNAME").unwrap_or_default();

    // Validate against allowlist
    if user_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Command::new("echo")
            .arg(&user_name) // ✅ Sanitized via allowlist check
            .spawn()?;
    }

    Ok(())
}

/// Safe: Path canonicalization (partial sanitization)
/// fs::canonicalize resolves .. and symlinks, reducing traversal risk
pub fn sanitized_canonicalize() -> std::io::Result<()> {
    let input_path = env::var("INPUT_PATH").unwrap_or_default();

    // Canonicalize resolves relative paths and symlinks
    let safe_path = fs::canonicalize(&input_path)?;

    // Now safer (but still tainted - could be outside expected directory)
    let _metadata = fs::metadata(&safe_path)?; // ✅ Reduced risk

    Ok(())
}

/// Safe: Validated with regex before use
/// (Future enhancement - not yet implemented in taint tracking)
pub fn validated_regex() -> std::io::Result<()> {
    let input = env::var("INPUT").unwrap_or_default();

    // Regex validation (simplified - imagine proper regex check)
    if input.len() < 50 && input.chars().all(|c| c.is_ascii_alphanumeric()) {
        fs::write("/tmp/output.txt", input.as_bytes())?; // ✅ Validated
    }

    Ok(())
}

/// Safe: Only using env var for non-security-sensitive purpose
/// Reading env var but not passing to any dangerous sink
pub fn env_var_no_sink() -> String {
    let debug = env::var("DEBUG").unwrap_or_else(|_| "false".to_string());

    // Just checking the value, not executing commands or writing files
    if debug == "true" {
        println!("Debug mode enabled"); // ✅ No dangerous sink
    }

    debug
}
