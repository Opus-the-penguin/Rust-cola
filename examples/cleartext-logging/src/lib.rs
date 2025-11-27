// Test cases for RUSTCOLA075: Cleartext Logging of Secrets
// This file contains **INTENTIONAL VULNERABILITIES** for testing.
//
// Logging sensitive data (passwords, tokens, API keys) in cleartext
// exposes secrets in log files, monitoring systems, and audit trails.

use std::env;

// ========== PROBLEMATIC CASES (should trigger RUSTCOLA075) ==========

/// PROBLEMATIC: Logs password from environment variable
pub fn log_password_from_env() {
    let password = env::var("DB_PASSWORD").unwrap_or_default();
    // Logging password directly - VULNERABLE
    println!("Connecting with password: {}", password);
}

/// PROBLEMATIC: Logs API key to debug output
pub fn log_api_key() {
    let api_key = env::var("API_KEY").unwrap_or_default();
    // Debug logging of API key - VULNERABLE
    eprintln!("DEBUG: Using API key {}", api_key);
}

/// PROBLEMATIC: Logs secret token
pub fn log_auth_token() {
    let token = env::var("AUTH_TOKEN").unwrap_or_default();
    // Format string with secret - VULNERABLE  
    let msg = format!("Token value: {}", token);
    println!("{}", msg);
}

/// PROBLEMATIC: Logs secret in error message
pub fn log_secret_in_error() {
    let secret = env::var("JWT_SECRET").unwrap_or_default();
    // Error messages with secrets - VULNERABLE
    panic!("Failed to validate with secret: {}", secret);
}

/// PROBLEMATIC: Multiple secrets in one log
pub fn log_multiple_secrets() {
    let password = env::var("PASSWORD").unwrap_or_default();
    let token = env::var("TOKEN").unwrap_or_default();
    // Multiple secrets logged - VULNERABLE
    println!("Auth: password={}, token={}", password, token);
}

/// PROBLEMATIC: Secret passed to function that logs
pub fn log_passed_secret() {
    let key = env::var("PRIVATE_KEY").unwrap_or_default();
    log_value(&key);
}

fn log_value(val: &str) {
    println!("Value: {}", val);
}

/// PROBLEMATIC: Secret logged through debug trait
pub fn log_secret_debug() {
    let secret = env::var("SECRET_DATA").unwrap_or_default();
    // Debug format - VULNERABLE
    println!("{:?}", secret);
}

// ========== SAFE CASES (should NOT trigger RUSTCOLA075) ==========

/// SAFE: Logs non-sensitive environment variable
pub fn log_safe_env_var() {
    let host = env::var("DATABASE_HOST").unwrap_or_default();
    // Hostname is not sensitive
    println!("Connecting to host: {}", host);
}

/// SAFE: Logs static message (no env vars)
pub fn log_static_message() {
    println!("Application started successfully");
}

/// SAFE: Masked password logging
pub fn log_masked_password() {
    let _password = env::var("DB_PASSWORD").unwrap_or_default();
    // Only logs that password was provided, not the value
    println!("Password: ****");
}

/// SAFE: Secret used but not logged
pub fn use_secret_without_logging() {
    let secret = env::var("SECRET").unwrap_or_default();
    // Secret used for computation, not logged
    let _hash = compute_hash(&secret);
    println!("Hash computed successfully");
}

fn compute_hash(input: &str) -> usize {
    input.len() // Simplified hash
}

/// SAFE: Logs result derived from secret (not the secret itself)
pub fn log_derived_value() {
    let password = env::var("PASSWORD").unwrap_or_default();
    let is_strong = password.len() >= 12;
    // Logs derived boolean, not the secret
    println!("Password strength check: {}", is_strong);
}

/// SAFE: Non-secret env var with sensitive-looking name
pub fn log_port_number() {
    let port = env::var("SECRET_PORT").unwrap_or_default();
    // Actually just a port number
    println!("Server port: {}", port);
}

/// SAFE: Secret redacted before logging
pub fn log_redacted_secret() {
    let token = env::var("AUTH_TOKEN").unwrap_or_default();
    let redacted = redact(&token);
    println!("Token: {}", redacted);
}

fn redact(s: &str) -> String {
    if s.len() > 4 {
        format!("{}****", &s[..4])
    } else {
        "****".to_string()
    }
}
