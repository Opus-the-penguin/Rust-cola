//! ⚠️ SECURITY SCANNER NOTICE ⚠️
//!
//! This crate contains INTENTIONAL security vulnerabilities for testing RUSTCOLA039.
//! DO NOT use these patterns in production code.
//!
//! codeql[rust/hardcoded-credentials]: Test examples for hard-coded crypto key detection

// NOSEC: This file contains test patterns for security scanners

/// BAD: Hard-coded AES key
/// Embedding cryptographic keys in source code enables theft and prevents rotation
pub fn bad_hardcoded_aes_key() {
    // NOSEC - Hard-coded key! This should be from environment or secret store
    let key = b"this_is_a_secret_key_32bytes!!"; // NOSEC
    // In real code: let cipher = Aes256::new(GenericArray::from_slice(key));
    println!("Using key: {:?}", key);
}

/// BAD: Hard-coded key in hex format
pub fn bad_hardcoded_hex_key() {
    // NOSEC - Hard-coded hex key
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // NOSEC
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    println!("Using hex key: {:?}", key);
}

/// BAD: Hard-coded HMAC secret
pub fn bad_hardcoded_hmac_secret() {
    // NOSEC - Hard-coded HMAC secret
    let secret = b"my_super_secret_hmac_key_12345"; // NOSEC
    // In real code: let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    println!("Using secret: {:?}", secret);
}

/// BAD: Hard-coded ChaCha20 key and nonce
pub fn bad_hardcoded_chacha_key() {
    // NOSEC - Hard-coded key and nonce
    let key = [0u8; 32]; // NOSEC - All zeros is still a hard-coded key!
    let nonce = [0u8; 12]; // NOSEC
    // In real code: ChaCha20::new(&key.into(), &nonce.into());
    println!("Using ChaCha key: {:?}, nonce: {:?}", key, nonce);
}

/// BAD: Hard-coded password variable
pub fn bad_hardcoded_password() {
    // NOSEC - Hard-coded password in variable name
    let password = "super_secret_password_that_should_not_be_here"; // NOSEC
    println!("Password length: {}", password.len());
}

/// BAD: Hard-coded token
pub fn bad_hardcoded_token() {
    // NOSEC - Hard-coded API token
    let api_token = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"; // NOSEC
    println!("Token: {}", api_token);
}

/// GOOD: Load key from environment variable
pub fn good_env_key() -> Result<Vec<u8>, std::env::VarError> {
    let key_hex = std::env::var("CRYPTO_KEY")?;
    // Parse hex string to bytes
    let key = hex::decode(&key_hex).unwrap_or_default();
    Ok(key)
}

/// GOOD: Load key from configuration file
pub fn good_config_key() -> std::io::Result<Vec<u8>> {
    use std::fs;
    let key = fs::read("config/secret.key")?;
    Ok(key)
}

/// GOOD: Generate key at runtime
pub fn good_generated_key() -> Vec<u8> {
    // In real code, use a proper CSPRNG like rand::thread_rng()
    vec![0u8; 32] // This is just placeholder, real code would generate random bytes
}

/// GOOD: Key passed as parameter
pub fn good_key_parameter(key: &[u8]) {
    // Key is provided by caller from secure source
    println!("Key length: {}", key.len());
}

/// GOOD: Use key management service
pub fn good_kms_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // In real code, fetch from AWS KMS, Azure Key Vault, etc.
    // This is a placeholder showing the pattern
    Ok(vec![])
}

// Mock hex decode for example purposes (in real code, use the hex crate)
mod hex {
    pub fn decode(_s: &str) -> Result<Vec<u8>, ()> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_good_patterns() {
        // These patterns are safe
        let key = good_generated_key();
        assert_eq!(key.len(), 32);
        
        good_key_parameter(&[1, 2, 3, 4]);
        
        // Env and file operations would require setup, skip in tests
    }
}

