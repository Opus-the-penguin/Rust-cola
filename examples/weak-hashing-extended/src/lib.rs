// Test suite for RUSTCOLA062: Weak hashing algorithms beyond MD5/SHA-1
// Tests detection of RIPEMD, CRC, Adler32, and other weak hashing algorithms
// that should not be used for security-sensitive operations

// ==============================================================================
// PROBLEMATIC CASES - Should trigger RUSTCOLA062
// ==============================================================================

/// PROBLEMATIC: RIPEMD-160 is cryptographically weak
pub fn ripemd160_hashing(data: &[u8]) -> Vec<u8> {
    use ripemd::{Ripemd160, Digest};
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// PROBLEMATIC: RIPEMD-128 is even weaker
pub fn ripemd128_usage(input: &str) {
    use ripemd::{Ripemd128, Digest};
    let mut hasher = Ripemd128::new();
    hasher.update(input.as_bytes());
    let _result = hasher.finalize();
}

/// PROBLEMATIC: RIPEMD-256 also deprecated
pub fn ripemd256_digest(data: &[u8]) {
    use ripemd::{Ripemd256, Digest};
    let digest = Ripemd256::digest(data);
    println!("Digest: {:x}", digest);
}

/// PROBLEMATIC: CRC32 is not cryptographically secure
pub fn crc32_checksum(data: &[u8]) -> u32 {
    use crc::{Crc, CRC_32_ISO_HDLC};
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    crc.checksum(data)
}

/// PROBLEMATIC: CRC32Fast for security is wrong
pub fn crc32fast_usage(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// PROBLEMATIC: Adler32 is a non-cryptographic checksum
pub fn adler32_checksum(bytes: &[u8]) -> u32 {
    adler::adler32_slice(bytes)
}

/// PROBLEMATIC: Using CRC for password hashing
pub fn password_with_crc(password: &str) -> u32 {
    use crc::{Crc, CRC_32_ISCSI};
    let crc = Crc::<u32>::new(&CRC_32_ISCSI);
    crc.checksum(password.as_bytes())
}

/// PROBLEMATIC: RIPEMD in authentication token
pub fn generate_auth_token(user_id: &str, secret: &str) -> String {
    use ripemd::{Ripemd160, Digest};
    let mut hasher = Ripemd160::new();
    hasher.update(user_id.as_bytes());
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ==============================================================================
// SAFE CASES - Should NOT trigger RUSTCOLA062
// ==============================================================================

/// SAFE: SHA-256 is cryptographically secure (though will trigger other rules)
pub fn sha256_hashing(data: &[u8]) -> Vec<u8> {
    // This is safe from RUSTCOLA062 perspective (strong hash)
    // Using SHA-256 for demonstration - would need actual sha2 crate
    data.to_vec() // Placeholder
}

/// SAFE: CRC in comment/documentation
/// We use CRC32 for file integrity but SHA-256 for security
pub fn documented_crc_usage() {
    // Safe: just documentation mentioning CRC
}

/// SAFE: Variable named after hash, not actual usage
pub fn crc_variable_name() {
    let crc_result = 42u32; // Just a variable name
    println!("Result: {}", crc_result);
}

/// SAFE: String literal mentioning RIPEMD
pub fn ripemd_in_string() {
    let message = "This system does not use RIPEMD hashing";
    println!("{}", message);
}

/// SAFE: CRC for non-security file integrity check
pub fn file_integrity_checksum(data: &[u8]) -> u32 {
    // In real code, CRC is acceptable for non-security checksums
    // But for testing, we'll avoid actual usage
    data.len() as u32 // Placeholder
}

/// SAFE: Adler32 mentioned in error message
pub fn error_with_checksum_name(error_code: u32) {
    if error_code == 0 {
        eprintln!("Checksum algorithm (not adler32 or crc) is required");
    }
}

/// SAFE: BLAKE3 is a modern secure hash
pub fn blake3_hashing(data: &[u8]) {
    // BLAKE3 is cryptographically secure - safe usage
    // Would need blake3 crate in real implementation
    let _hash = data;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problematic_functions_compile() {
        let test_data = b"test data";
        let _r160 = ripemd160_hashing(test_data);
        ripemd128_usage("test");
        ripemd256_digest(test_data);
        let _crc = crc32_checksum(test_data);
        let _crc_fast = crc32fast_usage(test_data);
        let _adler = adler32_checksum(test_data);
        let _pwd_hash = password_with_crc("password123");
        let _token = generate_auth_token("user1", "secret");
    }

    #[test]
    fn test_safe_functions_compile() {
        let test_data = b"test data";
        let _sha = sha256_hashing(test_data);
        documented_crc_usage();
        crc_variable_name();
        ripemd_in_string();
        let _integrity = file_integrity_checksum(test_data);
        error_with_checksum_name(0);
        blake3_hashing(test_data);
    }
}
