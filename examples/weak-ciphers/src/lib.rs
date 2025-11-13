//! Demonstrates RUSTCOLA045: Weak cipher detection
//!
//! This example shows various patterns of weak/deprecated cipher usage that should be flagged.

use des::cipher::KeyInit;

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA045
// ============================================================================

/// VULNERABLE: Using DES cipher (broken since 1998)
pub fn vulnerable_des_cipher() {
    // Real DES usage that will show up in MIR
    let key = [0u8; 8];
    let _cipher = des::Des::new(&key.into());
}

/// VULNERABLE: Using 3DES/TripleDES (deprecated, slow, 64-bit blocks)
pub fn vulnerable_triple_des() {
    // Real 3DES usage
    let key = [0u8; 24];
    let _cipher = des::TdesEde3::new(&key.into());
}

/// VULNERABLE: Pattern that would appear for RC4 usage
pub fn vulnerable_rc4_pattern() {
    // Simulating what RC4 usage would look like in MIR
    // In reality: rc4::Rc4::new(&key)
    // We simulate the pattern without the actual dependency
    let _placeholder = simulate_rc4_new();
}

fn simulate_rc4_new() -> u32 {
    // Function name pattern that would trigger: rc4::
    42
}

/// VULNERABLE: Pattern for RC2 usage
pub fn vulnerable_rc2_pattern() {
    let _placeholder = simulate_rc2_new();
}

fn simulate_rc2_new() -> u32 {
    // Function name pattern: rc2::
    42
}

/// VULNERABLE: Pattern for Blowfish usage
pub fn vulnerable_blowfish_pattern() {
    let _placeholder = simulate_blowfish_new();
}

fn simulate_blowfish_new() -> u32 {
    // Function name pattern: blowfish::
    42
}

/// VULNERABLE: Using DES in ECB mode (doubly bad!)
pub fn vulnerable_des_ecb() {
    let key = [0u8; 8];
    let _cipher = des::Des::new(&key.into());
    // In real code would also use block_modes::Ecb
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA045
// ============================================================================

/// SAFE: Using AES would be fine (we're not importing it, just showing pattern)
pub fn safe_aes_pattern() {
    // Would use: aes::Aes256::new(&key)
    // Pattern: aes:: (not flagged)
    let _safe = 42;
}

/// SAFE: Using ChaCha20 would be fine
pub fn safe_chacha_pattern() {
    // Would use: chacha20::ChaCha20::new(&key, &nonce)
    // Pattern: chacha20:: (not flagged)
    let _safe = 42;
}

/// SAFE: Just mentioning DES in a comment is OK
pub fn safe_comment_mention() {
    // This function discusses DES but doesn't use it
    // DES was broken in 1998 by the EFF DES Cracker
    println!("Don't use DES!");
}

/// SAFE: String containing "des" that's not a cipher
pub fn safe_string_contains_des() {
    let message = "This describes a process";
    println!("{}", message);
}

/// SAFE: Variable name containing "des" is OK
pub fn safe_variable_named_description() {
    let description = "A safe description";
    let _ = description;
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Generic parameter (we can't detect if it's DES at compile time)
pub fn edge_case_generic<C: KeyInit>() {
    // We can't know what C is without runtime information
    let _ = std::marker::PhantomData::<C>;
}

/// EDGE: Conditional compilation
#[cfg(feature = "legacy")]
pub fn edge_case_conditional() {
    let key = [0u8; 8];
    let _cipher = des::Des::new(&key.into());
}
