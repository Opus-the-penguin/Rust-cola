// Test suite for RUSTCOLA066: Modulo bias on random outputs
//
// Modulo bias occurs when using % n on random values because it creates
// non-uniform distributions. For example, rand() % 3 with a RNG producing
// 0-255 will favor 0 and 1 over 2 (256 % 3 = 1).
//
// This is especially dangerous in cryptographic contexts where uniform
// distribution is critical for security (key generation, nonces, tokens).

use rand::{thread_rng, Rng, RngCore};

// ============================================================================
// PROBLEMATIC: Modulo bias in cryptographic contexts
// ============================================================================

/// Generate crypto key with modulo bias - PROBLEMATIC
pub fn generate_crypto_key_modulo() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = Vec::new();
    for _ in 0..32 {
        // Biased: rand() % 256 creates non-uniform distribution
        key.push((rng.gen::<u32>() % 256) as u8);
    }
    key
}

/// Generate authentication token with modulo bias - PROBLEMATIC
pub fn generate_auth_token_modulo() -> String {
    let mut rng = thread_rng();
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut token = String::new();
    for _ in 0..32 {
        // Biased: favors some characters over others
        let idx = rng.gen::<usize>() % charset.len();
        token.push(charset[idx] as char);
    }
    token
}

/// Generate nonce for encryption with modulo bias - PROBLEMATIC
pub fn generate_nonce_modulo() -> u64 {
    let mut rng = thread_rng();
    // Biased: 2^64 % 1000000 creates non-uniform distribution
    rng.gen::<u64>() % 1_000_000
}

/// Hash salt generation with modulo bias - PROBLEMATIC
pub fn hash_salt_with_bias() -> Vec<u8> {
    let mut rng = thread_rng();
    (0..16).map(|_| (rng.gen::<u32>() % 256) as u8).collect()
}

/// Digital signature random k with modulo bias - PROBLEMATIC
pub fn signature_random_k_modulo(order: u64) -> u64 {
    let mut rng = thread_rng();
    // Biased: can lead to ECDSA key recovery attacks
    rng.gen::<u64>() % order
}

/// Session ID generation with modulo - PROBLEMATIC
pub fn generate_session_id_modulo() -> String {
    let mut rng = thread_rng();
    format!("session_{}", rng.gen::<u64>() % 1_000_000_000)
}

/// Secret value with modulo in crypto function - PROBLEMATIC
pub fn crypto_secret_modulo() -> u32 {
    let mut rng = thread_rng();
    let secret = rng.gen::<u32>() % 10000;
    encrypt_value(secret)
}

fn encrypt_value(val: u32) -> u32 {
    val ^ 0xDEADBEEF
}

// ============================================================================
// SAFE: Non-cryptographic uses or proper techniques
// ============================================================================

/// Non-crypto random color selection - SAFE
pub fn random_color() -> &'static str {
    let mut rng = thread_rng();
    let colors = ["red", "green", "blue", "yellow"];
    // Not crypto context, modulo bias acceptable for UI
    colors[rng.gen::<usize>() % colors.len()]
}

/// Random game position - SAFE
pub fn random_game_position() -> (i32, i32) {
    let mut rng = thread_rng();
    // Non-cryptographic use, bias acceptable
    let x = (rng.gen::<i32>() % 100).abs();
    let y = (rng.gen::<i32>() % 100).abs();
    (x, y)
}

/// Proper uniform distribution with gen_range - SAFE
pub fn generate_proper_token() -> String {
    let mut rng = thread_rng();
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut token = String::new();
    for _ in 0..32 {
        // Proper: gen_range provides uniform distribution
        let idx = rng.gen_range(0..charset.len());
        token.push(charset[idx] as char);
    }
    token
}

/// Proper key generation with fill_bytes - SAFE
pub fn generate_proper_key() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut key = vec![0u8; 32];
    // Proper: fill_bytes provides uniform random bytes
    rng.fill_bytes(&mut key);
    key
}

/// Random with explicit rejection sampling - SAFE
pub fn generate_uniform_value(max: u32) -> u32 {
    let mut rng = thread_rng();
    loop {
        let val = rng.gen::<u32>();
        let limit = u32::MAX - (u32::MAX % max);
        if val < limit {
            return val % max; // Safe: rejection sampling eliminates bias
        }
    }
}

/// Non-crypto simulation with modulo - SAFE
pub fn simulate_dice_roll() -> u8 {
    let mut rng = thread_rng();
    // Statistical simulation, not crypto
    (rng.gen::<u8>() % 6) + 1
}

/// Proper crypto random without modulo - SAFE
pub fn generate_secure_nonce() -> u64 {
    let mut rng = thread_rng();
    // Direct generation, no modulo
    rng.gen::<u64>()
}
