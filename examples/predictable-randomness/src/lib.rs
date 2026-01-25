//! Demonstrates RUSTCOLA046: Predictable randomness detection
//!
//! This example shows patterns of RNG initialization with constant seeds
//! that make random output predictable - a critical security flaw.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA046
// ============================================================================

/// VULNERABLE: Using constant seed for RNG (most common pattern)
pub fn vulnerable_constant_seed() {
    // CRITICAL: Constant seed makes all "random" output predictable!
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let _random = rng.gen::<u64>();
}

/// VULNERABLE: Hardcoded seed in cryptographic context
pub fn vulnerable_crypto_token_generation() {
    // CRITICAL: Session tokens will be predictable!
    let mut rng = ChaCha20Rng::seed_from_u64(999);
    let _token = rng.gen::<u128>();
}

/// VULNERABLE: Predictable nonce generation
pub fn vulnerable_nonce_generation() {
    // CRITICAL: Nonces must be unpredictable!
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let _nonce = rng.gen::<[u8; 12]>();
}

/// VULNERABLE: Password salt with constant seed
pub fn vulnerable_password_salt() {
    // CRITICAL: Password salts must be unique and unpredictable!
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let _salt = rng.gen::<[u8; 16]>();
}

/// VULNERABLE: Encryption key derivation
pub fn vulnerable_key_generation() {
    // CRITICAL: Cryptographic keys must be truly random!
    let mut rng = ChaCha20Rng::seed_from_u64(1337);
    let _key = rng.gen::<[u8; 32]>();
}

/// VULNERABLE: HMAC secret generation
pub fn vulnerable_hmac_secret() {
    // CRITICAL: HMAC secrets must be unpredictable!
    let mut rng = ChaCha20Rng::seed_from_u64(54321);
    let _secret = rng.gen::<[u8; 32]>();
}

/// VULNERABLE: Session ID generation
pub fn vulnerable_session_id() {
    // CRITICAL: Session IDs must be unique and unpredictable!
    let mut rng = ChaCha20Rng::seed_from_u64(7777);
    let _session_id = rng.gen::<u128>();
}

/// VULNERABLE: Zero seed (special case)
pub fn vulnerable_zero_seed() {
    // Using zero as seed is predictable
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    let _value = rng.gen::<u64>();
}

/// VULNERABLE: Small constant seed
pub fn vulnerable_small_seed() {
    // Small constants are easily guessable
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let _value = rng.gen::<u64>();
}

/// VULNERABLE: Non-crypto context but still bad practice
pub fn vulnerable_general_randomness() {
    // Even for non-crypto use, constant seeds are problematic
    let mut rng = ChaCha20Rng::seed_from_u64(9999);
    let _random_value = rng.gen::<u32>();
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA046
// ============================================================================

/// SAFE: Using OsRng (OS-provided cryptographically secure randomness)
pub fn safe_use_os_rng() {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let _random = rng.gen::<u64>();
}

/// SAFE: Using ThreadRng (thread-local cryptographically secure RNG)
pub fn safe_use_thread_rng() {
    let mut rng = rand::thread_rng();
    let _random = rng.gen::<u64>();
}

/// SAFE: Seeding from OsRng (proper entropy source)
pub fn safe_seed_from_entropy() {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let seed = OsRng.next_u64();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let _random = rng.gen::<u64>();
}

/// SAFE: Using from_entropy() method
pub fn safe_from_entropy() {
    let mut rng = ChaCha20Rng::from_entropy();
    let _random = rng.gen::<u64>();
}

/// SAFE: Crypto token with proper randomness
pub fn safe_crypto_token_generation() {
    let mut rng = rand::thread_rng();
    let _token = rng.gen::<u128>();
}

/// SAFE: Session ID with proper randomness
pub fn safe_session_id_generation() {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let _session_id = rng.gen::<u128>();
}

/// SAFE: Key generation with entropy
pub fn safe_key_generation() {
    let mut rng = ChaCha20Rng::from_entropy();
    let _key = rng.gen::<[u8; 32]>();
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Deterministic RNG for testing (acceptable in tests)
#[cfg(test)]
pub fn edge_case_test_deterministic() {
    // In test contexts, deterministic RNG might be acceptable
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let _value = rng.gen::<u64>();
}

/// EDGE: Seeded RNG for reproducible benchmarks
#[cfg(feature = "benchmarks")]
pub fn edge_case_benchmark_reproducible() {
    // Benchmarks might need reproducibility
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let _value = rng.gen::<u64>();
}

/// EDGE: Simulation with deterministic seed
pub fn edge_case_simulation() {
    // Scientific simulations might need reproducibility
    // But should document why the seed is constant
    let mut rng = ChaCha20Rng::seed_from_u64(31415);
    let _value = rng.gen::<f64>();
}

// ============================================================================
// DEMONSTRATION OF THE VULNERABILITY
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demonstrate_predictability() {
        // Two calls with the same seed produce identical sequences
        let mut rng1 = ChaCha20Rng::seed_from_u64(12345);
        let mut rng2 = ChaCha20Rng::seed_from_u64(12345);

        // These will be EXACTLY the same!
        let value1 = rng1.gen::<u64>();
        let value2 = rng2.gen::<u64>();

        assert_eq!(value1, value2, "Predictable! Same seed = same output");
    }

    #[test]
    fn demonstrate_unpredictability() {
        // Using proper entropy sources gives different values
        let mut rng1 = ChaCha20Rng::from_entropy();
        let mut rng2 = ChaCha20Rng::from_entropy();

        let value1 = rng1.gen::<u64>();
        let value2 = rng2.gen::<u64>();

        // These will be different (with overwhelming probability)
        assert_ne!(
            value1, value2,
            "Unpredictable! Different entropy = different output"
        );
    }
}
