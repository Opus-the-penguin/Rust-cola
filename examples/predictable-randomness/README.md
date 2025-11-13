# RUSTCOLA046: Predictable Randomness Detection

This example demonstrates detection of predictable random number generator initialization - a critical security vulnerability in cryptographic contexts.

## CWE-330: Use of Insufficiently Random Values

**Severity**: CRITICAL (in cryptographic contexts), HIGH (general)

Using constant or predictable seeds for random number generators makes the output deterministic and exploitable. Attackers can predict:
- Session tokens and IDs
- Cryptographic keys and nonces
- Password salts
- CSRF tokens
- API keys and secrets

## Vulnerability

```rust
// VULNERABLE: Constant seed makes output predictable!
let mut rng = ChaCha20Rng::seed_from_u64(12345);
let token = rng.gen::<u128>();  // Attacker can predict this!
```

If an attacker knows:
1. The RNG algorithm (ChaCha20Rng)
2. The seed value (12345)

They can **exactly reproduce** all "random" values generated, including cryptographic secrets.

## Security Impact

### Critical Scenarios
- **Session Hijacking**: Predictable session IDs allow account takeover
- **Broken Encryption**: Predictable nonces/IVs enable plaintext recovery
- **Password Cracking**: Predictable salts eliminate salt effectiveness
- **Token Forgery**: Predictable tokens allow authentication bypass

### Example Attack
```rust
// Attacker's code (knowing your seed):
let mut attacker_rng = ChaCha20Rng::seed_from_u64(12345);
let predicted_token = attacker_rng.gen::<u128>();

// Your code (using same seed):
let mut your_rng = ChaCha20Rng::seed_from_u64(12345);
let actual_token = your_rng.gen::<u128>();

assert_eq!(predicted_token, actual_token); // Attack succeeds!
```

## Safe Alternatives

### 1. Operating System Entropy (Best for Crypto)
```rust
use rand::rngs::OsRng;

let mut rng = OsRng;
let token = rng.gen::<u128>();  // Unpredictable!
```

### 2. Thread-Local RNG
```rust
use rand::thread_rng;

let mut rng = thread_rng();
let value = rng.gen::<u64>();  // Properly seeded!
```

### 3. from_entropy() Method
```rust
let mut rng = ChaCha20Rng::from_entropy();
let key = rng.gen::<[u8; 32]>();  // Secure!
```

## Detection Patterns

RUSTCOLA046 detects:

### Vulnerable Patterns
- `seed_from_u64(<constant>)` - most common pattern
- `from_seed(<constant_array>)` - array seed variants
- `::new(<constant>)` - legacy APIs
- `::new_seeded(<constant>)` - explicit seeding

### RNG Types Checked
- `StdRng`, `SmallRng` (rand crate)
- `ChaCha20Rng`, `ChaCha8Rng`, `ChaCha12Rng` (rand_chacha)
- `IsaacRng`, `Isaac64Rng` (rand_isaac)

### Context Awareness
Detections in functions with cryptographic keywords show **CRITICAL** severity:
- `encrypt`, `decrypt`
- `key`, `token`, `session`
- `nonce`, `salt`, `secret`

## Test Results

Expected findings:
- **10 vulnerable functions** (all with constant seeds)
  - 7 in crypto contexts (CRITICAL message prefix)
  - 3 in general contexts
- **7 safe functions** (using OsRng, ThreadRng, from_entropy) - 0 false positives
- **3 edge cases** (test/benchmark contexts) - may trigger but documented

### Vulnerable Functions
1. `vulnerable_constant_seed` - Basic constant seed
2. `vulnerable_crypto_token_generation` - Token with constant seed
3. `vulnerable_nonce_generation` - Nonce with constant seed
4. `vulnerable_password_salt` - Salt with constant seed
5. `vulnerable_key_generation` - Key with constant seed
6. `vulnerable_hmac_secret` - HMAC secret with constant seed
7. `vulnerable_session_id` - Session ID with constant seed
8. `vulnerable_zero_seed` - Zero seed (special case)
9. `vulnerable_small_seed` - Small constant
10. `vulnerable_general_randomness` - Non-crypto constant seed

### Safe Functions
1. `safe_use_os_rng` - OS entropy source
2. `safe_use_thread_rng` - Thread-local RNG
3. `safe_seed_from_entropy` - Seeded from OsRng
4. `safe_from_entropy` - from_entropy() method
5. `safe_crypto_token_generation` - Token with ThreadRng
6. `safe_session_id_generation` - Session ID with OsRng
7. `safe_key_generation` - Key with from_entropy()

## References

- **CWE-330**: Use of Insufficiently Random Values
- **CWE-338**: Use of Cryptographically Weak PRNG
- **OWASP**: Insufficient Entropy
- **NIST SP 800-90A**: Random Number Generation

## Fix Guidance

1. **NEVER use constant seeds** in production code
2. **Use OsRng or thread_rng()** for cryptographic randomness
3. **Use from_entropy()** when you need a specific RNG type
4. **Document deterministic seeds** in tests/benchmarks
5. **Audit all RNG initialization** for hardcoded values

Remember: **Predictable randomness = no randomness at all**
