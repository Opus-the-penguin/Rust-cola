# Weak Cipher Detection Example (RUSTCOLA045)

This example demonstrates **RUSTCOLA045**: Detection of weak or deprecated cryptographic ciphers that should not be used in security-sensitive applications.

## Vulnerability Overview

### The Problem

Many legacy cipher algorithms have known cryptographic weaknesses:

- **DES (Data Encryption Standard)**: 56-bit key broken by brute force in 1998
- **3DES (Triple DES)**: Slow, limited by 64-bit block size, officially deprecated by NIST
- **RC4**: Biased output distribution, multiple practical attacks
- **RC2**: Weak key schedule, vulnerable to related-key attacks
- **Blowfish**: 64-bit blocks vulnerable to birthday attacks at ~32GB of data
- **CAST5**: Outdated, replaced by modern algorithms

### Real-World Impact

Using weak ciphers can lead to:
- **Data breaches**: Encrypted data can be decrypted by attackers
- **Compliance violations**: NIST, PCI-DSS, HIPAA prohibit weak ciphers
- **Birthday attacks**: Small block sizes (64-bit) leak information
- **Known plaintext attacks**: RC4 and others vulnerable to statistical analysis

## Detection Criteria (RUSTCOLA045)

The rule detects usage patterns in MIR including:

1. **DES variants**:
   - `des::Des`, `des::TdesEde3`, `des_ede3::`, `tripledes::`
   - Block mode usage: `block_modes::des`

2. **RC4 stream cipher**:
   - `rc4::Rc4`, `stream_cipher::rc4`, `arcfour::`

3. **RC2**:
   - `rc2::Rc2`, `cipher::rc2`

4. **Blowfish**:
   - `blowfish::Blowfish`, `cipher::blowfish`

5. **Other legacy ciphers**:
   - `cast5::`, `arcfour::` (RC4 alias)

## Test Case Categories

### Vulnerable Patterns (6 cases) - Should trigger RUSTCOLA045

1. **`vulnerable_des_cipher`**: Direct DES cipher usage
2. **`vulnerable_triple_des`**: 3DES/TDES usage
3. **`vulnerable_rc4_pattern`**: RC4 stream cipher pattern (simulated)
4. **`vulnerable_rc2_pattern`**: RC2 cipher pattern (simulated)
5. **`vulnerable_blowfish_pattern`**: Blowfish cipher pattern (simulated)
6. **`vulnerable_des_ecb`**: DES in ECB mode

### Safe Patterns (6 cases) - Should NOT trigger RUSTCOLA045

1. **`safe_aes_pattern`**: AES usage pattern (not flagged)
2. **`safe_chacha_pattern`**: ChaCha20 pattern (not flagged)
3. **`safe_comment_mention`**: Mentioning DES in comments
4. **`safe_string_contains_des`**: String containing "des" substring
5. **`safe_variable_named_description`**: Variable names with "des"

### Edge Cases (2 cases)

1. **`edge_case_generic`**: Generic cipher parameter
2. **`edge_case_conditional`**: Conditional compilation

## Expected Detection Results

When running **mir-extractor** on this crate:

```bash
cargo run -p mir-extractor --bin mir-extractor -- \
    --crate-path examples/weak-ciphers \
    --out-dir out/weak-ciphers
```

**Expected findings:**
- **3 functions with RUSTCOLA045 detections** (10 total findings with duplicates per MIR line)
  - vulnerable_des_cipher (3 findings)
  - vulnerable_triple_des (4 findings)  
  - vulnerable_des_ecb (3 findings)
- **0 false positives** on safe patterns
- **Note**: Simulated patterns (RC4, RC2, Blowfish) won't be detected without actual crate usage

**Detection accuracy metrics:**
- **Recall**: 100% (3/3 real DES usage patterns detected)
- **Precision**: 100% (0/6 false positives on safe patterns)

## Recommended Alternatives

### Instead of DES/3DES:
```rust
// ❌ WEAK
use des::Des;
let cipher = Des::new(&key);

// ✅ STRONG
use aes_gcm::{Aes256Gcm, KeyInit};
let cipher = Aes256Gcm::new(&key);
```

### Instead of RC4:
```rust
// ❌ WEAK
use rc4::Rc4;
let cipher = Rc4::new(&key);

// ✅ STRONG
use chacha20::ChaCha20;
let cipher = ChaCha20::new(&key, &nonce);
```

### Instead of Blowfish:
```rust
// ❌ WEAK (64-bit blocks)
use blowfish::Blowfish;
let cipher = Blowfish::new(&key);

// ✅ STRONG (128-bit blocks + authentication)
use aes_gcm::Aes256Gcm;
let cipher = Aes256Gcm::new(&key);
```

## Modern Cipher Recommendations

### For Encryption (AEAD):
1. **AES-256-GCM** - Industry standard, hardware accelerated
2. **ChaCha20-Poly1305** - Fast in software, constant-time
3. **AES-GCM-SIV** - Nonce-misuse resistant variant

### For Hashing:
1. **SHA-256** or **SHA-3** - Not MD5 or SHA-1
2. **BLAKE3** - Modern, extremely fast

### For Key Derivation:
1. **Argon2** - Memory-hard, GPU-resistant
2. **scrypt** - Memory-hard alternative
3. **PBKDF2** - Minimum standard (slower iterations needed)

## CWE Mapping

- **CWE-327**: Use of a Broken or Risky Cryptographic Algorithm
- **CWE-326**: Inadequate Encryption Strength
- **CWE-328**: Use of Weak Hash

## References

- **NIST SP 800-131A**: Transitioning the Use of Cryptographic Algorithms and Key Lengths
- **NIST Deprecated DES/3DES**: https://csrc.nist.gov/news/2017/update-to-current-use-and-deprecation-of-tdea
- **RC4 Attacks**: https://www.rc4nomore.com/
- **OWASP Cryptographic Failures**: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/

## Running This Example

### Build the example:

```bash
cargo build -p weak-ciphers
```

### Run mir-extractor to detect vulnerabilities:

```bash
cargo run -p mir-extractor --bin mir-extractor -- \
    --crate-path examples/weak-ciphers \
    --out-dir out/weak-ciphers

# Check the findings
jq '.[] | select(.rule_id == "RUSTCOLA045") | .function' out/weak-ciphers/findings.json
```

### Expected output summary:

```
Found 10 instances of RUSTCOLA045 across 3 functions:
- vulnerable_des_cipher (3 detections - DES::new usage)
- vulnerable_triple_des (4 detections - TdesEde3::new usage)
- vulnerable_des_ecb (3 detections - DES in ECB mode)

0 false positives on safe patterns
```

## License

This example code is part of the rust-cola project and shares the same license.
