# Hard-coded Cryptographic Keys Test Examples

⚠️ **WARNING: This crate contains INTENTIONAL security vulnerabilities** ⚠️

This crate is part of the Rust-cola SAST tool's test suite for **RUSTCOLA039: Hard-coded cryptographic key detection**.

## About the Vulnerability

Embedding cryptographic keys, secrets, or passwords directly in source code is a critical security vulnerability (CWE-798) that enables:

- **Credential theft**: Anyone with access to the binary can extract the keys
- **Impossible rotation**: Changing keys requires code changes and redeployment
- **Version control exposure**: Keys committed to repositories may be accessible to unauthorized users
- **Compliance violations**: Fails PCI-DSS, HIPAA, and other security standards

## Test Patterns

### Bad Patterns (Should be detected)

1. **bad_hardcoded_aes_key**: Hard-coded AES-256 key as byte string literal
2. **bad_hardcoded_hex_key**: Hard-coded key as hex byte array
3. **bad_hardcoded_hmac_secret**: Hard-coded HMAC secret key
4. **bad_hardcoded_chacha_key**: Hard-coded ChaCha20 key and nonce
5. **bad_hardcoded_password**: Hard-coded password in variable
6. **bad_hardcoded_token**: Hard-coded API token (long string)

### Good Patterns (Should NOT be detected)

1. **good_env_key**: Load key from environment variable
2. **good_config_key**: Load key from external configuration file
3. **good_generated_key**: Generate key at runtime using CSPRNG
4. **good_key_parameter**: Accept key as function parameter
5. **good_kms_key**: Fetch key from key management service (AWS KMS, Azure Key Vault, etc.)

## Safe Alternatives

Instead of hard-coding keys, use these secure patterns:

```rust
// Environment variables
let key = std::env::var("ENCRYPTION_KEY")?;

// Configuration files (with proper permissions)
let key = std::fs::read("/secure/path/secret.key")?;

// Key Management Services
// AWS KMS
let key = kms_client.decrypt(&encrypted_key_blob).await?;

// Runtime generation
use rand::RngCore;
let mut key = vec![0u8; 32];
rand::thread_rng().fill_bytes(&mut key);

// Secret management services
// - HashiCorp Vault
// - AWS Secrets Manager
// - Azure Key Vault
// - Google Secret Manager
```

## Security Best Practices

1. **Never commit secrets to version control**
2. **Use environment-specific configuration**
3. **Implement key rotation policies**
4. **Use hardware security modules (HSMs) for production**
5. **Audit access to key management systems**
6. **Encrypt keys at rest and in transit**

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)

## Scanner Configuration

This crate should be **excluded** from security scans or marked as a false positive. The vulnerabilities are intentional test cases.
