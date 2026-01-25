//! Cryptographic security rules.
//!
//! Rules detecting weak or insecure cryptographic practices:
//! - Weak hash algorithms (MD5, SHA-1, RIPEMD, CRC32)
//! - Hardcoded cryptographic keys
//! - Weak cipher algorithms (DES, 3DES, RC4)
//! - Predictable randomness
//! - Timing attack vulnerabilities
//! - TLS verification disabled

use crate::{
    Confidence, Exploitability, Finding, MirPackage, Rule, RuleMetadata, RuleOrigin, Severity,
};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ============================================================================
// Helper Functions
// ============================================================================

pub(crate) fn line_contains_md5_usage(line: &str) -> bool {
    let lower = line.to_lowercase();
    let mut search_start = 0;

    while let Some(relative_idx) = lower[search_start..].find("md5") {
        let idx = search_start + relative_idx;

        let mut before_chars = lower[..idx].chars().rev().skip_while(|c| c.is_whitespace());
        let mut after_chars = lower[idx + 3..].chars().skip_while(|c| c.is_whitespace());

        let after_matches = matches!(
            (after_chars.next(), after_chars.next()),
            (Some(':'), Some(':'))
        );

        let before_first = before_chars.next();
        let before_second = before_chars.next();
        let before_matches = matches!((before_first, before_second), (Some(':'), Some(':')));

        if before_matches || after_matches {
            return true;
        }

        search_start = idx + 3;
    }

    false
}

pub(crate) fn line_contains_sha1_usage(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.contains("sha1::") || lower.contains("::sha1")
}

pub(crate) fn line_contains_weak_hash_extended(line: &str) -> bool {
    let lower = line.to_lowercase();

    // Skip const string assignments and hex dumps entirely
    if lower.contains("= [const \"") || lower.contains("const \"") {
        return false;
    }
    if lower.starts_with("0x") || (lower.contains("0x") && lower.contains("│")) {
        return false;
    }

    // RIPEMD family (all variants are deprecated)
    if lower.contains("ripemd") {
        if lower.contains("ripemd::")
            || lower.contains("::ripemd")
            || lower.contains("ripemd128")
            || lower.contains("ripemd160")
            || lower.contains("ripemd256")
            || lower.contains("ripemd320")
        {
            return true;
        }
    }

    // CRC family (non-cryptographic checksums)
    if lower.contains("crc") {
        if lower.contains("crc::")
            || lower.contains("::crc")
            || lower.contains("crc32")
            || lower.contains("crc_32")
            || lower.contains("crc16")
            || lower.contains("crc_16")
            || lower.contains("crc64")
            || lower.contains("crc_64")
        {
            return true;
        }
    }

    // Adler32 (non-cryptographic checksum)
    if lower.contains("adler")
        && (lower.contains("adler::") || lower.contains("::adler") || lower.contains("adler32"))
    {
        return true;
    }

    false
}

fn filter_entry(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    !name.starts_with('.') && name != "target"
}

// ============================================================================
// RUSTCOLA004: Insecure MD5 Hash
// ============================================================================

pub struct InsecureMd5Rule {
    metadata: RuleMetadata,
}

impl InsecureMd5Rule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA004".to_string(),
                name: "insecure-hash-md5".to_string(),
                short_description: "Usage of MD5 hashing".to_string(),
                full_description: "Detects calls into md5 hashing APIs which are considered cryptographically broken.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for InsecureMd5Rule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_md5_usage(line))
                .map(|line| line.trim().to_string())
                .collect();
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Insecure MD5 hashing detected in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                confidence: Confidence::Medium,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA005: Insecure SHA-1 Hash
// ============================================================================

pub struct InsecureSha1Rule {
    metadata: RuleMetadata,
}

impl InsecureSha1Rule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA005".to_string(),
                name: "insecure-hash-sha1".to_string(),
                short_description: "Usage of SHA-1 hashing".to_string(),
                full_description: "Detects SHA-1 hashing APIs which are deprecated for security-sensitive contexts.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for InsecureSha1Rule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("line_contains_sha1_usage") {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_sha1_usage(line))
                .map(|line| line.trim().to_string())
                .collect();
            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!("Insecure SHA-1 hashing detected in `{}`", function.name),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                confidence: Confidence::Medium,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA062: Weak Hashing Extended (RIPEMD, CRC, Adler)
// ============================================================================

pub struct WeakHashingExtendedRule {
    metadata: RuleMetadata,
}

impl WeakHashingExtendedRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA062".to_string(),
                name: "weak-hashing-extended".to_string(),
                short_description: "Usage of weak cryptographic hash algorithms".to_string(),
                full_description: "Detects usage of weak or deprecated cryptographic hash algorithms beyond MD5/SHA-1, including RIPEMD (all variants), CRC32, CRC32Fast, and Adler32. These algorithms should not be used for security-sensitive operations like password hashing, authentication tokens, or cryptographic signatures. Use SHA-256, SHA-3, BLAKE2, or BLAKE3 instead.".to_string(),
                help_uri: None,
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for WeakHashingExtendedRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("WeakHashingExtendedRule")
                || function.name.contains("line_contains_weak_hash_extended")
            {
                continue;
            }

            let evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line_contains_weak_hash_extended(line))
                .map(|line| line.trim().to_string())
                .collect();

            if evidence.is_empty() {
                continue;
            }

            findings.push(Finding {
                rule_id: self.metadata.id.clone(),
                rule_name: self.metadata.name.clone(),
                severity: self.metadata.default_severity,
                message: format!(
                    "Weak cryptographic hash algorithm detected in `{}`",
                    function.name
                ),
                function: function.name.clone(),
                function_signature: function.signature.clone(),
                evidence,
                span: function.span.clone(),
                confidence: Confidence::Medium,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                code_snippet: None,
                exploitability: Exploitability::default(),
                exploitability_score: Exploitability::default().score(),
            });
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA039: Hardcoded Crypto Key
// ============================================================================

pub struct HardcodedCryptoKeyRule {
    metadata: RuleMetadata,
}

impl HardcodedCryptoKeyRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA039".to_string(),
                name: "hardcoded-crypto-key".to_string(),
                short_description: "Hard-coded cryptographic key or IV".to_string(),
                full_description: "Detects hard-coded cryptographic keys, initialization vectors, or secrets in source code. Embedded secrets cannot be rotated without code changes, enable credential theft if the binary is reverse-engineered, and violate security best practices. Use environment variables, configuration files, or secret management services instead.".to_string(),
                help_uri: Some("https://cwe.mitre.org/data/definitions/798.html".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn crypto_key_patterns() -> &'static [&'static str] {
        &[
            "Aes128::new",
            "Aes192::new",
            "Aes256::new",
            "ChaCha20::new",
            "ChaCha20Poly1305::new",
            "Hmac::new_from_slice",
            "GenericArray::from_slice",
            "Key::from_slice",
            "Cipher::new",
        ]
    }

    fn suspicious_var_names() -> &'static [&'static str] {
        &["key", "secret", "password", "token", "iv", "nonce", "salt"]
    }

    fn is_suspicious_assignment(line: &str, pattern: &str) -> bool {
        let lower_line = line.to_lowercase();
        let lower_pattern = pattern.to_lowercase();

        if !lower_line.contains(&lower_pattern) {
            return false;
        }

        if !line.contains('=') {
            return false;
        }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return false;
        }

        let left_side = parts[0].trim().to_lowercase();
        let right_side = parts[1].trim();

        let has_pattern_in_identifier = Self::has_word_boundary_match(&left_side, &lower_pattern);

        if !has_pattern_in_identifier {
            return false;
        }

        // Check if right side contains a literal value
        if right_side.contains("b\"") || right_side.contains("b'") {
            return true;
        }
        if right_side.contains("&[") || right_side.contains("[0x") || right_side.contains("[0u8") {
            return true;
        }
        if right_side.starts_with('"') && right_side.len() > 30 {
            // Filter out URL paths - these are not secrets
            if Self::is_likely_url_path(right_side) {
                return false;
            }
            return true;
        }
        if right_side.starts_with('"')
            && right_side.chars().filter(|c| c.is_ascii_hexdigit()).count() > 20
        {
            return true;
        }

        false
    }

    /// Check if a string value looks like a URL path rather than a secret
    fn is_likely_url_path(value: &str) -> bool {
        let lower = value.to_lowercase();
        // URL paths start with "/" or contain path patterns
        lower.contains("\"/") ||           // Starts with /
        lower.contains("http://") ||
        lower.contains("https://") ||
        lower.contains("/api/") ||
        lower.contains("/v1/") ||
        lower.contains("/v2/") ||
        lower.contains("/v3/") ||
        lower.contains("/v4/") ||
        lower.contains("/auth/") ||
        lower.contains("/oauth/") ||
        lower.contains("/token/") ||       // Token endpoint path
        lower.contains("/configure/") ||
        lower.contains("/admin/")
    }

    fn has_word_boundary_match(text: &str, pattern: &str) -> bool {
        if let Some(pos) = text.find(pattern) {
            let before_ok = if pos == 0 {
                true
            } else {
                let char_before = text.chars().nth(pos - 1).unwrap_or(' ');
                !char_before.is_alphanumeric() || char_before == '_'
            };

            let after_pos = pos + pattern.len();
            let after_ok = if after_pos >= text.len() {
                true
            } else {
                let char_after = text.chars().nth(after_pos).unwrap_or(' ');
                !char_after.is_alphanumeric()
            };

            before_ok && after_ok
        } else {
            false
        }
    }
}

impl Rule for HardcodedCryptoKeyRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        if !crate_root.exists() {
            return findings;
        }

        for entry in WalkDir::new(crate_root)
            .into_iter()
            .filter_entry(|e| filter_entry(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lines: Vec<&str> = content.lines().collect();

            for (idx, line) in lines.iter().enumerate() {
                let trimmed = line.trim();

                if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                    continue;
                }

                for pattern in Self::crypto_key_patterns() {
                    if trimmed.contains(pattern) {
                        if trimmed.contains("b\"")
                            || trimmed.contains("&[")
                            || trimmed.contains("[0x")
                        {
                            let location = format!("{}:{}", rel_path, idx + 1);

                            findings.push(Finding::new(
                                self.metadata.id.clone(),
                                self.metadata.name.clone(),
                                self.metadata.default_severity,
                                "Hard-coded cryptographic key or IV detected in source code",
                                location,
                                pattern.to_string(),
                                vec![trimmed.to_string()],
                                None,
                            ));
                        }
                    }
                }

                for var_pattern in Self::suspicious_var_names() {
                    if Self::is_suspicious_assignment(trimmed, var_pattern) {
                        let location = format!("{}:{}", rel_path, idx + 1);

                        findings.push(Finding::new(
                            self.metadata.id.clone(),
                            self.metadata.name.clone(),
                            self.metadata.default_severity,
                            format!(
                                "Potential hard-coded secret in variable containing '{}'",
                                var_pattern
                            ),
                            location,
                            var_pattern.to_string(),
                            vec![trimmed.to_string()],
                            None,
                        ));
                    }
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA044: Timing Attack (Non-constant-time secret comparison)
// ============================================================================

pub struct TimingAttackRule {
    metadata: RuleMetadata,
}

impl TimingAttackRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA044".to_string(),
                name: "timing-attack-secret-comparison".to_string(),
                short_description: "Non-constant-time secret comparison".to_string(),
                full_description: "Detects comparisons of secrets (passwords, tokens, HMACs) using non-constant-time operations like == or .starts_with(). These can leak information through timing side-channels. Use constant_time_eq or subtle::ConstantTimeEq instead.".to_string(),
                help_uri: Some("https://codahale.com/a-lesson-in-timing-attacks/".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn looks_like_secret(var_name: &str) -> bool {
        let lowered = var_name.to_lowercase();
        let secret_markers = [
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "key",
            "hmac",
            "signature",
            "auth",
            "credential",
            "api_key",
            "apikey",
        ];
        secret_markers.iter().any(|marker| lowered.contains(marker))
    }

    fn is_non_constant_time_comparison(line: &str) -> bool {
        let lowered = line.to_lowercase();

        if lowered.contains("constant_time_eq")
            || lowered.contains("constanttimeeq")
            || lowered.contains("subtle::")
        {
            return false;
        }

        if lowered.contains(" == ")
            || lowered.contains(" != ")
            || lowered.contains(".eq(")
            || lowered.contains(".ne(")
            || lowered.contains(".starts_with(")
            || lowered.contains(".ends_with(")
        {
            let words: Vec<&str> = line
                .split(&[' ', '(', ')', ',', ';', '=', '!'][..])
                .filter(|w| !w.is_empty())
                .collect();

            return words.iter().any(|w| Self::looks_like_secret(w));
        }

        false
    }
}

impl Rule for TimingAttackRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        if package.crate_name == "mir-extractor" {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let crate_root = Path::new(&package.crate_root);

        if !crate_root.exists() {
            return findings;
        }

        for entry in WalkDir::new(crate_root)
            .into_iter()
            .filter_entry(|e| filter_entry(e))
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            if path.extension() != Some(OsStr::new("rs")) {
                continue;
            }

            let rel_path = path
                .strip_prefix(crate_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (idx, line) in content.lines().enumerate() {
                if line.trim().starts_with("//") {
                    continue;
                }

                if Self::is_non_constant_time_comparison(line) {
                    let location = format!("{}:{}", rel_path, idx + 1);

                    findings.push(Finding::new(
                        self.metadata.id.clone(),
                        self.metadata.name.clone(),
                        self.metadata.default_severity,
                        "Secret comparison using non-constant-time operation; vulnerable to timing attacks",
                        location,
                        String::new(),
                        vec![line.trim().to_string()],
                        None,
                    ));
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA045: Weak Cipher Usage
// ============================================================================

pub struct WeakCipherRule {
    metadata: RuleMetadata,
}

impl WeakCipherRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA045".to_string(),
                name: "weak-cipher-usage".to_string(),
                short_description: "Weak or deprecated cipher algorithm".to_string(),
                full_description: "Detects use of cryptographically broken or deprecated ciphers including DES, 3DES, RC4, RC2, and Blowfish. These algorithms have known vulnerabilities and should not be used for security-sensitive operations. Use modern algorithms like AES-256-GCM or ChaCha20-Poly1305 instead.".to_string(),
                help_uri: Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn contains_weak_cipher(line: &str) -> bool {
        let lowered = line.to_lowercase();

        if lowered.trim_start().starts_with("//") {
            return false;
        }

        let weak_patterns = [
            "::des::",
            "::des<",
            " des::",
            "<des>",
            "cipher::des",
            "block_modes::des",
            "des_ede3",
            "tripledes",
            "::tdes::",
            "::tdes<",
            "tdesede",
            "::rc4::",
            "::rc4<",
            " rc4::",
            "<rc4>",
            "cipher::rc4",
            "stream_cipher::rc4",
            "::rc2::",
            "::rc2<",
            " rc2::",
            "<rc2>",
            "cipher::rc2",
            "::blowfish::",
            "::blowfish<",
            " blowfish::",
            "<blowfish>",
            "cipher::blowfish",
            "block_modes::blowfish",
            "::arcfour::",
            " arcfour::",
            "::cast5::",
            " cast5::",
        ];

        for pattern in weak_patterns {
            if lowered.contains(pattern) {
                if lowered.contains("alloc") && (lowered.contains("0x") || lowered.contains("│"))
                {
                    continue;
                }
                return true;
            }
        }

        false
    }
}

impl Rule for WeakCipherRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("WeakCipherRule")
                || function.name.contains("contains_weak_cipher")
            {
                continue;
            }

            for line in &function.body {
                if Self::contains_weak_cipher(line) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!(
                            "Weak or deprecated cipher algorithm detected in `{}`",
                            function.name
                        ),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.trim().to_string()],
                        span: function.span.clone(),
                        confidence: Confidence::Medium,
                        cwe_ids: Vec::new(),
                        fix_suggestion: None,
                        code_snippet: None,
                        exploitability: Exploitability::default(),
                        exploitability_score: Exploitability::default().score(),
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA046: Predictable Randomness
// ============================================================================

pub struct PredictableRandomnessRule {
    metadata: RuleMetadata,
}

impl PredictableRandomnessRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA046".to_string(),
                name: "predictable-randomness".to_string(),
                short_description: "Predictable random number generation".to_string(),
                full_description: "Detects RNG initialization using constant or hardcoded seeds. Predictable randomness is a critical security flaw in cryptographic operations, session token generation, and nonce creation. Use cryptographically secure random sources like OsRng, ThreadRng, or properly seeded RNGs from entropy sources.".to_string(),
                help_uri: Some("https://owasp.org/www-community/vulnerabilities/Insecure_Randomness".to_string()),
                default_severity: Severity::High,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }

    fn is_predictable_seed(line: &str) -> bool {
        let lowered = line.to_lowercase();

        if lowered.trim_start().starts_with("//") {
            return false;
        }
        if lowered.contains("alloc") && (lowered.contains("0x") || lowered.contains("│")) {
            return false;
        }

        if lowered.contains("seed_from_u64") {
            if lowered.contains("const") && (lowered.contains("_u64") || lowered.contains("_i64")) {
                return true;
            }
        }

        if lowered.contains("from_seed") {
            if lowered.contains("const") && lowered.contains("[") {
                return true;
            }
        }

        let seedable_rngs = [
            "stdrng::seed_from_u64",
            "chacharng::seed_from_u64",
            "chacha8rng::seed_from_u64",
            "chacha12rng::seed_from_u64",
            "chacha20rng::seed_from_u64",
            "isaacrng::seed_from_u64",
            "isaac64rng::seed_from_u64",
            "smallrng::seed_from_u64",
        ];

        for rng in seedable_rngs {
            if lowered.contains(rng) && lowered.contains("const") {
                return true;
            }
        }

        false
    }
}

impl Rule for PredictableRandomnessRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            if function.name.contains("PredictableRandomnessRule")
                || function.name.contains("is_predictable_seed")
            {
                continue;
            }

            for line in &function.body {
                if Self::is_predictable_seed(line) {
                    findings.push(Finding {
                        rule_id: self.metadata.id.clone(),
                        rule_name: self.metadata.name.clone(),
                        severity: self.metadata.default_severity,
                        message: format!("Predictable RNG seed detected in `{}`", function.name),
                        function: function.name.clone(),
                        function_signature: function.signature.clone(),
                        evidence: vec![line.trim().to_string()],
                        span: function.span.clone(),
                        confidence: Confidence::Medium,
                        cwe_ids: Vec::new(),
                        fix_suggestion: None,
                        code_snippet: None,
                        exploitability: Exploitability::default(),
                        exploitability_score: Exploitability::default().score(),
                    });
                }
            }
        }

        findings
    }
}

// ============================================================================
// RUSTCOLA011: Modulo Bias in Random
// ============================================================================

pub struct ModuloBiasRandomRule {
    metadata: RuleMetadata,
}

impl ModuloBiasRandomRule {
    pub fn new() -> Self {
        Self {
            metadata: RuleMetadata {
                id: "RUSTCOLA011".to_string(),
                name: "modulo-bias-random".to_string(),
                short_description: "Modulo bias in random number generation".to_string(),
                full_description: "Detects patterns where random numbers are reduced using modulo (%), which can introduce statistical bias. For cryptographic or security contexts, use proper bounded range generation methods like gen_range().".to_string(),
                help_uri: None,
                default_severity: Severity::Medium,
                origin: RuleOrigin::BuiltIn,
                cwe_ids: Vec::new(),
                fix_suggestion: None,
                exploitability: Exploitability::default(),
            },
        }
    }
}

impl Rule for ModuloBiasRandomRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn evaluate(
        &self,
        package: &MirPackage,
        _inter_analysis: Option<&crate::interprocedural::InterProceduralAnalysis>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for function in &package.functions {
            // Skip self-references
            if function.name.contains("ModuloBiasRandomRule") {
                continue;
            }

            // Look for random generation followed by modulo
            let has_random = function.body.iter().any(|line| {
                let lower = line.to_lowercase();
                lower.contains("::random()")
                    || lower.contains(".next_u32()")
                    || lower.contains(".next_u64()")
                    || lower.contains(".gen::<")
                    || lower.contains("getrandom")
            });

            if !has_random {
                continue;
            }

            // Look for modulo operation in MIR (Rem operator)
            let modulo_evidence: Vec<String> = function
                .body
                .iter()
                .filter(|line| line.contains("Rem(") || line.contains(" % "))
                .map(|line| line.trim().to_string())
                .collect();

            if !modulo_evidence.is_empty() {
                findings.push(Finding {
                    rule_id: self.metadata.id.clone(),
                    rule_name: self.metadata.name.clone(),
                    severity: self.metadata.default_severity,
                    message: format!(
                        "Potential modulo bias in random number generation in `{}`",
                        function.name
                    ),
                    function: function.name.clone(),
                    function_signature: function.signature.clone(),
                    evidence: modulo_evidence,
                    span: function.span.clone(),
                    confidence: Confidence::Medium,
                    cwe_ids: Vec::new(),
                    fix_suggestion: None,
                    code_snippet: None,
                    exploitability: Exploitability::default(),
                    exploitability_score: Exploitability::default().score(),
                });
            }
        }

        findings
    }
}

/// Register all crypto rules with the rule engine.
pub fn register_crypto_rules(engine: &mut crate::RuleEngine) {
    engine.register_rule(Box::new(InsecureMd5Rule::new()));
    engine.register_rule(Box::new(InsecureSha1Rule::new()));
    engine.register_rule(Box::new(WeakHashingExtendedRule::new()));
    engine.register_rule(Box::new(HardcodedCryptoKeyRule::new()));
    engine.register_rule(Box::new(TimingAttackRule::new()));
    engine.register_rule(Box::new(WeakCipherRule::new()));
    engine.register_rule(Box::new(PredictableRandomnessRule::new()));
    engine.register_rule(Box::new(ModuloBiasRandomRule::new()));
}
