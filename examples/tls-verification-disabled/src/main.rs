//! Test cases for RUSTCOLA084: TLS verification disabled in custom clients
//!
//! This rule detects disabled TLS certificate verification across multiple
//! HTTP/TLS libraries including hyper, native-tls, rustls, and custom clients.

#![allow(dead_code, unused_imports, unused_variables)]

use std::sync::Arc;

// ============================================================================
// PROBLEMATIC PATTERNS - Should be flagged
// ============================================================================

// --- native-tls patterns ---

/// BAD: native-tls with danger_accept_invalid_certs
fn bad_native_tls_accept_invalid_certs() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)  // DANGEROUS!
        .build()
        .unwrap()
}

/// BAD: native-tls with danger_accept_invalid_hostnames
fn bad_native_tls_accept_invalid_hostnames() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_hostnames(true)  // DANGEROUS!
        .build()
        .unwrap()
}

/// BAD: native-tls with both disabled
fn bad_native_tls_both_disabled() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap()
}

// --- rustls patterns ---

/// BAD: rustls with custom verifier that accepts all certs
mod dangerous_verifier {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            // DANGEROUS: Always accepts any certificate!
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

/// BAD: rustls config with dangerous verifier
fn bad_rustls_dangerous_verifier() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()  // Entering dangerous mode!
        .with_custom_certificate_verifier(Arc::new(dangerous_verifier::NoVerifier))
        .with_no_client_auth()
}

// --- reqwest patterns (already covered by RUSTCOLA012, but included for completeness) ---

/// BAD: reqwest with danger_accept_invalid_certs
fn bad_reqwest_danger_certs() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
}

/// BAD: reqwest with danger_accept_invalid_hostnames  
fn bad_reqwest_danger_hostnames() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .danger_accept_invalid_hostnames(true)
}

// --- hyper-tls patterns ---

/// BAD: hyper-tls with native-tls connector that skips verification
fn bad_hyper_tls_no_verify() -> hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
    let mut tls = native_tls::TlsConnector::builder();
    tls.danger_accept_invalid_certs(true);
    let tls = tls.build().unwrap();
    
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.enforce_http(false);
    
    hyper_tls::HttpsConnector::from((http, tls.into()))
}

// ============================================================================
// SAFE PATTERNS - Should NOT be flagged
// ============================================================================

/// SAFE: native-tls with default verification (certs validated)
fn safe_native_tls_default() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .build()
        .unwrap()
}

/// SAFE: native-tls with explicit false (verification enabled)
fn safe_native_tls_explicit_false() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(false)  // Explicitly enabled
        .build()
        .unwrap()
}

/// SAFE: rustls with proper certificate verification
fn safe_rustls_with_roots() -> rustls::ClientConfig {
    let root_store = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
    );
    
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// SAFE: reqwest with default verification
fn safe_reqwest_default() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // No danger methods called
}

/// SAFE: hyper-tls with proper verification
fn safe_hyper_tls_default() -> hyper_tls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
    hyper_tls::HttpsConnector::new()
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Variable controlling danger flag (might be false)
fn edge_conditional_danger(skip_verify: bool) -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(skip_verify)  // Could be true or false
        .build()
        .unwrap()
}

/// EDGE: Danger in test code (common but still risky)
#[cfg(test)]
fn edge_test_only_danger() -> native_tls::TlsConnector {
    native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)  // Test only
        .build()
        .unwrap()
}

fn main() {
    println!("TLS verification test cases");
}
