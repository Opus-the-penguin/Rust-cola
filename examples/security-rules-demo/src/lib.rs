// Demo file to test new security rules RUSTCOLA042-044

#[cfg(test)]
mod tests {
    use cookie::Cookie;

    // RUSTCOLA042: Should detect - cookie without .secure(true)
    pub fn insecure_cookie_bad() {
        let cookie = Cookie::build(("session", "abc123"))
            .path("/")
            .http_only(true)
            .finish();  // Missing .secure(true)
    }

    // Should NOT detect - cookie has .secure(true)
    pub fn secure_cookie_good() {
        let cookie = Cookie::build(("session", "xyz789"))
            .path("/")
            .http_only(true)
            .secure(true)  // Good!
            .finish();
    }

    // RUSTCOLA043: Should detect - CORS wildcard
    pub fn cors_wildcard_bad() {
        // Example patterns that should be detected
        let _header = ("Access-Control-Allow-Origin", "*");  // Bad!
    }

    // RUSTCOLA044: Should detect - timing attack on password
    pub fn timing_attack_bad(input_password: &str, stored_password: &str) -> bool {
        input_password == stored_password  // Bad! Non-constant-time comparison
    }

    // Should NOT detect - uses constant-time comparison
    pub fn timing_attack_good(input_password: &str, stored_password: &str) -> bool {
        use subtle::ConstantTimeEq;
        input_password.as_bytes().ct_eq(stored_password.as_bytes()).into()
    }

    // RUSTCOLA044: Should detect - timing attack on token
    pub fn token_check_bad(user_token: &str, expected_token: &str) -> bool {
        user_token.starts_with(expected_token)  // Bad! Early return on mismatch
    }

    // RUSTCOLA044: Should detect - HMAC comparison  
    pub fn hmac_verify_bad(computed_hmac: &[u8], provided_hmac: &[u8]) -> bool {
        computed_hmac == provided_hmac  // Bad!
    }
}
