//! Demonstrates RUSTCOLA048: Invisible Unicode character detection
//!
//! This example shows how invisible Unicode characters can appear in source code.
//! Note: Rust's compiler rejects most invisible Unicode in identifiers,
//! but they can still appear in strings, comments, and MIR output.

// ============================================================================
// VULNERABLE PATTERNS - Would contain invisible Unicode in real scenarios
// ============================================================================

/// This function demonstrates where invisible Unicode might appear
/// The MIR representation may contain Unicode from string processing
pub fn process_user_input() {
    // In real code, this might come from untrusted input that gets embedded
    let data = "admin"; // In real attacks, this could contain zero-width chars
    println!("{}", data);
}

/// String literals can contain invisible Unicode
pub fn vulnerable_string_with_unicode() {
    // This string intentionally contains visible markers where
    // invisible chars would be in a real attack
    let name = "user[ZERO-WIDTH-SPACE]admin";
    println!("{}", name);
}

/// Comments might contain hidden Unicode for Trojan Source attacks
pub fn vulnerable_comment_unicode() {
    // [RTL-OVERRIDE] This comment could hide malicious code
    let is_admin = false;
    println!("Access: {}", is_admin);
}

/// Processed strings from external sources
pub fn vulnerable_external_data() {
    // In production, this data might come from network/files
    // and contain actual invisible Unicode
    let config = "setting[BIDI-EMBED]value";
    println!("{}", config);
}

// ============================================================================
// SAFE PATTERNS - Clean ASCII/visible Unicode
// ============================================================================

/// SAFE: Regular ASCII string
pub fn safe_ascii_string() {
    let message = "Hello, World!";
    println!("{}", message);
}

/// SAFE: Visible Unicode (emojis, non-Latin scripts)
pub fn safe_visible_unicode() {
    let message = "Hello 世界 🦀";
    println!("{}", message);
}

/// SAFE: Standard characters only
pub fn safe_standard_chars() {
    let value = "normal_identifier";
    println!("{}", value);
}

// ============================================================================
// DOCUMENTATION OF THE THREAT
// ============================================================================

/// Trojan Source Attack Example (Conceptual)
///
/// In a real attack, invisible Unicode characters like:
/// - U+200B (ZERO WIDTH SPACE) makes identifiers look identical
/// - U+202E (RTL OVERRIDE) reverses code visually
/// - U+202A (LTR EMBEDDING) changes text direction
///
/// The attack works because what you SEE is not what gets COMPILED.
///
/// Example of what an attacker might try:
/// ```text
/// let access_level = "user";    // What you see
/// let access_level​ = "admin";   // Hidden with U+200B - looks the same!
/// // Now there are TWO different variables with identical appearance
/// ```
pub fn trojan_source_explanation() {
    println!("See documentation for Trojan Source details");
}

#[cfg(test)]
mod tests {
    #[test]
    fn demonstrate_threat() {
        // The threat: Invisible Unicode can make code behave differently
        // than it appears, bypassing code review
        assert!(true);
    }
}

