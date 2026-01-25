//! Inter-procedural taint analysis test cases
//!
//! This library contains test cases for Phase 3 inter-procedural analysis.
//! Each function represents a different scenario we need to handle.

use std::process::Command;

// =============================================================================
// TEST CASE 1: Basic Two-Level Flow
// =============================================================================

/// VULNERABLE: Taint flows from env → get_input() → main → execute_command()
pub fn test_two_level_flow() {
    let input = get_user_input();
    execute_command(&input);
}

fn get_user_input() -> String {
    std::env::args().nth(1).unwrap_or_default()
}

fn execute_command(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

// =============================================================================
// TEST CASE 2: Three-Level Flow
// =============================================================================

/// VULNERABLE: Taint flows through 3 functions
pub fn test_three_level_flow() {
    let data = fetch_data();
    let cmd = build_command(&data);
    run_command(&cmd);
}

fn fetch_data() -> String {
    std::env::var("USER_INPUT").unwrap_or_default()
}

fn build_command(input: &str) -> String {
    format!("echo {}", input)
}

fn run_command(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

// =============================================================================
// TEST CASE 3: Sanitization in Helper Function
// =============================================================================

/// SAFE: Input is sanitized in validate_input() before reaching sink
pub fn test_helper_sanitization() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let safe = validate_input(&input);
    execute_validated_command(&safe);
}

fn validate_input(input: &str) -> String {
    // Sanitization: parse as integer, converting back to string
    input
        .parse::<i32>()
        .ok()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn execute_validated_command(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

// =============================================================================
// TEST CASE 4: Partial Sanitization
// =============================================================================

/// VULNERABLE: Only one path is sanitized
pub fn test_partial_sanitization() {
    let input = std::env::args().nth(1).unwrap_or_default();

    if input.contains("safe") {
        let safe = validate_input(&input);
        execute_command(&safe);
    } else {
        // This path is NOT sanitized
        execute_command(&input);
    }
}

// =============================================================================
// TEST CASE 5: Return Value Propagation
// =============================================================================

/// VULNERABLE: Tainted return value flows to sink
pub fn test_return_propagation() {
    let data = get_tainted_data();
    process_data(&data);
}

fn get_tainted_data() -> String {
    std::env::var("MALICIOUS_INPUT").unwrap_or_default()
}

fn process_data(data: &str) {
    let _ = Command::new("sh").arg("-c").arg(data).spawn();
}

// =============================================================================
// TEST CASE 6: Parameter Passing - By Value
// =============================================================================

/// VULNERABLE: Taint passed by value
pub fn test_pass_by_value() {
    let tainted =
        String::from_utf8_lossy(&std::fs::read("/tmp/user_input").unwrap_or_default()).to_string();

    consume_and_execute(tainted);
}

fn consume_and_execute(cmd: String) {
    let _ = Command::new("sh").arg("-c").arg(&cmd).spawn();
}

// =============================================================================
// TEST CASE 7: Parameter Passing - By Reference
// =============================================================================

/// VULNERABLE: Taint passed by reference
pub fn test_pass_by_reference() {
    let tainted = std::env::var("CMD").unwrap_or_default();
    execute_by_ref(&tainted);
}

fn execute_by_ref(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

// =============================================================================
// TEST CASE 8: Mutable Reference Flow
// =============================================================================

/// VULNERABLE: Taint flows through mutable reference
pub fn test_mutable_ref_flow() {
    let mut data = std::env::args().nth(1).unwrap_or_default();
    modify_data(&mut data);
    execute_command(&data);
}

fn modify_data(data: &mut String) {
    data.push_str(" && echo done");
}

// =============================================================================
// TEST CASE 9: Multiple Sources
// =============================================================================

/// VULNERABLE: Multiple taint sources, any could reach sink
pub fn test_multiple_sources() {
    let source1 = std::env::var("VAR1").unwrap_or_default();
    let source2 = std::env::args().nth(1).unwrap_or_default();

    if source1.is_empty() {
        execute_command(&source2);
    } else {
        execute_command(&source1);
    }
}

// =============================================================================
// TEST CASE 10: Safe Constant Propagation
// =============================================================================

/// SAFE: Constant data, not tainted
pub fn test_safe_constant() {
    let safe_cmd = get_safe_command();
    execute_command(&safe_cmd);
}

fn get_safe_command() -> String {
    "echo Hello World".to_string()
}

// =============================================================================
// TEST CASE 11: Context-Sensitive Analysis
// =============================================================================

/// MIXED: Same function called with tainted and safe data
pub fn test_context_sensitive() {
    let tainted = std::env::args().nth(1).unwrap_or_default();
    let safe = "echo safe";

    // First call: VULNERABLE
    process_and_execute(&tainted);

    // Second call: SAFE
    process_and_execute(safe);
}

fn process_and_execute(data: &str) {
    let _ = Command::new("sh").arg("-c").arg(data).spawn();
}

// =============================================================================
// TEST CASE 12: Branching with Sanitization
// =============================================================================

/// MIXED: One branch sanitized, one not
pub fn test_branching_sanitization() {
    let input = std::env::args().nth(1).unwrap_or_default();

    if input.starts_with("safe:") {
        let sanitized = sanitize_safe_prefix(&input);
        execute_command(&sanitized);
    } else {
        // VULNERABLE: No sanitization on this branch
        execute_command(&input);
    }
}

fn sanitize_safe_prefix(input: &str) -> String {
    input
        .strip_prefix("safe:")
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

// =============================================================================
// TEST CASE 13: Helper Function Chain
// =============================================================================

/// VULNERABLE: Taint flows through chain of helpers
pub fn test_helper_chain() {
    let input = read_user_input();
    let formatted = format_input(&input);
    let command = build_shell_command(&formatted);
    execute_command(&command);
}

fn read_user_input() -> String {
    std::env::var("USER_CMD").unwrap_or_default()
}

fn format_input(input: &str) -> String {
    format!("Command: {}", input)
}

fn build_shell_command(formatted: &str) -> String {
    formatted.to_string()
}

// =============================================================================
// TEST CASE 14: Sanitization Verification
// =============================================================================

/// SAFE: chars().all() validation
pub fn test_validation_check() {
    let input = std::env::args().nth(1).unwrap_or_default();

    if is_safe_input(&input) {
        execute_command(&input);
    }
}

fn is_safe_input(input: &str) -> bool {
    input.chars().all(|c| c.is_alphanumeric())
}

// =============================================================================
// TEST CASE 15: Closure Capture (Future: Phase 3.5)
// =============================================================================

/// VULNERABLE: Taint captured by closure
#[allow(dead_code)]
pub fn test_closure_capture() {
    let tainted = std::env::args().nth(1).unwrap_or_default();

    let closure = || {
        let _ = Command::new("sh").arg("-c").arg(&tainted).spawn();
    };

    closure();
}

// =============================================================================
// TEST CASE 16: Trait Method (Future: Phase 3.5)
// =============================================================================

trait Executor {
    fn execute(&self, cmd: &str);
}

struct ShellExecutor;

impl Executor for ShellExecutor {
    fn execute(&self, cmd: &str) {
        let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
    }
}

/// VULNERABLE: Taint through trait method
#[allow(dead_code)]
pub fn test_trait_method() {
    let input = std::env::args().nth(1).unwrap_or_default();
    let executor: Box<dyn Executor> = Box::new(ShellExecutor);
    executor.execute(&input);
}

// =============================================================================
// TEST CASE 17: Async Function (Future: Phase 3.5)
// =============================================================================

#[allow(dead_code)]
async fn get_async_input() -> String {
    std::env::var("ASYNC_INPUT").unwrap_or_default()
}

#[allow(dead_code)]
async fn execute_async(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).spawn();
}

/// VULNERABLE: Taint through async functions
#[allow(dead_code)]
pub async fn test_async_flow() {
    let input = get_async_input().await;
    execute_async(&input).await;
}

// =============================================================================
// TEST CASE 18: Mutable Reference Propagation
// =============================================================================

/// VULNERABLE: Taint flows from src to dest via mutable reference
pub fn test_mutable_ref_propagation() {
    let source = std::env::var("BAD").unwrap_or_default();
    let mut dest = String::new();
    propagate_taint(&mut dest, &source);
    execute_command(&dest);
}

fn propagate_taint(dest: &mut String, src: &str) {
    dest.push_str(src);
}

// =============================================================================
// Expected Results Summary
// =============================================================================

/// Expected analysis results for each test case
pub fn expected_results() -> Vec<(&'static str, bool)> {
    vec![
        ("test_two_level_flow", true),          // VULNERABLE
        ("test_three_level_flow", true),        // VULNERABLE
        ("test_helper_sanitization", false),    // SAFE
        ("test_partial_sanitization", true),    // VULNERABLE (one path)
        ("test_return_propagation", true),      // VULNERABLE
        ("test_pass_by_value", true),           // VULNERABLE
        ("test_pass_by_reference", true),       // VULNERABLE
        ("test_mutable_ref_flow", true),        // VULNERABLE
        ("test_mutable_ref_propagation", true), // VULNERABLE
        ("test_multiple_sources", true),        // VULNERABLE
        ("test_safe_constant", false),          // SAFE
        ("test_context_sensitive", true),       // VULNERABLE (one context)
        ("test_branching_sanitization", true),  // VULNERABLE (one branch)
        ("test_helper_chain", true),            // VULNERABLE
        ("test_validation_check", false),       // SAFE
                                                // Closures, traits, async: Phase 3.5
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_results_count() {
        let results = expected_results();
        assert_eq!(results.len(), 15); // 14 basic cases, 3 advanced for later

        let vulnerable_count = results.iter().filter(|(_, vuln)| *vuln).count();
        let safe_count = results.iter().filter(|(_, vuln)| !*vuln).count();

        println!("Expected vulnerable: {}", vulnerable_count);
        println!("Expected safe: {}", safe_count);

        assert_eq!(vulnerable_count, 11);
        assert_eq!(safe_count, 4);
    }
}
