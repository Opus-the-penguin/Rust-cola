//! SSRF (Server-Side Request Forgery) test cases for RUSTCOLA088
//!
//! CWE-918: Server-Side Request Forgery
//! SSRF vulnerabilities occur when an attacker can control the URL that a server-side
//! application uses to make HTTP requests. This can lead to:
//! - Access to internal services (cloud metadata APIs, internal APIs)
//! - Port scanning of internal networks
//! - Reading local files via file:// protocol
//! - Bypassing firewalls and access controls

use std::env;
use std::io::{self, BufRead};

// ============================================================================
// PROBLEMATIC PATTERNS - Should be detected by RUSTCOLA088
// ============================================================================

/// Bad: Environment variable directly used as URL
fn bad_env_var_url() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("TARGET_URL")?;
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Bad: CLI argument used as URL
fn bad_cli_arg_url() -> Result<String, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let url = &args[1];
    let response = reqwest::blocking::get(url)?;
    Ok(response.text()?)
}

/// Bad: stdin input used as URL
fn bad_stdin_url() -> Result<String, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let url = stdin.lock().lines().next().unwrap()?;
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Bad: Format string with user input
fn bad_format_url() -> Result<String, Box<dyn std::error::Error>> {
    let user_id = env::var("USER_ID")?;
    let url = format!("http://internal-api/users/{}", user_id);
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Bad: User controls host portion
fn bad_user_controlled_host() -> Result<String, Box<dyn std::error::Error>> {
    let host = env::var("API_HOST")?;
    let url = format!("http://{}/api/data", host);
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Bad: Concatenated URL
fn bad_concat_url() -> Result<String, Box<dyn std::error::Error>> {
    let base = "http://api.example.com/fetch?url=";
    let target = env::var("REDIRECT_URL")?;
    let url = base.to_string() + &target;
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Bad: Using ureq with env var URL
fn bad_ureq_env_var() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("WEBHOOK_URL")?;
    let response = ureq::get(&url).call()?;
    Ok(response.into_string()?)
}

/// Bad: Using reqwest Client with user URL
fn bad_reqwest_client() -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::new();
    let url = env::var("CALLBACK_URL")?;
    let response = client.get(&url).send()?;
    Ok(response.text()?)
}

/// Bad: POST request with user-controlled URL
fn bad_post_request() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("SUBMIT_URL")?;
    let response = reqwest::blocking::Client::new()
        .post(&url)
        .body("data")
        .send()?;
    Ok(response.text()?)
}

/// Bad: URL from file contents (indirect user input)
fn bad_url_from_file() -> Result<String, Box<dyn std::error::Error>> {
    let url = std::fs::read_to_string("config/webhook.txt")?;
    let response = reqwest::blocking::get(url.trim())?;
    Ok(response.text()?)
}

/// Bad: Interprocedural - URL passed through helper
fn bad_interprocedural() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("REMOTE_URL")?;
    fetch_remote(&url)
}

fn fetch_remote(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?;
    Ok(response.text()?)
}

/// Bad: Cloud metadata endpoint access possible
fn bad_cloud_metadata_possible() -> Result<String, Box<dyn std::error::Error>> {
    let endpoint = env::var("METADATA_ENDPOINT")?;
    // Attacker could set this to http://169.254.169.254/latest/meta-data/
    let response = reqwest::blocking::get(&endpoint)?;
    Ok(response.text()?)
}

// ============================================================================
// SAFE PATTERNS - Should NOT be detected
// ============================================================================

/// Safe: Hardcoded URL
fn safe_hardcoded_url() -> Result<String, Box<dyn std::error::Error>> {
    let url = "https://api.example.com/public/data";
    let response = reqwest::blocking::get(url)?;
    Ok(response.text()?)
}

/// Safe: URL from constant
const API_ENDPOINT: &str = "https://api.example.com/v1/status";

fn safe_constant_url() -> Result<String, Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(API_ENDPOINT)?;
    Ok(response.text()?)
}

/// Safe: URL validated against allowlist
fn safe_allowlist_validation() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("TARGET_URL")?;
    let allowed = ["https://api.trusted.com", "https://api.partner.com"];

    if !allowed.iter().any(|a| url.starts_with(a)) {
        return Err("URL not in allowlist".into());
    }

    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Safe: URL parsed and host validated
fn safe_parsed_host_validation() -> Result<String, Box<dyn std::error::Error>> {
    let url_str = env::var("TARGET_URL")?;
    let parsed = url::Url::parse(&url_str)?;

    match parsed.host_str() {
        Some("api.trusted.com") | Some("api.partner.com") => {}
        _ => return Err("Invalid host".into()),
    }

    let response = reqwest::blocking::get(url_str)?;
    Ok(response.text()?)
}

/// Safe: Only path portion from user, host is fixed
fn safe_fixed_host_user_path() -> Result<String, Box<dyn std::error::Error>> {
    let resource_id = env::var("RESOURCE_ID")?;
    // Validate resource_id is alphanumeric only
    if !resource_id.chars().all(|c| c.is_alphanumeric()) {
        return Err("Invalid resource ID".into());
    }
    let url = format!("https://api.trusted.com/resources/{}", resource_id);
    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

/// Safe: Scheme validation (only https allowed)
fn safe_scheme_validation() -> Result<String, Box<dyn std::error::Error>> {
    let url_str = env::var("TARGET_URL")?;
    let parsed = url::Url::parse(&url_str)?;

    if parsed.scheme() != "https" {
        return Err("Only HTTPS allowed".into());
    }

    // Additional host validation
    if parsed.host_str() != Some("api.trusted.com") {
        return Err("Invalid host".into());
    }

    let response = reqwest::blocking::get(url_str)?;
    Ok(response.text()?)
}

/// Safe: Internal URL only (no user input)
fn safe_internal_only() -> Result<String, Box<dyn std::error::Error>> {
    let internal_url = "http://localhost:8080/internal/health";
    let response = reqwest::blocking::get(internal_url)?;
    Ok(response.text()?)
}

/// Safe: URL from config with SSRF protection
fn safe_ssrf_protected_fetch() -> Result<String, Box<dyn std::error::Error>> {
    let url_str = env::var("TARGET_URL")?;
    let parsed = url::Url::parse(&url_str)?;

    // Block internal/cloud metadata IPs
    let host = parsed.host_str().unwrap_or("");
    if host == "localhost" 
        || host == "127.0.0.1"
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || host.starts_with("172.")
        || host == "169.254.169.254"  // AWS metadata
        || host.ends_with(".internal")
    {
        return Err("Internal URLs not allowed".into());
    }

    let response = reqwest::blocking::get(url_str)?;
    Ok(response.text()?)
}

/// Safe: Using URL builder with validated components
fn safe_url_builder() -> Result<String, Box<dyn std::error::Error>> {
    let resource = env::var("RESOURCE_NAME")?;

    // Validate resource is safe
    if resource.contains('/') || resource.contains("..") {
        return Err("Invalid resource name".into());
    }

    let mut url = url::Url::parse("https://api.trusted.com")?;
    url.set_path(&format!("/api/v1/{}", resource));

    let response = reqwest::blocking::get(url)?;
    Ok(response.text()?)
}

/// Safe: Regex validation of URL
fn safe_regex_validated() -> Result<String, Box<dyn std::error::Error>> {
    let url = env::var("TARGET_URL")?;

    // Only allow specific URL pattern
    if !url.starts_with("https://api.trusted.com/") {
        return Err("URL must match trusted pattern".into());
    }

    let response = reqwest::blocking::get(&url)?;
    Ok(response.text()?)
}

fn main() {
    println!("SSRF test cases for RUSTCOLA088");

    // List all test functions
    println!("\nProblematic patterns (should detect):");
    println!("  - bad_env_var_url");
    println!("  - bad_cli_arg_url");
    println!("  - bad_stdin_url");
    println!("  - bad_format_url");
    println!("  - bad_user_controlled_host");
    println!("  - bad_concat_url");
    println!("  - bad_ureq_env_var");
    println!("  - bad_reqwest_client");
    println!("  - bad_post_request");
    println!("  - bad_url_from_file");
    println!("  - bad_interprocedural");
    println!("  - bad_cloud_metadata_possible");

    println!("\nSafe patterns (should NOT detect):");
    println!("  - safe_hardcoded_url");
    println!("  - safe_constant_url");
    println!("  - safe_allowlist_validation");
    println!("  - safe_parsed_host_validation");
    println!("  - safe_fixed_host_user_path");
    println!("  - safe_scheme_validation");
    println!("  - safe_internal_only");
    println!("  - safe_ssrf_protected_fetch");
    println!("  - safe_url_builder");
    println!("  - safe_regex_validated");
}
