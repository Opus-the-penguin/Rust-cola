//! Test cases for RUSTCOLA091: Insecure JSON/TOML Deserialization
//!
//! This tests detection of untrusted input flowing to JSON/TOML parsers.
//! While JSON/TOML don't have YAML's billion laughs vulnerability,
//! deeply nested structures can still cause stack overflow or memory exhaustion.

use serde::Deserialize;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::net::TcpStream;

#[derive(Debug, Deserialize)]
struct Config {
    name: String,
    value: i32,
}

// ============================================================================
// BAD PATTERNS - Should trigger RUSTCOLA091
// ============================================================================

/// BAD: Environment variable directly into JSON parser
fn bad_env_var_json() -> Result<Config, Box<dyn std::error::Error>> {
    let json_str = env::var("CONFIG_JSON")?;
    let config: Config = serde_json::from_str(&json_str)?;
    Ok(config)
}

/// BAD: CLI argument directly into JSON parser
fn bad_cli_arg_json() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let config: Config = serde_json::from_str(&args[1])?;
        return Ok(config);
    }
    Err("No argument provided".into())
}

/// BAD: File contents into JSON without validation
fn bad_file_json() -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string("config.json")?;
    let config: Config = serde_json::from_str(&contents)?;
    Ok(config)
}

/// BAD: Stdin directly into JSON parser
fn bad_stdin_json() -> Result<Config, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut json_content = String::new();
    stdin.lock().read_to_string(&mut json_content)?;
    let config: Config = serde_json::from_str(&json_content)?;
    Ok(config)
}

/// BAD: Network data into JSON parser
fn bad_network_json() -> Result<Config, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect("example.com:8080")?;
    let mut json_data = String::new();
    stream.read_to_string(&mut json_data)?;
    let config: Config = serde_json::from_str(&json_data)?;
    Ok(config)
}

/// BAD: from_slice with untrusted bytes
fn bad_from_slice_json() -> Result<Config, Box<dyn std::error::Error>> {
    let bytes = fs::read("config.json")?;
    let config: Config = serde_json::from_slice(&bytes)?;
    Ok(config)
}

/// BAD: from_reader with untrusted source
fn bad_from_reader_json() -> Result<Config, Box<dyn std::error::Error>> {
    let file = fs::File::open("config.json")?;
    let config: Config = serde_json::from_reader(file)?;
    Ok(config)
}

/// BAD: Environment variable into TOML parser
fn bad_env_var_toml() -> Result<Config, Box<dyn std::error::Error>> {
    let toml_str = env::var("CONFIG_TOML")?;
    let config: Config = toml::from_str(&toml_str)?;
    Ok(config)
}

/// BAD: File contents into TOML without validation
fn bad_file_toml() -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

/// BAD: Stdin into TOML parser
fn bad_stdin_toml() -> Result<Config, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut toml_content = String::new();
    stdin.lock().read_to_string(&mut toml_content)?;
    let config: Config = toml::from_str(&toml_content)?;
    Ok(config)
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA091
// ============================================================================

/// SAFE: Hardcoded JSON string
fn safe_hardcoded_json() -> Result<Config, serde_json::Error> {
    let json = r#"{"name": "test", "value": 42}"#;
    serde_json::from_str(json)
}

/// SAFE: Const JSON string
fn safe_const_json() -> Result<Config, serde_json::Error> {
    const JSON: &str = r#"{"name": "config", "value": 100}"#;
    serde_json::from_str(JSON)
}

/// SAFE: Hardcoded TOML string
fn safe_hardcoded_toml() -> Result<Config, toml::de::Error> {
    let toml = r#"
        name = "test"
        value = 42
    "#;
    toml::from_str(toml)
}

/// SAFE: JSON with size validation before parsing
fn safe_size_limited_json() -> Result<Config, Box<dyn std::error::Error>> {
    let json_str = env::var("CONFIG_JSON")?;
    if json_str.len() > 1024 {
        return Err("JSON too large".into());
    }
    let config: Config = serde_json::from_str(&json_str)?;
    Ok(config)
}

/// SAFE: JSON with size check before parsing
fn safe_depth_limited_json() -> Result<Config, Box<dyn std::error::Error>> {
    let json_str = env::var("CONFIG_JSON")?;
    // Size check protects against memory exhaustion
    if json_str.len() > 4096 {
        return Err("JSON too large".into());
    }
    let config: Config = serde_json::from_str(&json_str)?;
    Ok(config)
}

/// SAFE: Internal-only config from trusted path
fn safe_internal_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Hardcoded trusted path
    let config: Config = serde_json::from_str(include_str!("../Cargo.toml"))?;
    Ok(config)
}

/// SAFE: Validated JSON structure before parsing
fn safe_validated_json() -> Result<Config, Box<dyn std::error::Error>> {
    let json_str = env::var("CONFIG_JSON")?;
    // Pre-validation: check for deeply nested structures
    let depth = json_str.matches('{').count();
    if depth > 10 {
        return Err("JSON too deeply nested".into());
    }
    let config: Config = serde_json::from_str(&json_str)?;
    Ok(config)
}

/// SAFE: Using streaming JSON parser
fn safe_streaming_json() -> Result<Vec<Config>, Box<dyn std::error::Error>> {
    use serde_json::Deserializer;
    let json_str = env::var("CONFIG_JSON")?;
    // Streaming deserializer allows processing item-by-item
    let stream = Deserializer::from_str(&json_str).into_iter::<Config>();
    let mut configs = Vec::new();
    for item in stream.take(100) {  // Limit items
        configs.push(item?);
    }
    Ok(configs)
}

fn main() {
    // Run the functions to prevent dead code warnings
    let _ = bad_env_var_json();
    let _ = bad_cli_arg_json();
    let _ = bad_file_json();
    let _ = bad_stdin_json();
    let _ = bad_network_json();
    let _ = bad_from_slice_json();
    let _ = bad_from_reader_json();
    let _ = bad_env_var_toml();
    let _ = bad_file_toml();
    let _ = bad_stdin_toml();
    
    let _ = safe_hardcoded_json();
    let _ = safe_const_json();
    let _ = safe_hardcoded_toml();
    let _ = safe_size_limited_json();
    let _ = safe_depth_limited_json();
    let _ = safe_internal_config();
    let _ = safe_validated_json();
    let _ = safe_streaming_json();
}
