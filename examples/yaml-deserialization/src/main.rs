//! Test cases for RUSTCOLA089: Insecure YAML Deserialization
//! 
//! Detects untrusted input (env vars, CLI args, stdin, file contents) flowing to
//! serde_yaml deserialization functions without validation. Attackers can craft
//! malicious YAML to cause:
//! - Billion laughs / YAML bombs (exponential entity expansion via anchors)
//! - Denial of service through deeply nested structures
//! - Unexpected type coercion attacks
//! - Deserialization of unintended types

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::{self, BufRead, Read};

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    name: String,
    value: i32,
}

#[derive(Debug, Deserialize)]
struct UserInput {
    command: String,
    args: Vec<String>,
}

// ============================================================================
// BAD PATTERNS - Untrusted input flows to YAML deserialization
// ============================================================================

/// BAD: Environment variable directly deserialized as YAML
fn bad_env_var_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let yaml_content = env::var("CONFIG_YAML")?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// BAD: CLI argument used as YAML content
fn bad_cli_arg_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let config: Config = serde_yaml::from_str(&args[1])?;
        return Ok(config);
    }
    Err("No argument provided".into())
}

/// BAD: stdin read directly into YAML parser
fn bad_stdin_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut yaml_content = String::new();
    stdin.lock().read_to_string(&mut yaml_content)?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// BAD: File path from env var, file contents deserialized
fn bad_file_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let file_path = env::var("CONFIG_FILE")?;
    let yaml_content = fs::read_to_string(&file_path)?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// BAD: from_slice with untrusted bytes
fn bad_from_slice_env() -> Result<Config, Box<dyn std::error::Error>> {
    let yaml_bytes = env::var("CONFIG_YAML")?.into_bytes();
    let config: Config = serde_yaml::from_slice(&yaml_bytes)?;
    Ok(config)
}

/// BAD: from_reader with untrusted source
fn bad_from_reader_stdin() -> Result<Config, Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let config: Config = serde_yaml::from_reader(stdin.lock())?;
    Ok(config)
}

/// BAD: Deserialize user input struct from env
fn bad_user_input_yaml() -> Result<UserInput, Box<dyn std::error::Error>> {
    let yaml_content = env::var("USER_INPUT")?;
    let input: UserInput = serde_yaml::from_str(&yaml_content)?;
    Ok(input)
}

/// BAD: Multiple env vars concatenated into YAML
fn bad_concat_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let name = env::var("NAME")?;
    let value = env::var("VALUE")?;
    let yaml_content = format!("name: {}\nvalue: {}", name, value);
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// BAD: File from CLI arg, then deserialized
fn bad_cli_file_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let yaml_content = fs::read_to_string(&args[1])?;
        let config: Config = serde_yaml::from_str(&yaml_content)?;
        return Ok(config);
    }
    Err("No file path provided".into())
}

/// BAD: Network-like pattern (file simulating network data)
fn bad_network_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let endpoint = env::var("API_ENDPOINT")?;
    // Simulating fetched content stored in temp file
    let response_file = format!("/tmp/response_{}.yaml", endpoint.replace("/", "_"));
    let yaml_content = fs::read_to_string(&response_file)?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

// Helper function that takes a string and deserializes - for interprocedural test
fn parse_yaml_config(yaml_str: &str) -> Result<Config, serde_yaml::Error> {
    serde_yaml::from_str(yaml_str)
}

/// BAD: Interprocedural - env var flows through helper function
fn bad_interprocedural() -> Result<Config, Box<dyn std::error::Error>> {
    let yaml_content = env::var("CONFIG_YAML")?;
    let config = parse_yaml_config(&yaml_content)?;
    Ok(config)
}

// ============================================================================
// SAFE PATTERNS - Proper validation or hardcoded sources
// ============================================================================

/// SAFE: Hardcoded YAML content
fn safe_hardcoded_yaml() -> Result<Config, serde_yaml::Error> {
    let yaml_content = "name: test\nvalue: 42";
    serde_yaml::from_str(yaml_content)
}

/// SAFE: Constant YAML embedded in binary
const EMBEDDED_CONFIG: &str = r#"
name: embedded
value: 100
"#;

fn safe_const_yaml() -> Result<Config, serde_yaml::Error> {
    serde_yaml::from_str(EMBEDDED_CONFIG)
}

/// SAFE: Validated structure before use (schema validation)
fn safe_validated_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let yaml_content = env::var("CONFIG_YAML")?;
    
    // Validation: check for dangerous patterns
    if yaml_content.contains("<<:") || yaml_content.contains("&") || yaml_content.contains("*") {
        return Err("YAML anchors/aliases not allowed".into());
    }
    
    // Size limit
    if yaml_content.len() > 10000 {
        return Err("YAML too large".into());
    }
    
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// SAFE: Parse as JSON instead (no anchors/aliases)
fn safe_json_instead() -> Result<Config, Box<dyn std::error::Error>> {
    let json_content = env::var("CONFIG_JSON")?;
    let config: Config = serde_json::from_str(&json_content)?;
    Ok(config)
}

/// SAFE: Allowlist validation of input
fn safe_allowlist_check() -> Result<Config, Box<dyn std::error::Error>> {
    let config_name = env::var("CONFIG_NAME")?;
    
    // Only allow specific config names
    let allowed = ["production", "staging", "development"];
    if !allowed.contains(&config_name.as_str()) {
        return Err("Invalid config name".into());
    }
    
    // Load from predefined path based on validated name
    let yaml_content = format!("name: {}\nvalue: 1", config_name);
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// SAFE: Internal configuration file with fixed path
fn safe_internal_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Fixed internal path, not user-controlled
    let yaml_content = fs::read_to_string("/etc/myapp/config.yaml")?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// SAFE: Schema validation with serde attributes
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictConfig {
    name: String,
    #[serde(default)]
    value: i32,
}

fn safe_strict_schema() -> Result<StrictConfig, Box<dyn std::error::Error>> {
    let yaml_content = env::var("CONFIG_YAML")?;
    // deny_unknown_fields provides some protection
    let config: StrictConfig = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// SAFE: Depth-limited parsing (conceptual - would need custom deserializer)
fn safe_depth_limited() -> Result<Config, Box<dyn std::error::Error>> {
    let yaml_content = env::var("CONFIG_YAML")?;
    
    // Count nesting depth (simplified check)
    let depth = yaml_content.matches("  ").count();
    if depth > 10 {
        return Err("YAML nesting too deep".into());
    }
    
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

/// SAFE: Pre-process to remove dangerous constructs
fn safe_sanitized_yaml() -> Result<Config, Box<dyn std::error::Error>> {
    let mut yaml_content = env::var("CONFIG_YAML")?;
    
    // Remove anchor definitions and references
    yaml_content = yaml_content.replace("&", "").replace("*", "").replace("<<:", "");
    
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    Ok(config)
}

fn main() {
    println!("YAML Deserialization Security Test Cases");
    
    // These would be called based on actual input in real scenarios
    match safe_hardcoded_yaml() {
        Ok(config) => println!("Hardcoded config: {:?}", config),
        Err(e) => println!("Error: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_safe_hardcoded() {
        assert!(safe_hardcoded_yaml().is_ok());
    }
    
    #[test]
    fn test_safe_const() {
        assert!(safe_const_yaml().is_ok());
    }
}
