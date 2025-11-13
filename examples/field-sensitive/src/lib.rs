use std::process::Command;

/// Struct with multiple fields to test field-sensitive analysis
#[derive(Default)]
pub struct UserData {
    pub username: String,
    pub password: String,
    pub email: String,
}

/// Test: Only password field is tainted, username is clean
pub fn test_partial_struct_taint() {
    let mut user = UserData::default();
    
    // Clean assignment
    user.username = "admin".to_string();
    
    // Tainted assignment - from environment
    user.password = std::env::args().nth(1).unwrap_or_default();
    
    // Clean assignment
    user.email = "admin@example.com".to_string();
    
    // Should be SAFE - username is not tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&user.username)  // Clean field
        .spawn();
    
    // Should be VULNERABLE - password is tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&user.password)  // Tainted field
        .spawn();
}

/// Test: Entire struct is tainted
pub fn test_full_struct_taint() {
    // Entire struct initialized with tainted data
    let tainted_input = std::env::args().nth(1).unwrap_or_default();
    
    let user = UserData {
        username: tainted_input.clone(),
        password: tainted_input.clone(),
        email: tainted_input,
    };
    
    // Should be VULNERABLE - all fields are tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&user.username)
        .spawn();
}

/// Test: Nested struct fields
pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub struct Account {
    pub id: u32,
    pub credentials: Credentials,
    pub active: bool,
}

pub fn test_nested_field_taint() {
    let mut account = Account {
        id: 1,
        credentials: Credentials {
            username: "user".to_string(),
            password: String::new(),
        },
        active: true,
    };
    
    // Only the nested password field is tainted
    account.credentials.password = std::env::args().nth(1).unwrap_or_default();
    
    // Should be SAFE - id is not tainted
    println!("Account ID: {}", account.id);
    
    // Should be SAFE - username is not tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&account.credentials.username)
        .spawn();
    
    // Should be VULNERABLE - password is tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&account.credentials.password)
        .spawn();
}

/// Test: Field-to-field propagation
pub fn test_field_to_field() {
    let mut user1 = UserData::default();
    let mut user2 = UserData::default();
    
    // Taint user1.password
    user1.password = std::env::args().nth(1).unwrap_or_default();
    
    // Copy tainted field to another struct
    user2.password = user1.password.clone();
    
    // Should be VULNERABLE - taint propagated
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&user2.password)
        .spawn();
    
    // But username should still be clean
    user2.username = "clean".to_string();
    
    // Should be SAFE
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&user2.username)
        .spawn();
}

/// Test: Tuple struct fields
pub struct Config(pub String, pub String, pub u32);

pub fn test_tuple_struct() {
    let mut config = Config(
        "localhost".to_string(),
        "8080".to_string(),
        42,
    );
    
    // Taint only field .1
    config.1 = std::env::args().nth(1).unwrap_or_default();
    
    // Should be SAFE - field .0 is clean
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&config.0)
        .spawn();
    
    // Should be VULNERABLE - field .1 is tainted
    let _ = Command::new("sh")
        .arg("-c")
        .arg(&config.1)
        .spawn();
}
