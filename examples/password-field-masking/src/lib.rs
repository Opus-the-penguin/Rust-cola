// Test cases for RUSTCOLA061: Missing password field masking in web forms
// Checkmarx parity: Rust_Low_Visibility.Missing_Password_Field_Masking

// ==================== PROBLEMATIC CASES ====================

/// Pattern 1: HTML input with type="text" for password field
/// SHOULD BE FLAGGED: Password field using type="text" instead of type="password"
pub fn text_input_for_password() {
    let html = r#"<input type="text" name="password" />"#;
    println!("{}", html);
}

/// Pattern 2: Password field with value attribute showing password
/// SHOULD BE FLAGGED: Echoing password value back to user
pub fn password_value_exposed() {
    let password = "secret123";
    let html = format!(r#"<input type="password" name="password" value="{}" />"#, password);
    println!("{}", html);
}

/// Pattern 3: Displaying password in response message
/// SHOULD BE FLAGGED: Showing password in plain text response
pub fn password_in_response() {
    let password = "userpass";
    let message = format!("Your password is: {}", password);
    println!("{}", message);
}

/// Pattern 4: Template rendering with exposed password
/// SHOULD BE FLAGGED: Template variable showing password
pub fn password_in_template() {
    let html = r#"<div>Password: {{password}}</div>"#;
    println!("{}", html);
}

/// Pattern 5: Form input with pwd field as text
/// SHOULD BE FLAGGED: Using pwd/passwd with type="text"
pub fn pwd_field_as_text() {
    let html = r#"<input type="text" name="pwd" placeholder="Enter password" />"#;
    println!("{}", html);
}

/// Pattern 6: Debug printing password value
/// SHOULD BE FLAGGED: Printing password in debug output
pub fn debug_print_password() {
    let password = "secret";
    println!("Debug: password={:?}", password);
}

// ==================== SAFE CASES ====================

/// Safe: Properly masked password input
/// Should NOT be flagged: Using type="password" correctly
pub fn properly_masked_password() {
    let html = r#"<input type="password" name="password" />"#;
    println!("{}", html);
}

/// Safe: Password label without exposing value
/// Should NOT be flagged: Just mentioning "password" in label text
pub fn password_label_only() {
    let html = r#"<label for="pwd">Enter your password:</label>"#;
    println!("{}", html);
}

/// Safe: Password placeholder text
/// Should NOT be flagged: Placeholder is just hint text
pub fn password_placeholder() {
    let html = r#"<input type="password" name="password" placeholder="Password" />"#;
    println!("{}", html);
}

/// Safe: Success message without showing password
/// Should NOT be flagged: Generic success message
pub fn success_message_no_password() {
    println!("Password updated successfully");
}

/// Safe: Password validation message
/// Should NOT be flagged: Validation message doesn't expose value
pub fn password_validation_message() {
    let message = "Password must be at least 8 characters";
    println!("{}", message);
}

/// Safe: Using const for password field name
/// Should NOT be flagged: Just defining a constant
pub fn password_field_name_const() {
    const PASSWORD_FIELD: &str = "password";
    println!("Field name: {}", PASSWORD_FIELD);
}

/// Safe: Checking password length without exposing value
/// Should NOT be flagged: Length check doesn't reveal password
pub fn password_length_check() {
    let password = "secret123";
    println!("Password length: {}", password.len());
}
