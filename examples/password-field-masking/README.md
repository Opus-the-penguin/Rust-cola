# Password Field Masking Test Suite (RUSTCOLA061)

This test suite validates detection of password fields that are exposed without proper masking in web forms and templates.

## Problem

**Checkmarx parity**: `Rust_Low_Visibility.Missing_Password_Field_Masking`

Exposing password fields without proper masking can leak credentials through:
- Browser history (if type="text" is used)
- Screen recordings or screenshots
- Server logs if password values are echoed
- Over-the-shoulder viewing

## Test Cases

### Problematic Cases (6 functions - SHOULD be detected)

1. **text_input_for_password**: HTML input using `type="text"` for password field
   - Pattern: `<input type="text" name="password">`
   
2. **password_value_exposed**: Password input with value attribute showing actual password
   - Pattern: `<input value="{}">` with password variable

3. **password_in_response**: Displaying password value in response message
   - Pattern: `format!("Your password is: {}", password)`

4. **password_in_template**: Template rendering that exposes password variable
   - Pattern: `{{password}}` in template string

5. **pwd_field_as_text**: Using pwd/passwd field name with type="text"
   - Pattern: `<input type="text" name="pwd">`

6. **debug_print_password**: Debug output showing password value
   - Pattern: `println!("password={:?}", password)`

### Safe Cases (7 functions - should NOT be detected)

1. **properly_masked_password**: Correct usage of `type="password"`
2. **password_label_only**: Label text mentioning password (not exposing value)
3. **password_placeholder**: Placeholder text (doesn't expose actual value)
4. **success_message_no_password**: Generic success message
5. **password_validation_message**: Validation message (no value exposed)
6. **password_field_name_const**: Defining field name constant
7. **password_length_check**: Checking password length (not exposing value)

## Detection Strategy

The rule uses heuristic pattern matching to identify:

1. **HTML inputs with type="text"** combined with password-related names (password, passwd, pwd, pin)
2. **Format/print macros** that interpolate password variables with `{}` or `{:?}`
3. **Template interpolation** patterns like `{{password}}` or `{password}`
4. **Value attributes** that include password variables

## Expected Results

- **Precision target**: High (minimize false positives on legitimate password mentions)
- **Recall target**: High (catch common exposure patterns)
- **False positives expected**: Possibly on generic password mentions in labels/placeholders

## Running Tests

```bash
cargo build -p password-field-masking
./target/debug/cargo-cola --crate-path examples/password-field-masking
```
