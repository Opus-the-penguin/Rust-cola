# RUSTCOLA053: Untrimmed Stdin Lines

## Problem

Reading lines from stdin without trimming leaves trailing newlines and whitespace in the strings. This seemingly minor oversight can enable serious security vulnerabilities:

1. **Command Injection**: Newlines in shell commands can execute additional commands
2. **Path Traversal**: Newlines in file paths create invalid paths or enable directory traversal
3. **Authentication Bypass**: Whitespace in credentials may bypass validation or create timing attacks
4. **Log Injection**: Newlines in log data can forge log entries
5. **SQL Injection**: In concatenated SQL, newlines can break out of quoted strings

## Example

### ❌ Problematic (no trimming)

```rust
use std::io::{self, BufRead};
use std::process::Command;

pub fn execute_user_command() -> io::Result<()> {
    let stdin = io::stdin();
    let mut command = String::new();
    stdin.lock().read_line(&mut command)?;
    
    // command = "ls\n" (includes newline!)
    Command::new("sh")
        .arg("-c")
        .arg(&command)  // Dangerous!
        .status()?;
    
    Ok(())
}
```

**If user enters:** `ls; rm -rf /`

**command contains:** `"ls; rm -rf /\n"`

**Shell executes:** Both commands! The newline doesn't prevent the injection.

### ✅ Better (with trimming)

```rust
pub fn execute_user_command() -> io::Result<()> {
    let stdin = io::stdin();
    let mut command = String::new();
    stdin.lock().read_line(&mut command)?;
    
    let command = command.trim();  // Remove newline and whitespace
    
    // Better: now validate/sanitize the trimmed input
    if command.contains(';') || command.contains('&') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid command"));
    }
    
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()?;
    
    Ok(())
}
```

## Real-World Attack Scenarios

### File Path Injection

```rust
// User enters: "../../../etc/passwd\n"
let mut path = String::new();
stdin.lock().read_line(&mut path)?;

// path = "../../../etc/passwd\n"
// File operations will fail OR create wrong files
std::fs::write(&path, data)?;  // Creates file with newline in name!
```

### Authentication Bypass

```rust
// User enters: "admin\n"
let mut username = String::new();
stdin.lock().read_line(&mut username)?;

// username = "admin\n"
if username == "admin" {  // FALSE! Because of newline
    grant_access();
}

// But timing attacks can detect the comparison still processes "admin"
```

### Log Injection

```rust
let mut user_input = String::new();
stdin.lock().read_line(&mut user_input)?;

// user_input = "innocent\nADMIN: Access granted to root\n"
println!("User entered: {}", user_input);
// Output:
// User entered: innocent
// ADMIN: Access granted to root
//
// Forged admin log entry!
```

## Detection

This rule detects functions that:
1. Read from stdin using `read_line()` or `.lines()`
2. Don't call `.trim()`, `.trim_end()`, or `.trim_start()` on the result
3. May pass untrimmed data to sensitive operations

## How to Fix

Always trim stdin input:

```rust
// For read_line
let mut input = String::new();
stdin.lock().read_line(&mut input)?;
let input = input.trim();  // Remove trailing newline

// For lines() iterator
let lines: Vec<String> = stdin.lock()
    .lines()
    .collect::<io::Result<Vec<_>>>()?
    .into_iter()
    .map(|s| s.trim().to_string())  // Trim each line
    .collect();
```

## Parity

- Sonar: RSPEC-7441
- Semgrep: Similar patterns for other languages

## Severity

**Medium** - Can enable injection attacks, but requires additional unsafe usage of the untrimmed input. Defense-in-depth: trim first, validate second.
