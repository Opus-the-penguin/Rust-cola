//! Demonstrates RUSTCOLA053: Untrimmed stdin detection
//!
//! Reading lines from stdin without trimming can enable injection attacks.

use std::io::{self, BufRead};
use std::process::Command;

// ============================================================================
// PROBLEMATIC PATTERN - Reading stdin without trimming
// ============================================================================

/// ❌ PROBLEMATIC: Reading filename from stdin without trimming the newline
pub fn read_file_from_stdin_untrimmed() -> io::Result<String> {
    let stdin = io::stdin();
    let mut filename = String::new();
    stdin.lock().read_line(&mut filename)?;
    
    // filename still contains trailing newline!
    // If used in file operations, this creates wrong paths
    std::fs::read_to_string(&filename)
}

/// ❌ PROBLEMATIC: Command argument from stdin without trimming
pub fn execute_command_untrimmed() -> io::Result<()> {
    let stdin = io::stdin();
    let mut command = String::new();
    stdin.lock().read_line(&mut command)?;
    
    // command contains newline - can enable injection!
    Command::new("sh")
        .arg("-c")
        .arg(&command)  // Dangerous: untrimmed input to shell
        .status()?;
    
    Ok(())
}

/// ❌ PROBLEMATIC: Reading lines iterator without trimming
pub fn process_lines_untrimmed() -> io::Result<Vec<String>> {
    let stdin = io::stdin();
    let lines: Vec<String> = stdin.lock()
        .lines()
        .collect::<io::Result<Vec<String>>>()?;
    
    // Each line still may have trailing whitespace
    // If used in commands/paths, this is dangerous
    Ok(lines)
}

/// ❌ PROBLEMATIC: Multiple inputs without trimming
pub fn read_user_and_password_untrimmed() -> io::Result<(String, String)> {
    let stdin = io::stdin();
    let mut user = String::new();
    let mut password = String::new();
    
    stdin.lock().read_line(&mut user)?;
    stdin.lock().read_line(&mut password)?;
    
    // Both contain newlines - authentication will fail or be exploitable
    Ok((user, password))
}

// ============================================================================
// BETTER PATTERN - Trim input after reading
// ============================================================================

/// ✅ BETTER: Trim the newline before using
pub fn read_file_from_stdin_trimmed() -> io::Result<String> {
    let stdin = io::stdin();
    let mut filename = String::new();
    stdin.lock().read_line(&mut filename)?;
    
    let filename = filename.trim();  // Remove trailing newline
    std::fs::read_to_string(filename)
}

/// ✅ BETTER: Trim before passing to command
pub fn execute_command_trimmed() -> io::Result<()> {
    let stdin = io::stdin();
    let mut command = String::new();
    stdin.lock().read_line(&mut command)?;
    
    let command = command.trim();  // Safe
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()?;
    
    Ok(())
}

/// ✅ BETTER: Trim each line after reading
pub fn process_lines_trimmed() -> io::Result<Vec<String>> {
    let stdin = io::stdin();
    let lines: Vec<String> = stdin.lock()
        .lines()
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .map(|line| line.trim().to_string())  // Trim each line
        .collect();
    
    Ok(lines)
}

/// ✅ BETTER: Trim both inputs
pub fn read_user_and_password_trimmed() -> io::Result<(String, String)> {
    let stdin = io::stdin();
    let mut user = String::new();
    let mut password = String::new();
    
    stdin.lock().read_line(&mut user)?;
    stdin.lock().read_line(&mut password)?;
    
    // Trim both before use
    Ok((user.trim().to_string(), password.trim().to_string()))
}
