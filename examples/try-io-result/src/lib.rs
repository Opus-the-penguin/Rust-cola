//! Demonstrates RUSTCOLA051: Try operator on io::Result detection
//!
//! This example shows why using ? directly on io::Result can lose error context.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

// ============================================================================
// PROBLEMATIC PATTERN - Using ? on io::Result
// ============================================================================

/// ❌ PROBLEMATIC: Using ? loses file path context when errors occur
pub fn read_config_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;  // If this fails, we don't know which file!
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;  // Which operation failed?
    Ok(contents)
}

/// ❌ PROBLEMATIC: Multiple IO operations with ? - hard to debug which failed
pub fn copy_file(src: &Path, dest: &Path) -> io::Result<()> {
    let mut source = File::open(src)?;
    let mut destination = File::create(dest)?;
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;
    destination.write_all(&buffer)?;
    Ok(())
}

/// ❌ PROBLEMATIC: Nested IO operations lose context
pub fn process_directory(dir: &Path) -> io::Result<Vec<String>> {
    let mut results = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let content = std::fs::read_to_string(entry.path())?;
        results.push(content);
    }
    Ok(results)
}

// ============================================================================
// BETTER PATTERN - Add context to errors (not detected)
// ============================================================================

/// ✅ BETTER: Use map_err to add file path context
pub fn read_config_with_context(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to open {:?}: {}", path, e)))?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to read {:?}: {}", path, e)))?;
    
    Ok(contents)
}

/// ✅ BETTER: Custom error type with context
#[derive(Debug)]
pub enum ConfigError {
    Io { path: String, source: io::Error },
    Parse(String),
}

pub fn read_config_custom_error(path: &Path) -> Result<String, ConfigError> {
    let mut file = File::open(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    
    Ok(contents)
}

// ============================================================================
// Edge cases
// ============================================================================

/// This should also be detected - indirect io::Result propagation
pub fn chained_io_operations() -> io::Result<()> {
    helper_that_returns_io_result()?;
    Ok(())
}

fn helper_that_returns_io_result() -> io::Result<()> {
    File::create("/tmp/test.txt")?;
    Ok(())
}
