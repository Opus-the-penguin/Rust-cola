// Test cases for RUSTCOLA056: OpenOptions Inconsistent Flags
//
// This module tests detection of OpenOptions with dangerous or inconsistent
// flag combinations that suggest programmer confusion or potential bugs.

use std::fs::OpenOptions;
use std::io;

// PROBLEMATIC: create(true) without write(true) - useless
pub fn create_without_write(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .create(true)  // Creates the file but...
        .read(true)    // ...only opens it for reading. Create is useless here.
        .open(path)?;
    Ok(())
}

// PROBLEMATIC: create_new(true) without write(true) - useless
pub fn create_new_without_write(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .create_new(true)  // Creates new file but...
        .read(true)        // ...only opens it for reading. Create is useless.
        .open(path)?;
    Ok(())
}

// PROBLEMATIC: truncate(true) without write(true) - dangerous data loss
pub fn truncate_without_write(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .truncate(true)  // Truncates file to zero length...
        .read(true)      // ...but can't write. Data lost for no reason!
        .open(path)?;
    Ok(())
}

// PROBLEMATIC: append(true) with truncate(true) - contradictory
pub fn append_with_truncate(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .append(true)    // Preserve existing content
        .truncate(true)  // Delete existing content - contradictory!
        .open(path)?;
    Ok(())
}

// SAFE: write(true) with create(true) - standard pattern
pub fn write_with_create(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;
    Ok(())
}

// SAFE: write(true) with truncate(true) - clear intent
pub fn write_with_truncate(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    Ok(())
}

// SAFE: write(true) with append(true) - append mode
pub fn write_with_append(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)?;
    Ok(())
}

// SAFE: write(true) with create(true) and truncate(true) - complete pattern
pub fn write_create_truncate(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    Ok(())
}

// SAFE: read-only access - no write, no create
pub fn read_only(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .open(path)?;
    Ok(())
}

// SAFE: append mode with create
pub fn append_with_create(path: &str) -> io::Result<()> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    Ok(())
}
