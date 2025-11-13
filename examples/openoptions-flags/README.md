# OpenOptions Inconsistent Flags Test Cases

This example demonstrates detection of `OpenOptions` with dangerous or inconsistent flag combinations.

## The Problem

Rust's `std::fs::OpenOptions` provides a builder API for opening files with specific access modes. However, certain combinations of flags are:

1. **Useless**: Create a file but don't make it writable
2. **Dangerous**: Truncate a file but can't write to it (data loss)
3. **Contradictory**: Both append and truncate (preserve and delete content)

These patterns suggest programmer confusion about file I/O operations and can lead to bugs or data loss.

## Common Mistakes

### Pattern 1: create() without write()

```rust
// WRONG: Creates file but can't write to it
OpenOptions::new()
    .create(true)   // File is created but...
    .read(true)     // ...only readable. Create flag is useless!
    .open(path)?;
```

The `create(true)` flag is pointless if the file isn't writable. This suggests the programmer intended to write but forgot to add `.write(true)`.

### Pattern 2: truncate() without write()

```rust
// DANGEROUS: Deletes file contents but can't write new data
OpenOptions::new()
    .truncate(true)  // Deletes all existing data...
    .read(true)      // ...but can't write anything. Data loss!
    .open(path)?;
```

This is particularly dangerous because it **deletes all file content** but doesn't allow writing new data. The file ends up empty.

### Pattern 3: append() with truncate()

```rust
// CONTRADICTORY: Preserve AND delete existing content?
OpenOptions::new()
    .write(true)
    .append(true)    // Preserve existing content
    .truncate(true)  // Delete existing content
    .open(path)?;    // Which one wins?
```

These flags have opposite meanings and are mutually exclusive.

## Safe Patterns

```rust
// Create writable file
OpenOptions::new()
    .write(true)
    .create(true)
    .open(path)?;

// Truncate and write
OpenOptions::new()
    .write(true)
    .truncate(true)
    .open(path)?;

// Append mode
OpenOptions::new()
    .append(true)
    .create(true)
    .open(path)?;

// Read-only (no create or write)
OpenOptions::new()
    .read(true)
    .open(path)?;
```

## Detection Strategy

RUSTCOLA056 detects three problematic patterns:

1. **create() or create_new() without write() or append()**: Useless create flag
2. **truncate() without write() or append()**: Dangerous data loss
3. **append() with truncate()**: Contradictory flags

## References

- Sonar RSPEC-7447: File operations should use consistent flags
- Clippy lint: `suspicious_open_options`
- Rust std::fs::OpenOptions documentation
