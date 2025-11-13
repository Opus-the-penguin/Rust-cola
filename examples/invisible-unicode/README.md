# RUSTCOLA048: Invisible Unicode Character Detection

This example demonstrates detection of invisible and dangerous Unicode characters that could be used for Trojan Source attacks, spoofing, or hidden backdoors.

## The Threat: Trojan Source

**CVE-2021-42574** and **CVE-2021-42694** describe "Trojan Source" attacks where invisible Unicode bidirectional (Bidi) control characters can make source code appear different from its actual behavior.

### How It Works

Bidirectional Unicode characters (designed for mixing left-to-right and right-to-left scripts like English and Arabic) can be weaponized:

```rust
// What the developer SEES:
let is_admin = false;
/* if is_admin */ {
    grant_access();
}

// What the compiler ACTUALLY EXECUTES:
let is_admin = false;
/*‮ } ⁦if is_admin⁩ ⁦ begin admins only */
    grant_access();  // THIS ACTUALLY RUNS!
/* end admins only ‮ { ⁦ */
```

The U+202E (RIGHT-TO-LEFT OVERRIDE) character reverses the visual order while preserving the logical order for compilation.

## Dangerous Characters Detected

### Zero-Width Characters
- **U+200B** - ZERO WIDTH SPACE
- **U+200C** - ZERO WIDTH NON-JOINER
- **U+200D** - ZERO WIDTH JOINER
- **U+FEFF** - ZERO WIDTH NO-BREAK SPACE (BOM)
- **U+2060** - WORD JOINER

**Attack**: Make two identifiers look identical but be different:
```rust
let access_level = "user";    // Normal variable
let access_level​ = "admin";   // Contains U+200B - looks identical!
```

### Bidirectional Text Controls (Trojan Source)
- **U+202A** - LEFT-TO-RIGHT EMBEDDING
- **U+202B** - RIGHT-TO-LEFT EMBEDDING  
- **U+202C** - POP DIRECTIONAL FORMATTING
- **U+202D** - LEFT-TO-RIGHT OVERRIDE
- **U+202E** - RIGHT-TO-LEFT OVERRIDE ⚠️ MOST DANGEROUS
- **U+2066** - LEFT-TO-RIGHT ISOLATE
- **U+2067** - RIGHT-TO-LEFT ISOLATE
- **U+2068** - FIRST STRONG ISOLATE
- **U+2069** - POP DIRECTIONAL ISOLATE

**Attack**: Make code execute in a different order than it appears.

### Private Use Areas
- **U+E000 to U+F8FF** - Private Use Area
- **U+F0000 to U+FFFFD** - Supplementary Private Use Area-A
- **U+100000 to U+10FFFD** - Supplementary Private Use Area-B

**Risk**: Could contain hidden malicious payloads or encoding schemes.

## Test Results

Expected findings:
- **5 vulnerable functions** with invisible Unicode characters
- **3 safe functions** with normal characters - 0 false positives

### Vulnerable Functions
1. `vulnerable_zero_width_space` - U+200B in identifier
2. `vulnerable_zero_width_non_joiner` - U+200C in identifier
3. `vulnerable_rtl_override` - U+202E (Trojan Source)
4. `vulnerable_bidi_embedding` - U+202A bidirectional control
5. `vulnerable_private_use` - Private use area character

### Safe Functions
1. `safe_ascii_only` - ASCII characters only
2. `safe_visible_unicode` - Visible Unicode (Chinese, emoji)
3. `safe_standard_whitespace` - Normal spaces and tabs

## Real-World Impact

### Supply Chain Attacks
```rust
// Backdoor hidden in dependency
pub fn authenticate(user: &str, pass: &str) -> bool {
    let is_admin​ = user == "admin"; // ​ <- Hidden zero-width space
    let is_admin = false;            // Shadows the real check!
    is_admin  // Always returns false for display
}
```

### Code Review Bypass
- Malicious code in pull requests that looks innocent
- Comments that are actually executable code
- Executable code that looks like comments
- Variable shadowing with identical-looking names

### Homoglyph Attacks
```rust
// Which ones are Latin 'a' vs Cyrillic 'а'?
let admin = false;  // Latin
let аdmin = true;   // Cyrillic 'а' (U+0430)
```

## Detection Methodology

RUSTCOLA048 scans all source text (including comments and strings) for:

1. **Zero-width characters** - Invisible spacing/joining
2. **Bidirectional overrides** - Text direction manipulation
3. **Private use areas** - Potentially encoded payloads
4. **Control characters** - Non-printable Unicode

Each finding includes the specific character code (e.g., U+202E) and name for remediation.

## References

- **CVE-2021-42574**: Trojan Source attack
- **CVE-2021-42694**: Bidi override vulnerability
- **https://trojansource.codes/** - Official Trojan Source disclosure
- **Sonar RSPEC-2479**: Invisible Unicode detection
- **Unicode TR #36**: Security Considerations

## Fix Guidance

1. **Remove invisible characters** from source code
2. **Use ASCII identifiers** where possible
3. **Enable Unicode normalization** checks in CI/CD
4. **Review dependencies** for suspicious Unicode
5. **Use tools** that highlight invisible characters
6. **Set editor** to show all Unicode characters

## Prevention

### Editor Configuration
- Enable "show invisible characters"
- Use monospace fonts that render all Unicode distinctly
- Install extensions that highlight suspicious Unicode

### CI/CD Integration
```bash
# Fail builds with invisible Unicode
cargo clippy -- -D clippy::invisible_characters
```

### Code Review
- Be suspicious of mixed scripts (Latin + Cyrillic)
- Watch for unusual spacing in identifiers
- Review any Unicode beyond basic printable ASCII

Remember: **If you can't see it, you can't trust it!**
