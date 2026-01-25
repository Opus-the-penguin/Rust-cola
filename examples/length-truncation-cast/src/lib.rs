//! Demonstrates RUSTSEC-2024-0363 and RUSTSEC-2024-0365: Protocol length truncation
//!
//! This example shows how casting payload lengths to narrower integer types
//! can enable protocol smuggling attacks in database clients.

use bytes::{BufMut, BytesMut};

// ============================================================================
// VULNERABLE PATTERNS - Should trigger RUSTCOLA022
// ============================================================================

/// VULNERABLE: Direct cast of payload length to u32 before serialization
/// An attacker can send >4GB payload to smuggle additional protocol commands
pub fn vulnerable_direct_cast_u32(payload: &[u8]) {
    let len = payload.len();
    // RUSTCOLA022 should flag this - usize to u32 cast can truncate
    let len_u32 = len as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32); // Serializing truncated length
    buffer.put_slice(payload);
}

/// VULNERABLE: Cast to i32 for signed protocol length fields
pub fn vulnerable_cast_i32(payload: &[u8]) {
    let len = payload.len();
    // RUSTCOLA022 should flag this - usize to i32 cast
    let len_i32 = len as i32;

    let mut buffer = BytesMut::new();
    buffer.put_i32(len_i32);
    buffer.put_slice(payload);
}

/// VULNERABLE: Cast to u16 (even more truncation)
pub fn vulnerable_cast_u16(payload: &[u8]) {
    let len = payload.len();
    // RUSTCOLA022 should flag this - usize to u16 cast
    let len_u16 = len as u16;

    let mut buffer = BytesMut::new();
    buffer.put_u16(len_u16);
    buffer.put_slice(payload);
}

/// VULNERABLE: Cast to u8 (extreme truncation)
pub fn vulnerable_cast_u8(payload: &[u8]) {
    let len = payload.len();
    // RUSTCOLA022 should flag this - usize to u8 cast
    let len_u8 = len as u8;

    let mut buffer = BytesMut::new();
    buffer.put_u8(len_u8);
    buffer.put_slice(payload);
}

/// VULNERABLE: try_into pattern without proper error handling
pub fn vulnerable_try_into_unwrap(payload: &[u8]) {
    let len = payload.len();
    // RUSTCOLA022 should flag this - try_into with unwrap defeats the purpose
    let len_u32: u32 = len.try_into().unwrap();

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(payload);
}

/// VULNERABLE: Indirect flow through variable
pub fn vulnerable_indirect_cast(payload: &[u8]) {
    let size = payload.len();
    let packet_len = size; // Taint propagates
                           // RUSTCOLA022 should flag this
    let network_len = packet_len as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(network_len);
    buffer.put_slice(payload);
}

/// VULNERABLE: Cast in expression
pub fn vulnerable_cast_in_expression(payload: &[u8]) {
    let mut buffer = BytesMut::new();
    // RUSTCOLA022 should flag this - direct cast in argument
    buffer.put_u32(payload.len() as u32);
    buffer.put_slice(payload);
}

/// VULNERABLE: Multi-step cast chain
pub fn vulnerable_cast_chain(payload: &[u8]) {
    let len = payload.len();
    let len_u64 = len as u64;
    // RUSTCOLA022 should flag this - u64 to u32 is still narrowing
    let len_u32 = len_u64 as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(payload);
}

// ============================================================================
// SAFE PATTERNS - Should NOT trigger RUSTCOLA022
// ============================================================================

/// SAFE: Using min() to clamp length before cast
pub fn safe_with_min_clamp(payload: &[u8]) {
    const MAX_LENGTH: usize = u32::MAX as usize;
    let len = payload.len();

    // Safe: clamped before cast
    let clamped_len = len.min(MAX_LENGTH);
    let len_u32 = clamped_len as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(&payload[..clamped_len]);
}

/// SAFE: Using checked conversion with proper error handling
pub fn safe_with_checked_conversion(payload: &[u8]) -> Result<BytesMut, &'static str> {
    let len = payload.len();

    // Safe: try_into with proper error handling
    let len_u32: u32 = len.try_into().map_err(|_| "Payload too large")?;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(payload);

    Ok(buffer)
}

/// SAFE: Explicit range check before cast
pub fn safe_with_range_check(payload: &[u8]) {
    let len = payload.len();

    // Safe: explicit validation
    assert!(len <= u32::MAX as usize, "Payload exceeds maximum size");
    let len_u32 = len as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(payload);
}

/// SAFE: Using if-let with try_into
pub fn safe_with_if_let(payload: &[u8]) {
    let len = payload.len();

    // Safe: conditional execution based on conversion success
    if let Ok(len_u32) = u32::try_from(len) {
        let mut buffer = BytesMut::new();
        buffer.put_u32(len_u32);
        buffer.put_slice(payload);
    } else {
        // Handle oversized payload
        eprintln!("Payload too large for protocol");
    }
}

/// SAFE: No narrowing cast - using u64
pub fn safe_with_wider_type(payload: &[u8]) {
    let len = payload.len();
    // Safe: casting to wider type (usize to u64 on 32-bit, same on 64-bit)
    let len_u64 = len as u64;

    let mut buffer = BytesMut::new();
    buffer.put_u64(len_u64);
    buffer.put_slice(payload);
}

/// SAFE: Using saturating_sub to ensure bounds
pub fn safe_with_saturating_ops(payload: &[u8]) {
    const MAX_SIZE: usize = 1024 * 1024; // 1MB
    let len = payload.len();

    // Safe: saturating operations prevent overflow
    let clamped = MAX_SIZE.saturating_sub(0).min(len);
    let len_u32 = clamped as u32;

    let mut buffer = BytesMut::new();
    buffer.put_u32(len_u32);
    buffer.put_slice(&payload[..clamped]);
}

/// SAFE: Constant size (not derived from payload.len())
pub fn safe_with_constant_size(payload: &[u8]) {
    const FIXED_SIZE: u32 = 1024;

    let mut buffer = BytesMut::new();
    buffer.put_u32(FIXED_SIZE);
    buffer.put_slice(&payload[..FIXED_SIZE.min(payload.len() as u32) as usize]);
}

// ============================================================================
// EDGE CASES
// ============================================================================

/// EDGE: Cast not related to serialization
pub fn edge_case_unrelated_cast(payload: &[u8]) {
    let len = payload.len();

    // This cast is for logging, not serialization - might still be flagged
    let len_u32 = len as u32;
    println!("Payload size: {}", len_u32);

    // Actual serialization uses full length
    let mut buffer = BytesMut::new();
    buffer.put_u64(len as u64);
    buffer.put_slice(payload);
}

/// EDGE: Cast happens but value not used for serialization
pub fn edge_case_unused_cast(payload: &[u8]) {
    let len = payload.len();
    let _truncated = len as u32; // Might be flagged even though unused

    let mut buffer = BytesMut::new();
    buffer.put_u64(len as u64);
    buffer.put_slice(payload);
}

/// EDGE: Multiple casts, only one goes to serialization
pub fn edge_case_multiple_casts(payload: &[u8]) {
    let len = payload.len();

    // For logging
    let _len_display = len as u32;

    // For serialization - safe
    let len_u64 = len as u64;
    let mut buffer = BytesMut::new();
    buffer.put_u64(len_u64);
    buffer.put_slice(payload);
}
