//! Test cases for RUSTCOLA081: Serde serialize_* length mismatch
//!
//! This rule detects when the length argument to serialize_struct/serialize_tuple/etc
//! doesn't match the actual number of serialize_field/serialize_element calls.

use serde::ser::{
    Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeTuple, SerializeTupleStruct,
    Serializer,
};
use serde::Serialize as DeriveSerialize;

// ============================================================================
// PROBLEMATIC: Length mismatches that will cause parsing issues
// ============================================================================

/// Problematic: Declares 3 fields but only serializes 2
pub struct TooFewFields {
    pub name: String,
    pub age: u32,
    pub email: String,
}

impl Serialize for TooFewFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Says 3 fields but only writes 2
        let mut state = serializer.serialize_struct("TooFewFields", 3)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("age", &self.age)?;
        // Missing: state.serialize_field("email", &self.email)?;
        state.end()
    }
}

/// Problematic: Declares 2 fields but serializes 3
pub struct TooManyFields {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

impl Serialize for TooManyFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Says 2 fields but writes 3
        let mut state = serializer.serialize_struct("TooManyFields", 2)?;
        state.serialize_field("x", &self.x)?;
        state.serialize_field("y", &self.y)?;
        state.serialize_field("z", &self.z)?;
        state.end()
    }
}

/// Problematic: Tuple with wrong length
pub struct WrongTupleLength(pub i32, pub i32, pub i32);

impl Serialize for WrongTupleLength {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Says 2 elements but writes 3
        let mut state = serializer.serialize_tuple(2)?;
        state.serialize_element(&self.0)?;
        state.serialize_element(&self.1)?;
        state.serialize_element(&self.2)?;
        state.end()
    }
}

/// Problematic: Tuple struct with mismatch
pub struct WrongTupleStructLength {
    pub a: String,
    pub b: String,
}

impl Serialize for WrongTupleStructLength {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Says 3 but writes 2
        let mut state = serializer.serialize_tuple_struct("WrongTupleStructLength", 3)?;
        state.serialize_field(&self.a)?;
        state.serialize_field(&self.b)?;
        state.end()
    }
}

/// Problematic: Map with wrong length hint
pub struct WrongMapLength {
    pub items: Vec<(String, i32)>,
}

impl Serialize for WrongMapLength {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Always says 5 entries regardless of actual count
        let mut state = serializer.serialize_map(Some(5))?;
        for (k, v) in &self.items {
            state.serialize_entry(k, v)?;
        }
        state.end()
    }
}

/// Problematic: Declares 0 fields but serializes some
pub struct ZeroButHasFields {
    pub value: i32,
}

impl Serialize for ZeroButHasFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Says 0 fields but writes 1
        let mut state = serializer.serialize_struct("ZeroButHasFields", 0)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

/// Problematic: Seq with wrong length hint
pub struct WrongSeqLength {
    pub data: Vec<u8>,
}

impl Serialize for WrongSeqLength {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // VULNERABLE: Always says 10 elements
        let mut state = serializer.serialize_seq(Some(10))?;
        for item in &self.data {
            state.serialize_element(item)?;
        }
        state.end()
    }
}

// ============================================================================
// SAFE: Correct length declarations
// ============================================================================

/// Safe: Correct field count
pub struct CorrectFields {
    pub name: String,
    pub age: u32,
}

impl Serialize for CorrectFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: 2 fields declared, 2 fields written
        let mut state = serializer.serialize_struct("CorrectFields", 2)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("age", &self.age)?;
        state.end()
    }
}

/// Safe: Correct tuple length
pub struct CorrectTuple(pub i32, pub i32);

impl Serialize for CorrectTuple {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: 2 elements declared, 2 elements written
        let mut state = serializer.serialize_tuple(2)?;
        state.serialize_element(&self.0)?;
        state.serialize_element(&self.1)?;
        state.end()
    }
}

/// Safe: Using None for unknown length (seq)
pub struct DynamicSeq {
    pub items: Vec<String>,
}

impl Serialize for DynamicSeq {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: None means unknown length, acceptable for dynamic collections
        let mut state = serializer.serialize_seq(None)?;
        for item in &self.items {
            state.serialize_element(item)?;
        }
        state.end()
    }
}

/// Safe: Using None for map length
pub struct DynamicMap {
    pub entries: Vec<(String, i32)>,
}

impl Serialize for DynamicMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: None means unknown length
        let mut state = serializer.serialize_map(None)?;
        for (k, v) in &self.entries {
            state.serialize_entry(k, v)?;
        }
        state.end()
    }
}

/// Safe: Correct seq length from .len()
pub struct CorrectSeqFromLen {
    pub data: Vec<u8>,
}

impl Serialize for CorrectSeqFromLen {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: Length comes from actual data
        let mut state = serializer.serialize_seq(Some(self.data.len()))?;
        for item in &self.data {
            state.serialize_element(item)?;
        }
        state.end()
    }
}

/// Safe: Using derive macro (always correct)
#[derive(DeriveSerialize)]
pub struct DerivedStruct {
    pub field1: String,
    pub field2: i32,
}

/// Safe: Empty struct with 0 fields
pub struct EmptyStruct;

impl Serialize for EmptyStruct {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: 0 fields declared, 0 fields written
        let state = serializer.serialize_struct("EmptyStruct", 0)?;
        state.end()
    }
}

/// Safe: Single field correct
pub struct SingleField {
    pub value: i32,
}

impl Serialize for SingleField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFE: 1 field declared, 1 field written
        let mut state = serializer.serialize_struct("SingleField", 1)?;
        state.serialize_field("value", &self.value)?;
        state.end()
    }
}

fn main() {
    println!("Serde length mismatch test cases");

    // Test some serializations
    let correct = CorrectFields {
        name: "Alice".to_string(),
        age: 30,
    };
    println!("Correct: {}", serde_json::to_string(&correct).unwrap());

    // These would produce incorrect output due to length mismatches
    let too_few = TooFewFields {
        name: "Bob".to_string(),
        age: 25,
        email: "bob@example.com".to_string(),
    };
    // This might work for JSON but fail for binary formats
    println!("TooFew: {}", serde_json::to_string(&too_few).unwrap());
}
