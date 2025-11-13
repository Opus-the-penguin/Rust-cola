/// Field-sensitive taint analysis module
///
/// This module provides data structures and algorithms for tracking taint
/// at the granularity of individual struct fields, enabling more precise
/// analysis and reducing false positives.

use std::collections::HashMap;

/// Represents a path to a specific field within a struct hierarchy
///
/// Examples:
/// - `_1.0` → base_var="_1", indices=[0]
/// - `_1.1.2` → base_var="_1", indices=[1, 2]
/// - `_3` → base_var="_3", indices=[] (whole variable)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldPath {
    /// Base variable name (e.g., "_1", "_3", "_10")
    pub base_var: String,
    
    /// Field indices from root to leaf
    /// Empty vec means the entire variable (not a specific field)
    pub indices: Vec<usize>,
}

impl FieldPath {
    /// Create a new field path
    pub fn new(base_var: String, indices: Vec<usize>) -> Self {
        FieldPath { base_var, indices }
    }
    
    /// Create a field path for an entire variable (no field access)
    pub fn whole_var(base_var: String) -> Self {
        FieldPath {
            base_var,
            indices: Vec::new(),
        }
    }
    
    /// Create a field path from a base and single field index
    pub fn single_field(base_var: String, index: usize) -> Self {
        FieldPath {
            base_var,
            indices: vec![index],
        }
    }
    
    /// Convert to canonical string representation
    /// Examples: "_1" , "_1.0", "_1.1.2"
    pub fn to_string(&self) -> String {
        if self.indices.is_empty() {
            self.base_var.clone()
        } else {
            let indices_str = self.indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(".");
            format!("{}.{}", self.base_var, indices_str)
        }
    }
    
    /// Check if this path is a prefix of another path
    ///
    /// Example: `_1.1` is a prefix of `_1.1.2`
    /// Example: `_1` is a prefix of `_1.0`
    /// Example: `_1.2` is NOT a prefix of `_1.1.2`
    pub fn is_prefix_of(&self, other: &FieldPath) -> bool {
        if self.base_var != other.base_var {
            return false;
        }
        
        if self.indices.len() > other.indices.len() {
            return false;
        }
        
        self.indices
            .iter()
            .zip(other.indices.iter())
            .all(|(a, b)| a == b)
    }
    
    /// Check if this is a whole variable (no field indices)
    pub fn is_whole_var(&self) -> bool {
        self.indices.is_empty()
    }
    
    /// Get parent field path (remove last index)
    /// Example: `_1.1.2` → `Some(_1.1)`
    /// Example: `_1.0` → `Some(_1)`
    /// Example: `_1` → `None`
    pub fn parent(&self) -> Option<FieldPath> {
        if self.indices.is_empty() {
            None
        } else {
            let mut parent_indices = self.indices.clone();
            parent_indices.pop();
            Some(FieldPath {
                base_var: self.base_var.clone(),
                indices: parent_indices,
            })
        }
    }
}

/// Taint state for a field or variable
#[derive(Debug, Clone, PartialEq)]
pub enum FieldTaint {
    /// Field is clean (not tainted)
    Clean,
    
    /// Field is tainted from a source
    Tainted {
        source_type: String,
        source_location: String,
    },
    
    /// Field was sanitized
    Sanitized {
        sanitizer: String,
    },
    
    /// Unknown state (not yet analyzed)
    Unknown,
}

impl FieldTaint {
    /// Check if taint state is tainted
    pub fn is_tainted(&self) -> bool {
        matches!(self, FieldTaint::Tainted { .. })
    }
    
    /// Check if taint state is clean
    pub fn is_clean(&self) -> bool {
        matches!(self, FieldTaint::Clean)
    }
    
    /// Check if taint state is sanitized
    pub fn is_sanitized(&self) -> bool {
        matches!(self, FieldTaint::Sanitized { .. })
    }
}

/// Maps field paths to their taint states
///
/// This data structure tracks taint at the field level, enabling precise
/// analysis where only specific fields of a struct are tainted.
#[derive(Debug, Clone)]
pub struct FieldTaintMap {
    /// Maps field paths to taint states
    fields: HashMap<FieldPath, FieldTaint>,
}

impl FieldTaintMap {
    /// Create a new empty field taint map
    pub fn new() -> Self {
        FieldTaintMap {
            fields: HashMap::new(),
        }
    }
    
    /// Set taint state for a specific field
    pub fn set_field_taint(&mut self, path: FieldPath, taint: FieldTaint) {
        self.fields.insert(path, taint);
    }
    
    /// Get taint state for a specific field
    ///
    /// If the exact field is not in the map, checks parent fields.
    /// Returns Unknown if no information is available.
    pub fn get_field_taint(&self, path: &FieldPath) -> FieldTaint {
        // Check exact match first
        if let Some(taint) = self.fields.get(path) {
            return taint.clone();
        }
        
        // Check parent fields (if child is unknown but parent is tainted, child is too)
        let mut current = path.clone();
        while let Some(parent) = current.parent() {
            if let Some(taint) = self.fields.get(&parent) {
                return taint.clone();
            }
            current = parent;
        }
        
        // No information available
        FieldTaint::Unknown
    }
    
    /// Set taint for an entire variable (all fields)
    ///
    /// This is used when a whole struct is assigned a tainted value.
    /// In conservative analysis, this taints all known fields of the struct.
    pub fn set_var_taint(&mut self, base_var: &str, taint: FieldTaint) {
        // Set taint for the base variable
        let base_path = FieldPath::whole_var(base_var.to_string());
        self.fields.insert(base_path, taint.clone());
        
        // Also propagate to all known fields of this variable
        let fields_to_update: Vec<FieldPath> = self
            .fields
            .keys()
            .filter(|path| path.base_var == base_var && !path.is_whole_var())
            .cloned()
            .collect();
        
        for field_path in fields_to_update {
            self.fields.insert(field_path, taint.clone());
        }
    }
    
    /// Get all fields for a given base variable
    pub fn get_fields_for_var(&self, base_var: &str) -> Vec<(FieldPath, FieldTaint)> {
        self.fields
            .iter()
            .filter(|(path, _)| path.base_var == base_var)
            .map(|(path, taint)| (path.clone(), taint.clone()))
            .collect()
    }
    
    /// Check if any field of a variable is tainted
    pub fn has_tainted_field(&self, base_var: &str) -> bool {
        self.fields
            .iter()
            .any(|(path, taint)| path.base_var == base_var && taint.is_tainted())
    }
    
    /// Merge another FieldTaintMap into this one
    ///
    /// Used when combining taint states from different paths.
    /// If a field appears in both maps, the more specific taint wins:
    /// Tainted > Sanitized > Clean > Unknown
    pub fn merge(&mut self, other: &FieldTaintMap) {
        for (path, other_taint) in &other.fields {
            let current_taint = self.get_field_taint(path);
            
            // Merge logic: tainted wins over everything
            let merged_taint = match (&current_taint, other_taint) {
                (FieldTaint::Tainted { .. }, _) => current_taint,
                (_, FieldTaint::Tainted { .. }) => other_taint.clone(),
                (FieldTaint::Sanitized { .. }, _) => current_taint,
                (_, FieldTaint::Sanitized { .. }) => other_taint.clone(),
                (FieldTaint::Clean, _) => current_taint,
                _ => other_taint.clone(),
            };
            
            self.fields.insert(path.clone(), merged_taint);
        }
    }
    
    /// Clear all taint information
    pub fn clear(&mut self) {
        self.fields.clear();
    }
    
    /// Get number of tracked fields
    pub fn len(&self) -> usize {
        self.fields.len()
    }
    
    /// Check if map is empty
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl Default for FieldTaintMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_field_path_creation() {
        let path = FieldPath::new("_1".to_string(), vec![0, 1, 2]);
        assert_eq!(path.base_var, "_1");
        assert_eq!(path.indices, vec![0, 1, 2]);
    }
    
    #[test]
    fn test_field_path_to_string() {
        let path1 = FieldPath::whole_var("_1".to_string());
        assert_eq!(path1.to_string(), "_1");
        
        let path2 = FieldPath::single_field("_1".to_string(), 0);
        assert_eq!(path2.to_string(), "_1.0");
        
        let path3 = FieldPath::new("_1".to_string(), vec![1, 2]);
        assert_eq!(path3.to_string(), "_1.1.2");
    }
    
    #[test]
    fn test_field_path_is_prefix() {
        let path1 = FieldPath::whole_var("_1".to_string());
        let path2 = FieldPath::single_field("_1".to_string(), 0);
        let path3 = FieldPath::new("_1".to_string(), vec![0, 1]);
        let path4 = FieldPath::new("_1".to_string(), vec![1, 2]);
        
        assert!(path1.is_prefix_of(&path2));
        assert!(path1.is_prefix_of(&path3));
        assert!(path2.is_prefix_of(&path3));
        assert!(!path2.is_prefix_of(&path4));
        assert!(!path3.is_prefix_of(&path2));
    }
    
    #[test]
    fn test_field_path_parent() {
        let path1 = FieldPath::new("_1".to_string(), vec![1, 2]);
        let parent1 = path1.parent().unwrap();
        assert_eq!(parent1.to_string(), "_1.1");
        
        let parent2 = parent1.parent().unwrap();
        assert_eq!(parent2.to_string(), "_1");
        
        assert!(parent2.parent().is_none());
    }
    
    #[test]
    fn test_field_taint_map_basic() {
        let mut map = FieldTaintMap::new();
        
        let path = FieldPath::single_field("_1".to_string(), 0);
        map.set_field_taint(path.clone(), FieldTaint::Tainted {
            source_type: "environment".to_string(),
            source_location: "env::args".to_string(),
        });
        
        let taint = map.get_field_taint(&path);
        assert!(taint.is_tainted());
    }
    
    #[test]
    fn test_field_taint_map_inheritance() {
        let mut map = FieldTaintMap::new();
        
        // Set parent field as tainted
        let parent = FieldPath::single_field("_1".to_string(), 1);
        map.set_field_taint(parent, FieldTaint::Tainted {
            source_type: "environment".to_string(),
            source_location: "test".to_string(),
        });
        
        // Child field should inherit taint
        let child = FieldPath::new("_1".to_string(), vec![1, 2]);
        let taint = map.get_field_taint(&child);
        assert!(taint.is_tainted());
    }
    
    #[test]
    fn test_set_var_taint() {
        let mut map = FieldTaintMap::new();
        
        // Add some fields first
        map.set_field_taint(
            FieldPath::single_field("_1".to_string(), 0),
            FieldTaint::Clean,
        );
        map.set_field_taint(
            FieldPath::single_field("_1".to_string(), 1),
            FieldTaint::Clean,
        );
        
        // Taint entire variable
        map.set_var_taint("_1", FieldTaint::Tainted {
            source_type: "test".to_string(),
            source_location: "test".to_string(),
        });
        
        // All fields should be tainted
        assert!(map.get_field_taint(&FieldPath::single_field("_1".to_string(), 0)).is_tainted());
        assert!(map.get_field_taint(&FieldPath::single_field("_1".to_string(), 1)).is_tainted());
    }
    
    #[test]
    fn test_merge() {
        let mut map1 = FieldTaintMap::new();
        map1.set_field_taint(
            FieldPath::single_field("_1".to_string(), 0),
            FieldTaint::Tainted {
                source_type: "test".to_string(),
                source_location: "test".to_string(),
            },
        );
        
        let mut map2 = FieldTaintMap::new();
        map2.set_field_taint(
            FieldPath::single_field("_1".to_string(), 1),
            FieldTaint::Tainted {
                source_type: "test2".to_string(),
                source_location: "test2".to_string(),
            },
        );
        
        map1.merge(&map2);
        
        assert!(map1.get_field_taint(&FieldPath::single_field("_1".to_string(), 0)).is_tainted());
        assert!(map1.get_field_taint(&FieldPath::single_field("_1".to_string(), 1)).is_tainted());
    }
}
