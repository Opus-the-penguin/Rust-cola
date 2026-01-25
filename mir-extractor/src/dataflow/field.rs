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
            let indices_str = self
                .indices
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
    Sanitized { sanitizer: String },

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

/// Parse field access patterns from MIR expressions
pub mod parser {
    use super::*;

    /// Parse a field access from a MIR expression
    ///
    /// Handles patterns:
    /// - `(_1.0: Type)` → FieldPath { base_var: "_1", indices: [0] }
    /// - `(_1.1: Type)` → FieldPath { base_var: "_1", indices: [1] }
    /// - `((_1.1: Type).2: Type2)` → FieldPath { base_var: "_1", indices: [1, 2] }
    /// - `((_2 as Ready).0: String)` → FieldPath { base_var: "_2", indices: [0] }
    ///
    /// Returns None if the expression is not a field access.
    pub fn parse_field_access(expr: &str) -> Option<FieldPath> {
        let expr = expr.trim();

        // Check if this looks like a field access (requires a dot)
        if !expr.contains('.') {
            return None;
        }

        // If it contains parentheses, try MIR-style parsing
        if expr.contains('(') {
            // Try parsing as nested field first
            if let Some(path) = parse_nested_field_access(expr) {
                return Some(path);
            }

            // Try parsing as downcast field access
            if let Some(path) = parse_downcast_field_access(expr) {
                return Some(path);
            }

            // Try parsing as simple MIR field access
            if let Some(path) = parse_simple_field_access(expr) {
                return Some(path);
            }
        }

        // Try parsing simple dot notation: _VAR.INDEX (e.g., _3.0, _1.2.3)
        parse_dot_notation(expr)
    }

    /// Parse simple dot notation: _VAR.INDEX (without MIR type annotations)
    fn parse_dot_notation(expr: &str) -> Option<FieldPath> {
        let expr = expr.trim();

        // Pattern: _VAR.INDEX or _VAR.INDEX.INDEX2
        // Examples: _3.0, _1.2.3

        if !expr.starts_with('_') {
            return None;
        }

        let parts: Vec<&str> = expr.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let base_var = parts[0].trim().to_string();

        // Validate base_var is a proper variable name (_N)
        if !base_var.starts_with('_') {
            return None;
        }
        let digits_only = base_var[1..].chars().all(|c| c.is_ascii_digit());
        if !digits_only || base_var.len() < 2 {
            return None;
        }

        // Parse indices
        let mut indices = Vec::new();
        for part in &parts[1..] {
            if let Ok(index) = part.trim().parse::<usize>() {
                indices.push(index);
            } else {
                // Not a valid numeric index, not a simple field access
                return None;
            }
        }

        if indices.is_empty() {
            None
        } else {
            Some(FieldPath::new(base_var, indices))
        }
    }

    /// Parse downcast field access: ((_VAR as Variant).INDEX: TYPE)
    fn parse_downcast_field_access(expr: &str) -> Option<FieldPath> {
        let expr = expr.trim();

        // Pattern: ((_VAR as Variant).INDEX: TYPE)
        // Example: ((_2 as Ready).0: std::string::String)

        if !expr.starts_with("((") {
            return None;
        }

        // Find " as "
        let as_pos = expr.find(" as ")?;

        // Extract base var: "_2"
        // Skip "((" (2 chars)
        if as_pos <= 2 {
            return None;
        }
        let base_var_raw = expr[2..as_pos].trim();

        // Handle dereference (*_25) or parens
        let mut clean_base = base_var_raw;
        while clean_base.starts_with('(') && clean_base.ends_with(')') {
            clean_base = &clean_base[1..clean_base.len() - 1].trim();
        }

        let base_var = if clean_base.starts_with('*') {
            clean_base[1..].trim().to_string()
        } else {
            clean_base.to_string()
        };

        if !base_var.starts_with('_') {
            return None;
        }

        // Find closing paren of downcast followed by dot
        // We search from as_pos
        let downcast_end = expr[as_pos..].find(").")?;
        let absolute_downcast_end = as_pos + downcast_end;

        // Extract index part: ".0: String)"
        // The dot is at absolute_downcast_end + 1
        let remaining = &expr[absolute_downcast_end + 1..];

        // Should start with dot
        if !remaining.starts_with('.') {
            return None;
        }

        // Find colon
        let colon_pos = remaining.find(':')?;

        // Extract index: "0"
        // Skip dot (1 char)
        let index_str = remaining[1..colon_pos].trim();

        if let Ok(index) = index_str.parse::<usize>() {
            // For downcasts, we treat it as accessing field 0 of the base variable
            // This is an approximation, but sufficient for taint tracking
            // If _2 is tainted, then ((_2 as Ready).0) is tainted
            return Some(FieldPath::new(base_var, vec![index]));
        }

        None
    }

    /// Parse a simple field access: (_VAR.INDEX: TYPE)
    fn parse_simple_field_access(expr: &str) -> Option<FieldPath> {
        let expr = expr.trim();

        // Pattern: (_VAR.INDEX: TYPE)
        // Example: (_1.0: std::string::String)

        if !expr.starts_with('(') {
            return None;
        }

        // Find the colon that separates field from type
        let colon_pos = expr.find(':')?;

        // Extract the field part: "_VAR.INDEX"
        let field_part = &expr[1..colon_pos].trim();

        // Split by dot to get base and indices
        let parts: Vec<&str> = field_part.split('.').collect();

        if parts.len() < 2 {
            return None;
        }

        let base_var = parts[0].trim().to_string();

        // Parse indices
        let mut indices = Vec::new();
        for part in &parts[1..] {
            if let Ok(index) = part.trim().parse::<usize>() {
                indices.push(index);
            } else {
                // Not a valid index
                return None;
            }
        }

        if indices.is_empty() {
            None
        } else {
            Some(FieldPath::new(base_var, indices))
        }
    }

    /// Parse nested field access: ((_VAR.OUTER: TYPE).INNER: TYPE2)
    fn parse_nested_field_access(expr: &str) -> Option<FieldPath> {
        let expr = expr.trim();

        // Pattern: ((_VAR.INDEX: TYPE).INDEX2: TYPE2)
        // Example: ((_1.1: Credentials).2: std::string::String)

        if !expr.starts_with("((") {
            return None;
        }

        // Find the matching closing paren for the inner expression
        let mut depth = 0;
        let mut inner_end = 0;

        for (i, ch) in expr.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 1 {
                        // Found the end of inner expression
                        inner_end = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        if inner_end == 0 {
            return None;
        }

        // Parse the inner expression first
        let inner_expr = &expr[1..inner_end + 1]; // (_1.1: Type)
        let mut base_path = parse_simple_field_access(inner_expr)?;

        // Now parse the outer index
        let remaining = &expr[inner_end + 1..];

        // Pattern should be: .INDEX: TYPE)
        if !remaining.starts_with('.') {
            return None;
        }

        // Find the colon
        let colon_pos = remaining.find(':')?;
        let index_str = &remaining[1..colon_pos].trim();

        if let Ok(index) = index_str.parse::<usize>() {
            base_path.indices.push(index);
            Some(base_path)
        } else {
            None
        }
    }

    /// Check if an expression contains a field access
    pub fn contains_field_access(expr: &str) -> bool {
        // Check for characteristic elements of MIR field access
        // (_1.0: Type) or ((_1 as Variant).0: Type) or dereferenced (*_1.0)
        let has_mir_style = expr.contains(':')
            && expr.contains('.')
            && (expr.contains("(_") || expr.contains("(*_"));
        if has_mir_style {
            return true;
        }

        // Also check for simple dot notation: _VAR.INDEX
        // e.g., _3.0, _1.2
        if expr.starts_with('_') && expr.contains('.') {
            let parts: Vec<&str> = expr.split('.').collect();
            if parts.len() >= 2 {
                // Check if at least one part after the base is a numeric index
                return parts[1..].iter().any(|p| p.trim().parse::<usize>().is_ok());
            }
        }

        false
    }

    /// Extract the base variable from an expression
    ///
    /// Examples:
    /// - `(_1.0: Type)` → Some("_1")
    /// - `_2` → Some("_2")
    /// - `move _3` → Some("_3")
    pub fn extract_base_var(expr: &str) -> Option<String> {
        let expr = expr.trim();

        // Handle field access
        if let Some(path) = parse_field_access(expr) {
            return Some(path.base_var);
        }

        // Handle simple variable
        if expr.starts_with('_') {
            // Extract until non-digit
            let var: String = expr
                .chars()
                .take_while(|c| *c == '_' || c.is_ascii_digit())
                .collect();
            if !var.is_empty() {
                return Some(var);
            }
        }

        // Handle prefixed variables (move _1, copy _2, &_3)
        // Check longer prefixes first to avoid incorrect matches
        for prefix in &["&mut ", "move ", "copy ", "&"] {
            if expr.starts_with(prefix) {
                let rest = &expr[prefix.len()..];
                return extract_base_var(rest);
            }
        }

        None
    }

    /// Extract all field paths from an expression
    ///
    /// This handles complex expressions that may reference multiple fields.
    pub fn extract_all_field_paths(expr: &str) -> Vec<FieldPath> {
        let mut paths = Vec::new();
        let expr = expr.trim();

        // Look for field access patterns
        let mut search_pos = 0;

        while let Some(paren_start) = expr[search_pos..].find("(_") {
            let actual_pos = search_pos + paren_start;

            // Try to extract field access from this position
            let remaining = &expr[actual_pos..];

            // Find the extent of this field access
            if let Some(colon_pos) = remaining.find(':') {
                // Try to find the closing paren
                if let Some(close_paren) = remaining[colon_pos..].find(')') {
                    let field_expr = &remaining[..colon_pos + close_paren + 1];

                    if let Some(path) = parse_field_access(field_expr) {
                        paths.push(path);
                    }
                }
            }

            search_pos = actual_pos + 1;
        }

        paths
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
        map.set_field_taint(
            path.clone(),
            FieldTaint::Tainted {
                source_type: "environment".to_string(),
                source_location: "env::args".to_string(),
            },
        );

        let taint = map.get_field_taint(&path);
        assert!(taint.is_tainted());
    }

    #[test]
    fn test_field_taint_map_inheritance() {
        let mut map = FieldTaintMap::new();

        // Set parent field as tainted
        let parent = FieldPath::single_field("_1".to_string(), 1);
        map.set_field_taint(
            parent,
            FieldTaint::Tainted {
                source_type: "environment".to_string(),
                source_location: "test".to_string(),
            },
        );

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
        map.set_var_taint(
            "_1",
            FieldTaint::Tainted {
                source_type: "test".to_string(),
                source_location: "test".to_string(),
            },
        );

        // All fields should be tainted
        assert!(map
            .get_field_taint(&FieldPath::single_field("_1".to_string(), 0))
            .is_tainted());
        assert!(map
            .get_field_taint(&FieldPath::single_field("_1".to_string(), 1))
            .is_tainted());
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

        assert!(map1
            .get_field_taint(&FieldPath::single_field("_1".to_string(), 0))
            .is_tainted());
        assert!(map1
            .get_field_taint(&FieldPath::single_field("_1".to_string(), 1))
            .is_tainted());
    }

    // Parser tests

    #[test]
    fn test_parse_simple_field_access() {
        use parser::parse_field_access;

        let path = parse_field_access("(_1.0: std::string::String)").unwrap();
        assert_eq!(path.base_var, "_1");
        assert_eq!(path.indices, vec![0]);

        let path = parse_field_access("(_1.1: std::string::String)").unwrap();
        assert_eq!(path.base_var, "_1");
        assert_eq!(path.indices, vec![1]);

        let path = parse_field_access("(_3.2: u32)").unwrap();
        assert_eq!(path.base_var, "_3");
        assert_eq!(path.indices, vec![2]);
    }

    #[test]
    fn test_parse_nested_field_access() {
        use parser::parse_field_access;

        let path = parse_field_access("((_1.1: Credentials).0: std::string::String)").unwrap();
        assert_eq!(path.base_var, "_1");
        assert_eq!(path.indices, vec![1, 0]);

        let path = parse_field_access("((_1.1: Credentials).2: std::string::String)").unwrap();
        assert_eq!(path.base_var, "_1");
        assert_eq!(path.indices, vec![1, 2]);
    }

    #[test]
    fn test_parse_field_access_invalid() {
        use parser::parse_field_access;

        // Not a field access
        assert!(parse_field_access("_1").is_none());
        assert!(parse_field_access("move _2").is_none());
        assert!(parse_field_access("copy _3").is_none());

        // No indices
        assert!(parse_field_access("(_1: Type)").is_none());
    }

    #[test]
    fn test_contains_field_access() {
        use parser::contains_field_access;

        assert!(contains_field_access("(_1.0: String)"));
        assert!(contains_field_access("((_1.1: Type).2: Type2)"));
        assert!(!contains_field_access("_1"));
        assert!(!contains_field_access("move _2"));
    }

    #[test]
    fn test_extract_base_var() {
        use parser::extract_base_var;

        assert_eq!(extract_base_var("(_1.0: Type)").unwrap(), "_1");
        assert_eq!(extract_base_var("_2").unwrap(), "_2");
        assert_eq!(extract_base_var("move _3").unwrap(), "_3");
        assert_eq!(extract_base_var("copy _4").unwrap(), "_4");
        assert_eq!(extract_base_var("&_5").unwrap(), "_5");
        assert_eq!(extract_base_var("&mut _6").unwrap(), "_6");
    }

    #[test]
    fn test_extract_all_field_paths() {
        use parser::extract_all_field_paths;

        let paths = extract_all_field_paths("(_1.0: String) = move (_2.1: String)");
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].to_string(), "_1.0");
        assert_eq!(paths[1].to_string(), "_2.1");

        let paths = extract_all_field_paths("_3 = Command::arg(copy _4, copy (_5.2: String))");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].to_string(), "_5.2");
    }
}
