//! HIR Query Interface for Offline Analysis
//!
//! Provides convenient access to type metadata extracted during HIR capture.
//! Unlike TypeAnalyzer (which requires live TyCtxt), these functions work
//! with HirPackage data and can be used for offline security analysis.

use crate::hir::{HirPackage, HirTypeMetadata};
use anyhow::{Context, Result};

/// Query interface for HIR type metadata
pub struct HirQuery<'a> {
    package: &'a HirPackage,
}

impl<'a> HirQuery<'a> {
    /// Create a new query interface for a HIR package
    pub fn new(package: &'a HirPackage) -> Self {
        Self { package }
    }

    /// Get type metadata by type name
    ///
    /// # Arguments
    /// * `type_name` - Full type path (e.g., "my_crate::MyStruct")
    ///
    /// # Returns
    /// * `Some(&HirTypeMetadata)` - Type metadata found
    /// * `None` - Type not found in metadata
    pub fn get_type(&self, type_name: &str) -> Option<&HirTypeMetadata> {
        self.package
            .type_metadata
            .iter()
            .find(|meta| meta.type_name == type_name)
    }

    /// Get the size of a type in bytes
    ///
    /// # Returns
    /// * `Ok(Some(size))` - Type has a known size
    /// * `Ok(None)` - Type not found or size unknown
    pub fn size_of(&self, type_name: &str) -> Result<Option<usize>> {
        Ok(self.get_type(type_name).and_then(|meta| meta.size_bytes))
    }

    /// Check if a type is zero-sized (ZST)
    ///
    /// # Returns
    /// * `Ok(true)` - Type is definitely zero-sized
    /// * `Ok(false)` - Type has non-zero size or not found
    pub fn is_zst(&self, type_name: &str) -> Result<bool> {
        Ok(self
            .get_type(type_name)
            .map(|meta| meta.is_zst)
            .unwrap_or(false))
    }

    /// Find all zero-sized types in the package
    ///
    /// # Returns
    /// Iterator over all ZST type metadata
    pub fn find_all_zsts(&self) -> impl Iterator<Item = &HirTypeMetadata> {
        self.package.type_metadata.iter().filter(|meta| meta.is_zst)
    }

    /// Find all types matching a predicate
    ///
    /// # Arguments
    /// * `predicate` - Function to test each type metadata
    ///
    /// # Returns
    /// Iterator over matching type metadata
    pub fn find_types<F>(&self, predicate: F) -> impl Iterator<Item = &HirTypeMetadata>
    where
        F: Fn(&&HirTypeMetadata) -> bool,
    {
        self.package.type_metadata.iter().filter(predicate)
    }

    /// Get all type metadata
    pub fn all_types(&self) -> &[HirTypeMetadata] {
        &self.package.type_metadata
    }

    /// Check if a type name appears to be a pointer/reference to a ZST
    ///
    /// Helper for detecting patterns like `*const ()` or `*mut PhantomData<T>`
    pub fn looks_like_zst_pointer(&self, type_string: &str) -> bool {
        let lower = type_string.to_lowercase();

        // Direct pointer patterns
        if lower.contains("*const ()") || lower.contains("*mut ()") {
            return true;
        }

        // Check if it's a pointer to a known ZST
        for zst in self.find_all_zsts() {
            let zst_name_lower = zst.type_name.to_lowercase();
            if lower.contains("*const") && lower.contains(&zst_name_lower) {
                return true;
            }
            if lower.contains("*mut") && lower.contains(&zst_name_lower) {
                return true;
            }
        }

        // Known ZST marker types
        let zst_markers = [
            "phantomdata",
            "phantompinned",
            "::marker::phantomdata",
            "::marker::phantompinned",
        ];

        zst_markers.iter().any(|marker| {
            lower.contains(marker) && (lower.contains("*const") || lower.contains("*mut"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hir::{HirPackage, HirTargetSpec, HirTypeMetadata};

    fn make_test_package() -> HirPackage {
        HirPackage {
            crate_name: "test_crate".to_string(),
            crate_root: "/tmp/test".to_string(),
            target: HirTargetSpec {
                kind: "lib".to_string(),
                crate_name: "test_crate".to_string(),
                target_name: None,
            },
            items: vec![],
            functions: vec![],
            type_metadata: vec![
                HirTypeMetadata {
                    type_name: "test_crate::MyStruct".to_string(),
                    size_bytes: Some(16),
                    is_send: None,
                    is_sync: None,
                    is_zst: false,
                },
                HirTypeMetadata {
                    type_name: "test_crate::EmptyStruct".to_string(),
                    size_bytes: Some(0),
                    is_send: None,
                    is_sync: None,
                    is_zst: true,
                },
                HirTypeMetadata {
                    type_name: "test_crate::WithPhantom".to_string(),
                    size_bytes: Some(0),
                    is_send: None,
                    is_sync: None,
                    is_zst: true,
                },
            ],
        }
    }

    #[test]
    fn test_get_type() {
        let package = make_test_package();
        let query = HirQuery::new(&package);

        assert!(query.get_type("test_crate::MyStruct").is_some());
        assert!(query.get_type("test_crate::NonExistent").is_none());
    }

    #[test]
    fn test_size_of() {
        let package = make_test_package();
        let query = HirQuery::new(&package);

        assert_eq!(query.size_of("test_crate::MyStruct").unwrap(), Some(16));
        assert_eq!(query.size_of("test_crate::EmptyStruct").unwrap(), Some(0));
        assert_eq!(query.size_of("test_crate::NonExistent").unwrap(), None);
    }

    #[test]
    fn test_is_zst() {
        let package = make_test_package();
        let query = HirQuery::new(&package);

        assert_eq!(query.is_zst("test_crate::MyStruct").unwrap(), false);
        assert_eq!(query.is_zst("test_crate::EmptyStruct").unwrap(), true);
        assert_eq!(query.is_zst("test_crate::WithPhantom").unwrap(), true);
        assert_eq!(query.is_zst("test_crate::NonExistent").unwrap(), false);
    }

    #[test]
    fn test_find_all_zsts() {
        let package = make_test_package();
        let query = HirQuery::new(&package);

        let zsts: Vec<_> = query.find_all_zsts().collect();
        assert_eq!(zsts.len(), 2);
        assert!(zsts
            .iter()
            .any(|m| m.type_name == "test_crate::EmptyStruct"));
        assert!(zsts
            .iter()
            .any(|m| m.type_name == "test_crate::WithPhantom"));
    }

    #[test]
    fn test_looks_like_zst_pointer() {
        let package = make_test_package();
        let query = HirQuery::new(&package);

        assert!(query.looks_like_zst_pointer("*const ()"));
        assert!(query.looks_like_zst_pointer("*mut ()"));
        assert!(query.looks_like_zst_pointer("*const PhantomData<T>"));
        assert!(query.looks_like_zst_pointer("*mut test_crate::EmptyStruct"));
        assert!(!query.looks_like_zst_pointer("*const u32"));
    }
}
