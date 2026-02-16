//! LCOV coverage file parser for covguard.
//!
//! This crate provides parsing and merging of LCOV format coverage files,
//! producing a normalized coverage map that can be used by the domain layer.

use std::collections::BTreeMap;

use thiserror::Error;

// ============================================================================
// Types
// ============================================================================

/// A map of file paths to their line coverage data.
///
/// The outer map is keyed by normalized file path (repo-relative, forward slashes).
/// The inner map is keyed by line number (1-indexed) with hit count as value.
pub type CoverageMap = BTreeMap<String, BTreeMap<u32, u32>>;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur while parsing LCOV files.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LcovError {
    /// Invalid format in the LCOV file.
    #[error("Invalid LCOV format: {0}")]
    InvalidFormat(String),

    /// I/O error while reading the file.
    #[error("I/O error: {0}")]
    IoError(String),
}

// ============================================================================
// Path Normalization
// ============================================================================

/// Normalize a file path to repo-relative format.
///
/// - Converts backslashes to forward slashes
/// - Removes leading `./`
/// - Handles common absolute path prefixes (strips them if detected)
///
/// # Examples
///
/// ```
/// use covguard_adapters_coverage::normalize_path;
///
/// assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
/// assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
/// assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
/// ```
pub fn normalize_path(path: &str) -> String {
    normalize_path_with_strip(path, &[])
}

/// Normalize a file path with optional prefix stripping.
pub fn normalize_path_with_strip(path: &str, strip_prefixes: &[String]) -> String {
    let mut normalized = path.replace('\\', "/");

    // Apply configured prefix strips (normalized to forward slashes)
    for prefix in strip_prefixes {
        let prefix_norm = prefix.replace('\\', "/");
        if normalized.starts_with(&prefix_norm) {
            normalized = normalized[prefix_norm.len()..].to_string();
            break;
        }
    }

    // Remove leading ./
    while normalized.starts_with("./") {
        normalized = normalized[2..].to_string();
    }

    // Handle common absolute path patterns
    // Strip /home/user/project/ or /Users/user/project/ style prefixes
    // by finding the last occurrence of common source directories
    if normalized.starts_with('/') {
        // Look for common source directory markers
        for marker in &["/src/", "/lib/", "/test/", "/tests/"] {
            if let Some(pos) = normalized.find(marker) {
                // Keep from "src/" onwards (skip the leading /)
                normalized = normalized[pos + 1..].to_string();
                break;
            }
        }
    }

    // Handle Windows-style absolute paths (C:/...)
    if normalized.len() > 2 && normalized.chars().nth(1) == Some(':') {
        // Look for common source directory markers
        for marker in &["/src/", "/lib/", "/test/", "/tests/"] {
            if let Some(pos) = normalized.find(marker) {
                normalized = normalized[pos + 1..].to_string();
                break;
            }
        }
    }

    normalized
}

// ============================================================================
// LCOV Parsing
// ============================================================================

/// Parse an LCOV format string into a coverage map.
///
/// LCOV format records:
/// - `TN:<test name>` - Test name (optional, ignored)
/// - `SF:<source file>` - Source file path (starts a record)
/// - `DA:<line>,<hits>` - Line coverage data
/// - `end_of_record` - Ends the current record
///
/// # Examples
///
/// ```
/// use covguard_adapters_coverage::parse_lcov;
///
/// let lcov = r#"TN:
/// SF:src/lib.rs
/// DA:1,1
/// DA:2,0
/// end_of_record
/// "#;
///
/// let coverage = parse_lcov(lcov).unwrap();
/// assert_eq!(coverage.get("src/lib.rs").unwrap().get(&1), Some(&1));
/// assert_eq!(coverage.get("src/lib.rs").unwrap().get(&2), Some(&0));
/// ```
pub fn parse_lcov(text: &str) -> Result<CoverageMap, LcovError> {
    parse_lcov_with_strip(text, &[])
}

/// Parse an LCOV format string into a coverage map with optional prefix stripping.
pub fn parse_lcov_with_strip(
    text: &str,
    strip_prefixes: &[String],
) -> Result<CoverageMap, LcovError> {
    let mut coverage_map: CoverageMap = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut current_lines: BTreeMap<u32, u32> = BTreeMap::new();

    for (line_num, line) in text.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        if line.starts_with("TN:") {
            // Test name - ignored
            continue;
        }

        if let Some(path) = line.strip_prefix("SF:") {
            // Source file - start a new record
            // If there was a previous file without end_of_record, save it
            if let Some(file) = current_file.take() {
                merge_file_coverage(&mut coverage_map, &file, &current_lines);
                current_lines.clear();
            }
            current_file = Some(normalize_path_with_strip(path, strip_prefixes));
            current_lines = BTreeMap::new();
            continue;
        }

        if let Some(data) = line.strip_prefix("DA:") {
            // Line coverage data
            if current_file.is_none() {
                return Err(LcovError::InvalidFormat(format!(
                    "DA record at line {} without preceding SF record",
                    line_num + 1
                )));
            }

            let parts: Vec<&str> = data.split(',').collect();
            if parts.len() < 2 {
                return Err(LcovError::InvalidFormat(format!(
                    "Invalid DA format at line {}: expected 'DA:<line>,<hits>', got '{}'",
                    line_num + 1,
                    line
                )));
            }

            let line_number: u32 = parts[0].parse().map_err(|_| {
                LcovError::InvalidFormat(format!(
                    "Invalid line number at line {}: '{}'",
                    line_num + 1,
                    parts[0]
                ))
            })?;

            let hits: u32 = parts[1].parse().map_err(|_| {
                LcovError::InvalidFormat(format!(
                    "Invalid hit count at line {}: '{}'",
                    line_num + 1,
                    parts[1]
                ))
            })?;

            current_lines.insert(line_number, hits);
            continue;
        }

        if line == "end_of_record" {
            // End of record - save current file data
            if let Some(file) = current_file.take() {
                merge_file_coverage(&mut coverage_map, &file, &current_lines);
                current_lines.clear();
            }
            continue;
        }

        // Ignore other LCOV records (FN, FNF, FNH, BRDA, BRF, BRH, LF, LH, etc.)
        // These are function and branch coverage which we don't use
    }

    // Handle case where file has no end_of_record at the end
    if let Some(file) = current_file {
        merge_file_coverage(&mut coverage_map, &file, &current_lines);
    }

    Ok(coverage_map)
}

fn merge_file_coverage(coverage_map: &mut CoverageMap, file: &str, lines: &BTreeMap<u32, u32>) {
    let entry = coverage_map.entry(file.to_string()).or_default();
    for (line, hits) in lines {
        let existing = entry.entry(*line).or_insert(*hits);
        if *hits > *existing {
            *existing = *hits;
        }
    }
}

// ============================================================================
// Coverage Merging
// ============================================================================

/// Merge multiple coverage maps into one.
///
/// For files that appear in multiple maps:
/// - Lines are unioned
/// - Hit counts for the same line take the maximum value
///
/// # Examples
///
/// ```
/// use covguard_adapters_coverage::{parse_lcov, merge_coverage};
///
/// let lcov1 = "SF:src/lib.rs\nDA:1,1\nDA:2,0\nend_of_record\n";
/// let lcov2 = "SF:src/lib.rs\nDA:2,1\nDA:3,1\nend_of_record\n";
///
/// let map1 = parse_lcov(lcov1).unwrap();
/// let map2 = parse_lcov(lcov2).unwrap();
///
/// let merged = merge_coverage(vec![map1, map2]);
///
/// let file = merged.get("src/lib.rs").unwrap();
/// assert_eq!(file.get(&1), Some(&1));  // from map1
/// assert_eq!(file.get(&2), Some(&1));  // max(0, 1) = 1
/// assert_eq!(file.get(&3), Some(&1));  // from map2
/// ```
pub fn merge_coverage(maps: Vec<CoverageMap>) -> CoverageMap {
    let mut merged: CoverageMap = BTreeMap::new();

    for map in maps {
        for (file, lines) in map {
            let entry = merged.entry(file).or_default();
            for (line, hits) in lines {
                let current = entry.entry(line).or_insert(0);
                *current = (*current).max(hits);
            }
        }
    }

    merged
}

// ============================================================================
// Query Helpers
// ============================================================================

/// Get the hit count for a specific file and line.
///
/// Returns `None` if the file or line is not in the coverage map.
///
/// # Examples
///
/// ```
/// use covguard_adapters_coverage::{parse_lcov, get_hits};
///
/// let lcov = "SF:src/lib.rs\nDA:1,5\nend_of_record\n";
/// let coverage = parse_lcov(lcov).unwrap();
///
/// assert_eq!(get_hits(&coverage, "src/lib.rs", 1), Some(5));
/// assert_eq!(get_hits(&coverage, "src/lib.rs", 2), None);
/// assert_eq!(get_hits(&coverage, "other.rs", 1), None);
/// ```
pub fn get_hits(map: &CoverageMap, path: &str, line: u32) -> Option<u32> {
    map.get(path).and_then(|lines| lines.get(&line).copied())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Path Normalization Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_removes_leading_dot_slash() {
        assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path("././src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_converts_backslashes() {
        assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path("src\\sub\\lib.rs"), "src/sub/lib.rs");
    }

    #[test]
    fn test_normalize_path_handles_absolute_unix() {
        assert_eq!(
            normalize_path("/home/user/project/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(
            normalize_path("/Users/user/project/src/main.rs"),
            "src/main.rs"
        );
    }

    #[test]
    fn test_normalize_path_handles_absolute_windows() {
        assert_eq!(
            normalize_path("C:\\Users\\user\\project\\src\\lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(normalize_path("D:/code/project/src/main.rs"), "src/main.rs");
    }

    #[test]
    fn test_normalize_path_with_strip_prefixes() {
        let prefixes = vec!["/home/runner/work/".to_string(), "C:\\repo\\".to_string()];
        assert_eq!(
            normalize_path_with_strip("/home/runner/work/src/lib.rs", &prefixes),
            "src/lib.rs"
        );
        assert_eq!(
            normalize_path_with_strip("C:\\repo\\lib\\mod.rs", &prefixes),
            "lib/mod.rs"
        );
    }

    #[test]
    fn test_normalize_path_windows_marker_strips_to_lib() {
        assert_eq!(
            normalize_path("C:/code/project/lib/utils.rs"),
            "lib/utils.rs"
        );
    }

    // ------------------------------------------------------------------------
    // Fixture Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_covered_fixture() {
        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
DA:2,1
DA:3,1
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert_eq!(coverage.len(), 1);
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.get(&1), Some(&1));
        assert_eq!(file.get(&2), Some(&1));
        assert_eq!(file.get(&3), Some(&1));
    }

    #[test]
    fn test_parse_uncovered_fixture() {
        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert_eq!(coverage.len(), 1);
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.get(&1), Some(&0));
        assert_eq!(file.get(&2), Some(&0));
        assert_eq!(file.get(&3), Some(&0));
    }

    // ------------------------------------------------------------------------
    // Parsing Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_multiple_files() {
        let lcov = r#"TN:test
SF:src/lib.rs
DA:1,1
end_of_record
SF:src/main.rs
DA:5,0
DA:6,2
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert_eq!(coverage.len(), 2);

        let lib = coverage.get("src/lib.rs").unwrap();
        assert_eq!(lib.len(), 1);
        assert_eq!(lib.get(&1), Some(&1));

        let main = coverage.get("src/main.rs").unwrap();
        assert_eq!(main.len(), 2);
        assert_eq!(main.get(&5), Some(&0));
        assert_eq!(main.get(&6), Some(&2));
    }

    #[test]
    fn test_parse_lcov_merges_duplicate_records_takes_max_hits() {
        let lcov = r#"TN:test
SF:src/lib.rs
DA:1,1
end_of_record
SF:src/lib.rs
DA:1,3
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.get(&1), Some(&3));
    }

    #[test]
    fn test_parse_absolute_sf_paths() {
        let lcov = r#"TN:
SF:/home/user/project/src/lib.rs
DA:1,1
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert!(coverage.contains_key("src/lib.rs"));
        assert_eq!(coverage.get("src/lib.rs").unwrap().get(&1), Some(&1));
    }

    #[test]
    fn test_parse_windows_sf_paths() {
        let lcov = r#"TN:
SF:C:\Users\dev\project\src\lib.rs
DA:1,1
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert!(coverage.contains_key("src/lib.rs"));
    }

    #[test]
    fn test_parse_empty_input() {
        let coverage = parse_lcov("").unwrap();
        assert!(coverage.is_empty());
    }

    #[test]
    fn test_parse_empty_lines() {
        let lcov = r#"

TN:

SF:src/lib.rs

DA:1,1

end_of_record

"#;
        let coverage = parse_lcov(lcov).unwrap();
        assert_eq!(coverage.len(), 1);
    }

    #[test]
    fn test_parse_missing_end_of_record() {
        // Should still work - save data when encountering next SF or EOF
        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
SF:src/main.rs
DA:2,0
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert_eq!(coverage.len(), 2);
        assert!(coverage.contains_key("src/lib.rs"));
        assert!(coverage.contains_key("src/main.rs"));
    }

    #[test]
    fn test_parse_ignores_other_lcov_records() {
        let lcov = r#"TN:test
SF:src/lib.rs
FN:10,my_function
FNDA:5,my_function
FNF:1
FNH:1
DA:1,5
DA:2,5
BRDA:1,0,0,1
BRDA:1,0,1,0
BRF:2
BRH:1
LF:2
LH:2
end_of_record
"#;
        let coverage = parse_lcov(lcov).unwrap();

        assert_eq!(coverage.len(), 1);
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 2);
        assert_eq!(file.get(&1), Some(&5));
        assert_eq!(file.get(&2), Some(&5));
    }

    // ------------------------------------------------------------------------
    // Error Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_da_without_sf_fails() {
        let lcov = "DA:1,1\nend_of_record\n";
        let result = parse_lcov(lcov);

        assert!(matches!(
            result,
            Err(LcovError::InvalidFormat(msg)) if msg.contains("without preceding SF")
        ));
    }

    #[test]
    fn test_parse_invalid_da_format() {
        let lcov = "SF:src/lib.rs\nDA:invalid\nend_of_record\n";
        let result = parse_lcov(lcov);

        assert!(matches!(
            result,
            Err(LcovError::InvalidFormat(msg)) if msg.contains("Invalid DA format")
        ));
    }

    #[test]
    fn test_parse_invalid_line_number() {
        let lcov = "SF:src/lib.rs\nDA:abc,1\nend_of_record\n";
        let result = parse_lcov(lcov);

        assert!(matches!(
            result,
            Err(LcovError::InvalidFormat(msg)) if msg.contains("Invalid line number")
        ));
    }

    #[test]
    fn test_parse_invalid_hit_count() {
        let lcov = "SF:src/lib.rs\nDA:1,xyz\nend_of_record\n";
        let result = parse_lcov(lcov);

        assert!(matches!(
            result,
            Err(LcovError::InvalidFormat(msg)) if msg.contains("Invalid hit count")
        ));
    }

    // ------------------------------------------------------------------------
    // Merge Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_merge_disjoint_files() {
        let map1 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 1);
            m.insert("src/a.rs".to_string(), lines);
            m
        };

        let map2 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 1);
            m.insert("src/b.rs".to_string(), lines);
            m
        };

        let merged = merge_coverage(vec![map1, map2]);

        assert_eq!(merged.len(), 2);
        assert!(merged.contains_key("src/a.rs"));
        assert!(merged.contains_key("src/b.rs"));
    }

    #[test]
    fn test_merge_same_file_disjoint_lines() {
        let map1 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 1);
            lines.insert(2, 0);
            m.insert("src/lib.rs".to_string(), lines);
            m
        };

        let map2 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(3, 1);
            lines.insert(4, 0);
            m.insert("src/lib.rs".to_string(), lines);
            m
        };

        let merged = merge_coverage(vec![map1, map2]);

        assert_eq!(merged.len(), 1);
        let file = merged.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 4);
        assert_eq!(file.get(&1), Some(&1));
        assert_eq!(file.get(&2), Some(&0));
        assert_eq!(file.get(&3), Some(&1));
        assert_eq!(file.get(&4), Some(&0));
    }

    #[test]
    fn test_merge_same_line_takes_max() {
        let map1 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 0);
            lines.insert(2, 5);
            m.insert("src/lib.rs".to_string(), lines);
            m
        };

        let map2 = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 3);
            lines.insert(2, 2);
            m.insert("src/lib.rs".to_string(), lines);
            m
        };

        let merged = merge_coverage(vec![map1, map2]);

        let file = merged.get("src/lib.rs").unwrap();
        assert_eq!(file.get(&1), Some(&3)); // max(0, 3)
        assert_eq!(file.get(&2), Some(&5)); // max(5, 2)
    }

    #[test]
    fn test_merge_empty() {
        let merged = merge_coverage(vec![]);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_merge_single_map() {
        let map = {
            let mut m: CoverageMap = BTreeMap::new();
            let mut lines = BTreeMap::new();
            lines.insert(1, 1);
            m.insert("src/lib.rs".to_string(), lines);
            m
        };

        let merged = merge_coverage(vec![map]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged.get("src/lib.rs").unwrap().get(&1), Some(&1));
    }

    // ------------------------------------------------------------------------
    // Query Helper Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_get_hits_existing() {
        let mut coverage: CoverageMap = BTreeMap::new();
        let mut lines = BTreeMap::new();
        lines.insert(1, 5);
        lines.insert(2, 0);
        coverage.insert("src/lib.rs".to_string(), lines);

        assert_eq!(get_hits(&coverage, "src/lib.rs", 1), Some(5));
        assert_eq!(get_hits(&coverage, "src/lib.rs", 2), Some(0));
    }

    #[test]
    fn test_get_hits_missing_line() {
        let mut coverage: CoverageMap = BTreeMap::new();
        let mut lines = BTreeMap::new();
        lines.insert(1, 5);
        coverage.insert("src/lib.rs".to_string(), lines);

        assert_eq!(get_hits(&coverage, "src/lib.rs", 99), None);
    }

    #[test]
    fn test_get_hits_missing_file() {
        let coverage: CoverageMap = BTreeMap::new();

        assert_eq!(get_hits(&coverage, "nonexistent.rs", 1), None);
    }
}

// ============================================================================
// Property Tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Merging coverage maps should be commutative
        #[test]
        fn merge_is_commutative(
            lines1 in prop::collection::btree_map(1u32..100, 0u32..1000, 0..10),
            lines2 in prop::collection::btree_map(1u32..100, 0u32..1000, 0..10),
        ) {
            let mut map1: CoverageMap = BTreeMap::new();
            map1.insert("file.rs".to_string(), lines1.clone());

            let mut map2: CoverageMap = BTreeMap::new();
            map2.insert("file.rs".to_string(), lines2.clone());

            let merged_12 = merge_coverage(vec![map1.clone(), map2.clone()]);
            let merged_21 = merge_coverage(vec![map2, map1]);

            prop_assert_eq!(merged_12, merged_21);
        }

        /// Merging with empty map is identity
        #[test]
        fn merge_with_empty_is_identity(
            lines in prop::collection::btree_map(1u32..100, 0u32..1000, 0..10),
        ) {
            let mut map: CoverageMap = BTreeMap::new();
            map.insert("file.rs".to_string(), lines);

            let merged = merge_coverage(vec![map.clone(), BTreeMap::new()]);

            prop_assert_eq!(merged, map);
        }

        /// Merge result has max hits for each line
        #[test]
        fn merge_takes_max_hits(
            line in 1u32..100,
            hits1 in 0u32..1000,
            hits2 in 0u32..1000,
        ) {
            let mut map1: CoverageMap = BTreeMap::new();
            let mut lines1 = BTreeMap::new();
            lines1.insert(line, hits1);
            map1.insert("file.rs".to_string(), lines1);

            let mut map2: CoverageMap = BTreeMap::new();
            let mut lines2 = BTreeMap::new();
            lines2.insert(line, hits2);
            map2.insert("file.rs".to_string(), lines2);

            let merged = merge_coverage(vec![map1, map2]);
            let actual_hits = get_hits(&merged, "file.rs", line).unwrap();

            prop_assert_eq!(actual_hits, hits1.max(hits2));
        }

        /// Path normalization is idempotent
        #[test]
        fn normalize_path_idempotent(path in "[a-z/\\.]{1,50}") {
            let once = normalize_path(&path);
            let twice = normalize_path(&once);
            prop_assert_eq!(once, twice);
        }

        /// Parsing valid LCOV and reparsing gives same result
        #[test]
        fn roundtrip_simple_lcov(
            line_num in 1u32..1000,
            hits in 0u32..1000,
        ) {
            let lcov = format!(
                "TN:\nSF:src/test.rs\nDA:{},{}\nend_of_record\n",
                line_num, hits
            );

            let coverage = parse_lcov(&lcov).unwrap();
            prop_assert_eq!(
                coverage.get("src/test.rs").unwrap().get(&line_num),
                Some(&hits)
            );
        }
    }
}

// ============================================================================
// Integration Tests (with actual fixture files)
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test parsing the actual covered.info fixture file
    #[test]
    fn test_parse_covered_info_fixture_file() {
        let lcov_content = include_str!("../../../fixtures/lcov/covered.info");
        let coverage = parse_lcov(lcov_content).unwrap();

        // Expected: {"src/lib.rs": {1: 1, 2: 1, 3: 1}}
        assert_eq!(coverage.len(), 1);
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.get(&1), Some(&1));
        assert_eq!(file.get(&2), Some(&1));
        assert_eq!(file.get(&3), Some(&1));
    }

    /// Test parsing the actual uncovered.info fixture file
    #[test]
    fn test_parse_uncovered_info_fixture_file() {
        let lcov_content = include_str!("../../../fixtures/lcov/uncovered.info");
        let coverage = parse_lcov(lcov_content).unwrap();

        // Expected: {"src/lib.rs": {1: 0, 2: 0, 3: 0}}
        assert_eq!(coverage.len(), 1);
        let file = coverage.get("src/lib.rs").unwrap();
        assert_eq!(file.len(), 3);
        assert_eq!(file.get(&1), Some(&0));
        assert_eq!(file.get(&2), Some(&0));
        assert_eq!(file.get(&3), Some(&0));
    }

    /// Test merging the covered and uncovered fixture files
    #[test]
    fn test_merge_fixture_files() {
        let covered = include_str!("../../../fixtures/lcov/covered.info");
        let uncovered = include_str!("../../../fixtures/lcov/uncovered.info");

        let map1 = parse_lcov(covered).unwrap();
        let map2 = parse_lcov(uncovered).unwrap();

        let merged = merge_coverage(vec![map1, map2]);

        // Both files have same path, max should be taken
        let file = merged.get("src/lib.rs").unwrap();
        assert_eq!(file.get(&1), Some(&1)); // max(1, 0) = 1
        assert_eq!(file.get(&2), Some(&1)); // max(1, 0) = 1
        assert_eq!(file.get(&3), Some(&1)); // max(1, 0) = 1
    }
}
