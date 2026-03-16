//! coverage.py JSON coverage file parser for covguard.
//!
//! This module provides parsing of coverage.py JSON format coverage files,
//! producing a normalized coverage map that can be used by the domain layer.
//!
//! Only available when the `coverage-py` feature is enabled.
//!
//! # Format Overview
//!
//! coverage.py generates JSON reports with this structure:
//! ```json
//! {
//!   "meta": {
//!     "version": "5.5",
//!     "timestamp": "2024-01-15T10:30:00.000000",
//!     "branch_coverage": false
//!   },
//!   "files": {
//!     "src/main.py": {
//!       "executed_lines": [1, 2, 5, 10, 11],
//!       "summary": { ... }
//!     }
//!   }
//! }
//! ```
//!
//! # Key Mappings
//!
//! - Path: `files` object key (e.g., `src/main.py`)
//! - Line numbers: `executed_lines` array
//! - Hit count: 1 for each executed line (coverage.py doesn't track hit counts)

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use crate::{normalize_path_with_strip, CoverageMap};

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur while parsing coverage.py JSON files.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoveragePyError {
    /// Invalid JSON format.
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    /// Invalid coverage.py format - missing required fields.
    #[error("Invalid coverage.py format: {0}")]
    InvalidFormat(String),
}

// ============================================================================
// JSON Structures
// ============================================================================

/// Root structure of a coverage.py JSON report.
#[derive(Debug, Clone, Deserialize)]
struct CoverageReport {
    /// Metadata about the coverage run.
    #[serde(default)]
    meta: Option<CoverageMeta>,
    /// File coverage data, keyed by file path.
    files: BTreeMap<String, FileCoverage>,
}

/// Metadata about the coverage run.
#[derive(Debug, Clone, Deserialize)]
struct CoverageMeta {
    /// coverage.py version.
    #[serde(default)]
    version: Option<String>,
    /// Timestamp of the coverage run.
    #[serde(default)]
    timestamp: Option<String>,
    /// Whether branch coverage was enabled.
    #[serde(default)]
    branch_coverage: Option<bool>,
}

/// Coverage data for a single file.
#[derive(Debug, Clone, Deserialize)]
struct FileCoverage {
    /// Lines that were executed (have coverage).
    #[serde(default)]
    executed_lines: Vec<u32>,
    /// Summary statistics (not used by parser).
    #[serde(default)]
    summary: Option<FileSummary>,
}

/// Summary statistics for a file.
#[derive(Debug, Clone, Deserialize)]
struct FileSummary {
    /// Number of covered lines.
    #[serde(default)]
    covered_lines: Option<u32>,
    /// Total number of statements.
    #[serde(default)]
    num_statements: Option<u32>,
    /// Percentage covered.
    #[serde(default)]
    percent_covered: Option<f64>,
}

// ============================================================================
// coverage.py Parsing
// ============================================================================

/// Parse a coverage.py JSON format string into a coverage map.
///
/// coverage.py JSON format key elements:
/// - `meta` - Metadata object (optional, contains version, timestamp, etc.)
/// - `files` - Object mapping file paths to coverage data
/// - `executed_lines` - Array of line numbers that were executed
///
/// # Path Handling
///
/// File paths from coverage.py are typically relative to the project root.
/// They are normalized using the standard path normalization:
/// - Backslashes converted to forward slashes
/// - Leading `./` removed
/// - Common absolute path prefixes stripped
///
/// # Line Coverage
///
/// coverage.py only reports executed lines. Lines not in `executed_lines`
/// are considered uncovered. The hit count is always 1 for executed lines
/// since coverage.py doesn't track execution counts.
///
/// # Examples
///
/// ```ignore
/// use covguard_adapters_coverage::parse_coverage_py;
///
/// let json = r#"{
///   "meta": { "version": "5.5" },
///   "files": {
///     "src/main.py": {
///       "executed_lines": [1, 2, 5, 10]
///     }
///   }
/// }"#;
///
/// let coverage = parse_coverage_py(json).unwrap();
/// assert_eq!(coverage.get("src/main.py").unwrap().get(&1), Some(&1));
/// assert_eq!(coverage.get("src/main.py").unwrap().get(&5), Some(&1));
/// ```
pub fn parse_coverage_py(text: &str) -> Result<CoverageMap, CoveragePyError> {
    parse_coverage_py_with_strip(text, &[])
}

/// Parse a coverage.py JSON format string into a coverage map with optional prefix stripping.
pub fn parse_coverage_py_with_strip(
    text: &str,
    strip_prefixes: &[String],
) -> Result<CoverageMap, CoveragePyError> {
    // Parse JSON
    let report: CoverageReport =
        serde_json::from_str(text).map_err(|e| CoveragePyError::InvalidJson(e.to_string()))?;

    // Convert to coverage map
    let mut coverage_map: CoverageMap = BTreeMap::new();

    for (path, file_coverage) in report.files {
        let normalized_path = normalize_path_with_strip(&path, strip_prefixes);
        let line_coverage: BTreeMap<u32, u32> = file_coverage
            .executed_lines
            .into_iter()
            .map(|line| (line, 1)) // coverage.py doesn't track hit counts, use 1
            .collect();

        // Always insert the file into the coverage map, even if it has no
        // executed lines. This lets the domain layer distinguish "file is
        // present in coverage data with 0% coverage" from "file has no
        // coverage data at all" (missing).
        coverage_map
            .entry(normalized_path.clone())
            .or_default();

        merge_file_coverage(&mut coverage_map, &normalized_path, &line_coverage);
    }

    Ok(coverage_map)
}

/// Merge file coverage into the coverage map.
fn merge_file_coverage(
    coverage_map: &mut CoverageMap,
    file: &str,
    lines: &BTreeMap<u32, u32>,
) {
    if lines.is_empty() {
        return;
    }
    let entry = coverage_map.entry(file.to_string()).or_default();
    for (line, hits) in lines {
        let existing = entry.entry(*line).or_insert(*hits);
        if *hits > *existing {
            *existing = *hits;
        }
    }
}

// ============================================================================
// Format Detection
// ============================================================================

/// Check if the content appears to be a coverage.py JSON report.
///
/// Returns true if the content:
/// 1. Is valid JSON
/// 2. Has a `files` key at the root level
/// 3. Optionally has a `meta` key (not required but indicative)
///
/// This detection is intentionally lenient to handle variations in
/// coverage.py output format across versions.
pub fn is_coverage_py_format(text: &str) -> bool {
    let trimmed = text.trim();

    // Quick check: must start with '{'
    if !trimmed.starts_with('{') {
        return false;
    }

    // Try to parse as JSON and check structure
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => {
            // Must have "files" key
            if !map.contains_key("files") {
                return false;
            }

            // "files" should be an object
            if let Some(files) = map.get("files") {
                matches!(files, serde_json::Value::Object(_))
            } else {
                false
            }
        }
        _ => false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coverage_py_minimal() {
        let json = r#"{
            "meta": {
                "version": "5.5",
                "timestamp": "2024-01-15T10:30:00.000000",
                "branch_coverage": false
            },
            "files": {
                "src/main.py": {
                    "executed_lines": [1, 2, 5, 10],
                    "summary": {
                        "covered_lines": 4,
                        "num_statements": 10,
                        "percent_covered": 40.0
                    }
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert!(coverage.contains_key("src/main.py"));
        let file = coverage.get("src/main.py").unwrap();
        assert_eq!(file.get(&1), Some(&1));
        assert_eq!(file.get(&2), Some(&1));
        assert_eq!(file.get(&5), Some(&1));
        assert_eq!(file.get(&10), Some(&1));
        assert_eq!(file.len(), 4);
    }

    #[test]
    fn test_parse_coverage_py_multiple_files() {
        let json = r#"{
            "meta": {"version": "5.5"},
            "files": {
                "src/main.py": {
                    "executed_lines": [1, 2, 3]
                },
                "src/utils.py": {
                    "executed_lines": [10, 20, 30]
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert_eq!(coverage.len(), 2);
        assert!(coverage.contains_key("src/main.py"));
        assert!(coverage.contains_key("src/utils.py"));

        let main = coverage.get("src/main.py").unwrap();
        assert_eq!(main.get(&1), Some(&1));
        assert_eq!(main.get(&2), Some(&1));
        assert_eq!(main.get(&3), Some(&1));

        let utils = coverage.get("src/utils.py").unwrap();
        assert_eq!(utils.get(&10), Some(&1));
        assert_eq!(utils.get(&20), Some(&1));
        assert_eq!(utils.get(&30), Some(&1));
    }

    #[test]
    fn test_parse_coverage_py_without_meta() {
        let json = r#"{
            "files": {
                "src/lib.py": {
                    "executed_lines": [5, 10, 15]
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert!(coverage.contains_key("src/lib.py"));
        let file = coverage.get("src/lib.py").unwrap();
        assert_eq!(file.get(&5), Some(&1));
        assert_eq!(file.get(&10), Some(&1));
        assert_eq!(file.get(&15), Some(&1));
    }

    #[test]
    fn test_parse_coverage_py_empty_files() {
        let json = r#"{
            "meta": {"version": "5.5"},
            "files": {}
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert!(coverage.is_empty());
    }

    #[test]
    fn test_parse_coverage_py_empty_executed_lines() {
        let json = r#"{
            "files": {
                "src/empty.py": {
                    "executed_lines": [],
                    "summary": {
                        "covered_lines": 0,
                        "num_statements": 5,
                        "percent_covered": 0.0
                    }
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        // Files with no executed lines should still appear in coverage map
        // (with an empty line map) so domain can distinguish "uncovered" from "missing"
        assert!(coverage.contains_key("src/empty.py"));
        assert!(coverage.get("src/empty.py").unwrap().is_empty());
    }

    #[test]
    fn test_parse_coverage_py_normalizes_paths() {
        let json = r#"{
            "files": {
                "./src/lib.py": {
                    "executed_lines": [1]
                },
                "src\\utils.py": {
                    "executed_lines": [2]
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        // Paths should be normalized
        assert!(coverage.contains_key("src/lib.py"));
        assert!(coverage.contains_key("src/utils.py"));
    }

    #[test]
    fn test_parse_coverage_py_with_strip_prefix() {
        let json = r#"{
            "files": {
                "/home/user/project/src/lib.py": {
                    "executed_lines": [1, 2, 3]
                }
            }
        }"#;

        let prefixes = vec!["/home/user/project/".to_string()];
        let coverage = parse_coverage_py_with_strip(json, &prefixes).unwrap();
        assert!(coverage.contains_key("src/lib.py"));
    }

    #[test]
    fn test_parse_coverage_py_invalid_json() {
        let invalid = r#"{ not valid json }"#;
        let result = parse_coverage_py(invalid);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoveragePyError::InvalidJson(_)));
    }

    #[test]
    fn test_parse_coverage_py_missing_files() {
        let json = r#"{
            "meta": {"version": "5.5"}
        }"#;

        let result = parse_coverage_py(json);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CoveragePyError::InvalidJson(_)));
    }

    #[test]
    fn test_is_coverage_py_format_valid() {
        let json = r#"{
            "meta": {"version": "5.5"},
            "files": {
                "src/main.py": {"executed_lines": [1, 2]}
            }
        }"#;
        assert!(is_coverage_py_format(json));
    }

    #[test]
    fn test_is_coverage_py_format_without_meta() {
        let json = r#"{
            "files": {
                "src/main.py": {"executed_lines": [1]}
            }
        }"#;
        assert!(is_coverage_py_format(json));
    }

    #[test]
    fn test_is_coverage_py_format_missing_files() {
        let json = r#"{
            "meta": {"version": "5.5"}
        }"#;
        assert!(!is_coverage_py_format(json));
    }

    #[test]
    fn test_is_coverage_py_format_not_json() {
        assert!(!is_coverage_py_format("not json"));
        assert!(!is_coverage_py_format("<xml></xml>"));
        assert!(!is_coverage_py_format("SF:src/lib.rs\nDA:1,1\nend_of_record"));
    }

    #[test]
    fn test_is_coverage_py_format_files_not_object() {
        let json = r#"{
            "files": ["src/main.py", "src/lib.py"]
        }"#;
        assert!(!is_coverage_py_format(json));
    }

    #[test]
    fn test_parse_coverage_py_real_world_fixture() {
        // Simulates a real coverage.py output
        let json = r#"{
            "meta": {
                "version": "7.4.4",
                "timestamp": "2024-01-15T10:30:00.000000",
                "branch_coverage": true,
                "show_contexts": false
            },
            "files": {
                "src/__init__.py": {
                    "executed_lines": [1],
                    "summary": {
                        "covered_lines": 1,
                        "num_statements": 1,
                        "percent_covered": 100.0,
                        "missing_lines": 0,
                        "excluded_lines": 0
                    }
                },
                "src/calculator.py": {
                    "executed_lines": [1, 2, 5, 6, 7, 10, 11, 12, 15, 20],
                    "summary": {
                        "covered_lines": 10,
                        "num_statements": 15,
                        "percent_covered": 66.67,
                        "missing_lines": 5,
                        "excluded_lines": 0
                    }
                },
                "tests/test_calculator.py": {
                    "executed_lines": [1, 2, 3, 5, 6, 7, 8, 10, 11, 12],
                    "summary": {
                        "covered_lines": 10,
                        "num_statements": 10,
                        "percent_covered": 100.0,
                        "missing_lines": 0,
                        "excluded_lines": 0
                    }
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert_eq!(coverage.len(), 3);

        // Check __init__.py
        let init = coverage.get("src/__init__.py").unwrap();
        assert_eq!(init.len(), 1);
        assert_eq!(init.get(&1), Some(&1));

        // Check calculator.py
        let calc = coverage.get("src/calculator.py").unwrap();
        assert_eq!(calc.len(), 10);
        assert_eq!(calc.get(&1), Some(&1));
        assert_eq!(calc.get(&20), Some(&1));

        // Check test file
        let test = coverage.get("tests/test_calculator.py").unwrap();
        assert_eq!(test.len(), 10);
    }
}
