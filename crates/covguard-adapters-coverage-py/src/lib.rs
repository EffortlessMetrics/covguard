//! coverage.py JSON coverage file parser for covguard.
//!
//! This crate provides parsing of coverage.py JSON format coverage files,
//! producing a normalized coverage map that can be used by the domain layer.

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use covguard_paths::normalize_coverage_path_with_strip;
use covguard_ports::{CoverageMap, CoverageProvider};

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
#[allow(dead_code)]
struct CoverageReport {
    /// Metadata about the coverage run.
    #[serde(default)]
    meta: Option<CoverageMeta>,
    /// File coverage data, keyed by file path.
    files: BTreeMap<String, FileCoverage>,
}

/// Metadata about the coverage run.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
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
    /// Lines known to be missing from coverage.
    #[serde(default)]
    missing_lines: Vec<u32>,
}

// ============================================================================
// coverage.py Parsing
// ============================================================================

/// Parse a coverage.py JSON format string into a coverage map.
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
        let normalized_path = normalize_coverage_path_with_strip(&path, strip_prefixes);
        let mut line_coverage: BTreeMap<u32, u32> = file_coverage
            .executed_lines
            .into_iter()
            .map(|line| (line, 1)) // coverage.py doesn't track hit counts, use 1
            .collect();

        for line in file_coverage.missing_lines {
            line_coverage.entry(line).or_insert(0);
        }

        coverage_map.insert(normalized_path, line_coverage);
    }

    Ok(coverage_map)
}

/// Check if the content appears to be a coverage.py JSON report.
pub fn is_coverage_py_format(text: &str) -> bool {
    let trimmed = text.trim();
    if !trimmed.starts_with('{') {
        return false;
    }
    match serde_json::from_str::<serde_json::Value>(trimmed) {
        Ok(serde_json::Value::Object(map)) => {
            if !map.contains_key("files") {
                return false;
            }
            if let Some(files) = map.get("files") {
                matches!(files, serde_json::Value::Object(_))
            } else {
                false
            }
        }
        _ => false,
    }
}

/// coverage.py coverage provider implementation.
pub struct CoveragePyProvider;

impl CoverageProvider for CoveragePyProvider {
    fn parse_coverage(
        &self,
        text: &str,
        format: covguard_types::CoverageFormat,
        strip_prefixes: &[String],
    ) -> Result<CoverageMap, String> {
        if format != covguard_types::CoverageFormat::CoveragePy
            && format != covguard_types::CoverageFormat::Auto
        {
            return Err(format!(
                "CoveragePyProvider only supports CoveragePy format, got {:?}",
                format
            ));
        }
        if format == covguard_types::CoverageFormat::Auto && !is_coverage_py_format(text) {
            return Err("Auto-detection failed for CoveragePy format".to_string());
        }
        parse_coverage_py_with_strip(text, strip_prefixes).map_err(|e| e.to_string())
    }

    fn merge_coverage(&self, maps: Vec<CoverageMap>) -> CoverageMap {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coverage_py_minimal() {
        let json = r#"{
            "files": {
                "src/main.py": {
                    "executed_lines": [1, 2, 5, 10]
                }
            }
        }"#;

        let coverage = parse_coverage_py(json).unwrap();
        assert!(coverage.contains_key("src/main.py"));
        let file = coverage.get("src/main.py").unwrap();
        assert_eq!(file.get(&1), Some(&1));
        assert_eq!(file.len(), 4);
    }

    #[test]
    fn test_is_coverage_py_format_valid() {
        let json = r#"{
            "files": {
                "src/main.py": {"executed_lines": [1, 2]}
            }
        }"#;
        assert!(is_coverage_py_format(json));
    }
}
