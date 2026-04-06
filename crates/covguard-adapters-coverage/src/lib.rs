//! LCOV coverage file parser for covguard.
//!
//! This crate provides parsing and merging of LCOV coverage files,
//! producing a normalized coverage map that can be used by the domain layer.

use std::collections::BTreeMap;

use covguard_paths::{normalize_coverage_path, normalize_coverage_path_with_strip};
use covguard_ports::{CoverageMap as PortCoverageMap, CoverageProvider};
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
    #[error("{message}")]
    InvalidFormat {
        /// Detailed error message
        message: String,
        /// Line number where the error occurred (1-indexed)
        line_number: Option<usize>,
        /// Suggestion for fixing the error
        suggestion: Option<String>,
    },

    /// Missing SF (source file) record.
    #[error("Missing SF (source file) record at line {line_number}")]
    MissingSourceFile {
        /// Line number where the error occurred (1-indexed)
        line_number: usize,
    },

    /// Invalid DA (data) record format.
    #[error("Invalid DA record at line {line_number}: expected 'DA:<line>,<hits>', got '{actual}'")]
    InvalidDaRecord {
        /// Line number where the error occurred (1-indexed)
        line_number: usize,
        /// The actual content that was found
        actual: String,
    },

    /// I/O error while reading the file.
    #[error("I/O error: {message}")]
    IoError {
        /// Error message
        message: String,
        /// Path to the file that couldn't be read
        path: Option<String>,
    },

    /// Empty LCOV file.
    #[error("LCOV file is empty or contains no valid records")]
    EmptyFile,

    /// Truncated LCOV file.
    #[error("LCOV file appears truncated: {0}")]
    TruncatedFile(String),
}

impl LcovError {
    /// Creates an InvalidFormat error with a simple message (for backward compatibility).
    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: message.into(),
            line_number: None,
            suggestion: None,
        }
    }

    /// Creates an InvalidFormat error with line number context.
    pub fn invalid_format_at_line(message: impl Into<String>, line_number: usize) -> Self {
        Self::InvalidFormat {
            message: message.into(),
            line_number: Some(line_number),
            suggestion: None,
        }
    }

    /// Creates an IoError with file path context.
    pub fn io_error_with_path(message: impl Into<String>, path: impl Into<String>) -> Self {
        Self::IoError {
            message: message.into(),
            path: Some(path.into()),
        }
    }
}

impl covguard_types::EnhancedError for LcovError {
    fn code(&self) -> &'static str {
        covguard_types::CODE_INVALID_LCOV
    }

    fn description(&self) -> &str {
        match self {
            Self::InvalidFormat { .. } => "Failed to parse LCOV file",
            Self::MissingSourceFile { .. } => "Missing source file record in LCOV",
            Self::InvalidDaRecord { .. } => "Invalid data record in LCOV",
            Self::IoError { .. } => "Failed to read LCOV file",
            Self::EmptyFile => "LCOV file is empty",
            Self::TruncatedFile(_) => "LCOV file is truncated",
        }
    }

    fn remediation(&self) -> &str {
        match self {
            Self::InvalidFormat { suggestion, .. } => suggestion.as_deref().unwrap_or(
                "Verify the coverage generation step produced valid LCOV.\n\
                     Ensure the LCOV file is not truncated or corrupted.\n\
                     Try running: geninfo output.gcno -o coverage.info",
            ),
            Self::MissingSourceFile { .. } => {
                "LCOV files must start with SF: records. Ensure your coverage\n\
                 report was generated correctly. Try running:\n\
                   geninfo output.gcno -o coverage.info"
            }
            Self::InvalidDaRecord { .. } => {
                "DA records must be in format 'DA:<line_number>,<hit_count>'.\n\
                 Ensure the coverage tool generated the report correctly."
            }
            Self::IoError { path, .. } => {
                if path.is_some() {
                    "Check that the file path is correct and readable.\n\
                     Ensure the file exists and has appropriate permissions."
                } else {
                    "Check file permissions and disk availability."
                }
            }
            Self::EmptyFile => {
                "The LCOV file contains no coverage data. Ensure:\n\
                 1. Tests were executed before coverage collection\n\
                 2. Coverage tool was configured to output LCOV format\n\
                 3. Source files were compiled with coverage flags"
            }
            Self::TruncatedFile(_) => {
                "The LCOV file appears incomplete. This can happen if:\n\
                 1. Coverage generation was interrupted\n\
                 2. File transfer was incomplete\n\
                 3. Disk ran out of space during write\n\
                 Regenerate the coverage report and try again."
            }
        }
    }

    fn help_uri(&self) -> &'static str {
        "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#invalid_lcov"
    }

    fn format_enhanced(&self) -> String {
        let context = match self {
            Self::InvalidFormat { line_number, .. } => {
                if let Some(ln) = line_number {
                    format!("at line {}", ln)
                } else {
                    String::new()
                }
            }
            Self::MissingSourceFile { line_number } => format!("at line {}", line_number),
            Self::InvalidDaRecord { line_number, .. } => format!("at line {}", line_number),
            Self::IoError { path: Some(p), .. } => format!("file: {}", p),
            _ => String::new(),
        };

        if context.is_empty() {
            format!(
                "Error [{}]: {}\n  {}\n\n  Hint: {}\n\n  See: {}\n",
                self.code(),
                self.description(),
                self,
                self.remediation(),
                self.help_uri()
            )
        } else {
            format!(
                "Error [{}]: {}\n  {}\n  Context: {}\n\n  Hint: {}\n\n  See: {}\n",
                self.code(),
                self.description(),
                self,
                context,
                self.remediation(),
                self.help_uri()
            )
        }
    }
}

/// Default LCOV coverage provider backed by this crate's parser and merger.
pub struct LcovCoverageProvider;

impl CoverageProvider for LcovCoverageProvider {
    fn parse_coverage(
        &self,
        text: &str,
        format: covguard_types::CoverageFormat,
        strip_prefixes: &[String],
    ) -> Result<PortCoverageMap, String> {
        if format != covguard_types::CoverageFormat::Lcov
            && format != covguard_types::CoverageFormat::Auto
        {
            return Err(format!(
                "LcovCoverageProvider only supports Lcov format, got {:?}",
                format
            ));
        }
        parse_lcov_with_strip(text, strip_prefixes).map_err(|e| e.to_string())
    }

    fn merge_coverage(&self, maps: Vec<PortCoverageMap>) -> PortCoverageMap {
        merge_coverage(maps)
    }
}

// ============================================================================
// Path Normalization
// ============================================================================

/// Normalize a file path to repo-relative format.
pub fn normalize_path(path: &str) -> String {
    normalize_coverage_path(path)
}

/// Normalize a file path with optional prefix stripping.
pub fn normalize_path_with_strip(path: &str, strip_prefixes: &[String]) -> String {
    normalize_coverage_path_with_strip(path, strip_prefixes)
}

// ============================================================================
// LCOV Parsing
// ============================================================================

/// Parse an LCOV format string into a coverage map.
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

        if line.is_empty() {
            continue;
        }

        if line.starts_with("TN:") {
            continue;
        }

        if let Some(path) = line.strip_prefix("SF:") {
            if let Some(file) = current_file.take() {
                merge_file_coverage(&mut coverage_map, &file, &current_lines);
                current_lines.clear();
            }
            current_file = Some(normalize_path_with_strip(path, strip_prefixes));
            current_lines = BTreeMap::new();
            continue;
        }

        if let Some(data) = line.strip_prefix("DA:") {
            if current_file.is_none() {
                return Err(LcovError::MissingSourceFile {
                    line_number: line_num + 1,
                });
            }

            let parts: Vec<&str> = data.split(',').collect();
            if parts.len() < 2 {
                return Err(LcovError::InvalidDaRecord {
                    line_number: line_num + 1,
                    actual: line.to_string(),
                });
            }

            let line_number: u32 = parts[0].parse().map_err(|_| {
                LcovError::invalid_format_at_line(
                    format!("Invalid line number: '{}'", parts[0]),
                    line_num + 1,
                )
            })?;

            let hits: u32 = parts[1].parse().map_err(|_| {
                LcovError::invalid_format_at_line(
                    format!("Invalid hit count: '{}'", parts[1]),
                    line_num + 1,
                )
            })?;

            current_lines.insert(line_number, hits);
            continue;
        }

        if line == "end_of_record" {
            if let Some(file) = current_file.take() {
                merge_file_coverage(&mut coverage_map, &file, &current_lines);
                current_lines.clear();
            }
            continue;
        }
    }

    if let Some(file) = current_file {
        merge_file_coverage(&mut coverage_map, &file, &current_lines);
    }

    if coverage_map.is_empty() && !text.trim().is_empty() {
        return Err(LcovError::EmptyFile);
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
pub fn get_hits(map: &CoverageMap, path: &str, line: u32) -> Option<u32> {
    map.get(path).and_then(|lines| lines.get(&line).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lcov_simple() {
        let lcov = "SF:src/lib.rs\nDA:1,1\nDA:2,0\nend_of_record\n";
        let coverage = parse_lcov(lcov).unwrap();
        assert_eq!(get_hits(&coverage, "src/lib.rs", 1), Some(1));
        assert_eq!(get_hits(&coverage, "src/lib.rs", 2), Some(0));
    }
}
