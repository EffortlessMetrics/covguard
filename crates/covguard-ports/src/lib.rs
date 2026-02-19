//! Shared port traits and boundary DTOs for covguard's hexagonal architecture.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::Path;

/// Canonical changed-line representation used at the port boundary.
pub type ChangedRanges = BTreeMap<String, Vec<RangeInclusive<u32>>>;

/// Canonical line-hit representation used at the port boundary.
pub type CoverageMap = BTreeMap<String, BTreeMap<u32, u32>>;

/// Parsed diff payload used by the diff provider port.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiffParseResult {
    /// Changed lines grouped by normalized repo-relative path.
    pub changed_ranges: ChangedRanges,
    /// Binary file paths detected in the diff.
    pub binary_files: Vec<String>,
}

/// Port for obtaining changed ranges from diff input.
pub trait DiffProvider {
    /// Parse unified diff text and return changed ranges plus metadata.
    fn parse_patch(&self, text: &str) -> Result<DiffParseResult, String>;

    /// Load a unified diff between two refs from a repository path.
    fn load_diff_from_git(
        &self,
        base: &str,
        head: &str,
        repo_root: &Path,
    ) -> Result<String, String>;
}

/// Port for loading and merging LCOV coverage data.
pub trait CoverageProvider {
    /// Parse an LCOV payload into a normalized coverage map.
    fn parse_lcov(&self, text: &str, strip_prefixes: &[String]) -> Result<CoverageMap, String>;

    /// Merge multiple coverage maps into one.
    fn merge_coverage(&self, maps: Vec<CoverageMap>) -> CoverageMap;
}

/// Port for obtaining the current UTC time.
pub trait Clock {
    /// Returns the current time in UTC.
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
}

/// Port for reading source lines from the repository.
pub trait RepoReader {
    /// Returns the source line at 1-based `line_no`, or `None` when unavailable.
    fn read_line(&self, path: &str, line_no: u32) -> Option<String>;
}
