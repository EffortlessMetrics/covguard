//! Canonical error codes and enhanced error traits for covguard.
//!
//! This crate defines the shared vocabulary of error codes used by all
//! covguard components, enabling consistent reporting and remediation advice.

use serde::{Deserialize, Serialize};

// ============================================================================
// Enums
// ============================================================================

/// Supported coverage report formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CoverageFormat {
    /// LCOV format (default).
    #[default]
    Lcov,
    /// JaCoCo XML format.
    Jacoco,
    /// coverage.py JSON format.
    CoveragePy,
    /// Automatically detect format from content.
    Auto,
}

// ============================================================================
// Error Code Constants
// ============================================================================

/// Error code for uncovered changed lines.
pub const CODE_UNCOVERED_LINE: &str = "covguard.diff.uncovered_line";

/// Error code for diff coverage below threshold.
pub const CODE_COVERAGE_BELOW_THRESHOLD: &str = "covguard.diff.coverage_below_threshold";

/// Error code for files with changes but no coverage data.
pub const CODE_MISSING_COVERAGE_FOR_FILE: &str = "covguard.diff.missing_coverage_for_file";

/// Error code for invalid LCOV input.
pub const CODE_INVALID_LCOV: &str = "covguard.input.invalid_lcov";

/// Error code for invalid diff input.
pub const CODE_INVALID_DIFF: &str = "covguard.input.invalid_diff";

/// Error code for runtime errors.
pub const CODE_RUNTIME_ERROR: &str = "tool.runtime_error";

/// Check ID for runtime/tool errors.
pub const CHECK_ID_RUNTIME: &str = "tool.runtime_error";

// ============================================================================
// Verdict Reason Tokens (fleet vocabulary)
// ============================================================================

/// Reason: LCOV coverage data was not provided.
pub const REASON_MISSING_LCOV: &str = "missing_lcov";

/// Reason: Diff contained no changed lines in scope.
pub const REASON_NO_CHANGED_LINES: &str = "no_changed_lines";

/// Reason: All diff lines are covered.
pub const REASON_DIFF_COVERED: &str = "diff_covered";

/// Reason: Some changed lines are uncovered.
pub const REASON_UNCOVERED_LINES: &str = "uncovered_lines";

/// Reason: Diff coverage is below the configured threshold.
pub const REASON_BELOW_THRESHOLD: &str = "below_threshold";

/// Reason: A tool/runtime error occurred.
pub const REASON_TOOL_ERROR: &str = "tool_error";

/// Reason: Evaluation was skipped (e.g., missing inputs in cockpit mode).
pub const REASON_SKIPPED: &str = "skipped";

/// Reason: Findings were truncated due to max_findings limit.
pub const REASON_TRUNCATED: &str = "truncated";

/// Reason: Diff input was not provided.
pub const REASON_MISSING_DIFF: &str = "missing_diff";

// ============================================================================
// Code Registry
// ============================================================================

/// Metadata for a covguard error code.
#[derive(Debug, Clone, Copy)]
pub struct CodeInfo {
    pub code: &'static str,
    pub name: &'static str,
    pub short_description: &'static str,
    pub full_description: &'static str,
    pub remediation: &'static str,
    pub help_anchor: &'static str,
    pub help_uri: &'static str,
}

/// Registry of all covguard codes.
pub const CODE_REGISTRY: &[CodeInfo] = &[
    CodeInfo {
        code: CODE_UNCOVERED_LINE,
        name: "UncoveredLine",
        short_description: "Uncovered changed line",
        full_description: "A changed line has zero hits in coverage data.",
        remediation: r#"Add tests that execute the changed line.
If the line is intentionally uncovered, use `covguard: ignore` (line/block) or exclude the path via `covguard.toml`."#,
        help_anchor: "uncovered_line",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#uncovered_line",
    },
    CodeInfo {
        code: CODE_COVERAGE_BELOW_THRESHOLD,
        name: "CoverageBelowThreshold",
        short_description: "Diff coverage below threshold",
        full_description: "Diff-scoped coverage percentage is below the configured threshold.",
        remediation: r#"Add tests for changed lines, or adjust your configured threshold.
If coverage `SF:` paths are absolute or use a different root, use `--path-strip` (repeatable) so coverage paths match repo paths."#,
        help_anchor: "coverage_below_threshold",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#coverage_below_threshold",
    },
    CodeInfo {
        code: CODE_MISSING_COVERAGE_FOR_FILE,
        name: "MissingCoverageForFile",
        short_description: "Missing coverage for file",
        full_description: "A changed file has no coverage record.",
        remediation: r#"Ensure your coverage generation includes the file.
If coverage `SF:` paths don't match repo-relative paths, use `--path-strip`.
If the file is generated/vendor content, exclude it via `covguard.toml`."#,
        help_anchor: "missing_coverage_for_file",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#missing_coverage_for_file",
    },
    CodeInfo {
        code: CODE_INVALID_LCOV,
        name: "InvalidLcov",
        short_description: "Invalid LCOV input",
        full_description: "LCOV input could not be parsed as valid LCOV format.",
        remediation: r#"Ensure your coverage tool generated an LCOV `.info` file.
- LCOV records must include `SF:<path>` lines before any `DA:<line>,<hits>`.
- For Rust: `cargo llvm-cov --lcov --output-path coverage.info`
- For gcov/lcov: `lcov --capture --directory . --output-file coverage.info`
If the file looks truncated, re-run coverage and upload the raw LCOV as an artifact."#,
        help_anchor: "invalid_lcov",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#invalid_lcov",
    },
    CodeInfo {
        code: CODE_INVALID_DIFF,
        name: "InvalidDiff",
        short_description: "Invalid diff input",
        full_description: "Diff input could not be parsed as a unified diff.",
        remediation: r#"Provide a unified diff via one of:
- `--diff-file <path>` (or `--diff-file -` to read from stdin)
- `--base <sha>` + `--head <sha>` (requires those commits locally)
In CI, ensure the base commit exists (e.g., `actions/checkout` with `fetch-depth: 0`)."#,
        help_anchor: "invalid_diff",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#invalid_diff",
    },
    CodeInfo {
        code: CODE_RUNTIME_ERROR,
        name: "RuntimeError",
        short_description: "Tool runtime error",
        full_description: "covguard failed due to a runtime or internal error.",
        remediation: r#"Re-run with `--raw` to capture inputs under `artifacts/covguard/raw/`.
If reproducible, file a bug and attach:
- diff.patch
- coverage report
- covguard version + OS"#,
        help_anchor: "runtime_error",
        help_uri: "https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#runtime_error",
    },
];

/// Lookup code metadata by code string.
pub fn explain(code: &str) -> Option<&'static CodeInfo> {
    CODE_REGISTRY.iter().find(|info| info.code == code)
}

// ============================================================================
// Enhanced Error Trait
// ============================================================================

/// Trait for errors that provide enhanced messages with remediation hints.
///
/// This trait enables errors to include actionable guidance for users,
/// following the enhanced error message format:
/// - Error code
/// - Brief description
/// - Remediation hint
/// - Link to documentation
pub trait EnhancedError: std::fmt::Display + std::fmt::Debug {
    /// Returns the error code (e.g., "covguard.input.invalid_lcov").
    fn code(&self) -> &'static str;

    /// Returns a brief description of the error.
    fn description(&self) -> &str;

    /// Returns the remediation hint with actionable guidance.
    fn remediation(&self) -> &str;

    /// Returns the documentation URL for this error.
    fn help_uri(&self) -> &'static str;

    /// Formats the error with full enhanced output.
    fn format_enhanced(&self) -> String {
        format!(
            "Error [{}]: {}\n  {}\n\n  Hint: {}\n\n  See: {}\n",
            self.code(),
            self.description(),
            self,
            self.remediation(),
            self.help_uri()
        )
    }

    /// Formats the error with enhanced output and context.
    fn format_enhanced_with_context(&self, context: &str) -> String {
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
