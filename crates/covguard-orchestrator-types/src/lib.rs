//! Shared types for covguard orchestration.

use covguard_domain::MissingBehavior;
use covguard_output_features::OutputFeatureFlags;
use covguard_policy::FailOn;
use covguard_types::{Report, Scope};
use std::collections::BTreeMap;
use thiserror::Error;

/// Input for a coverage report.
#[derive(Debug, Clone)]
pub struct CoverageInput {
    /// Content of the coverage report.
    pub content: String,
    /// Path to the coverage report, for metadata.
    pub path: String,
    /// Format of the coverage report.
    pub format: covguard_types::CoverageFormat,
}

/// Request for a coverage check operation.
#[derive(Debug, Clone)]
pub struct CheckRequest {
    /// Patch file content (unified diff format).
    pub diff_text: String,
    /// Path to the diff file, for report metadata.
    pub diff_file_path: Option<String>,
    /// Base git ref, for report metadata (alternative to diff_file_path).
    pub base_ref: Option<String>,
    /// Head git ref, for report metadata (alternative to diff_file_path).
    pub head_ref: Option<String>,
    /// Coverage inputs (LCOV, JaCoCo, coverage.py).
    pub coverage_inputs: Vec<CoverageInput>,
    /// LCOV coverage file contents (one per input).
    /// DEPRECATED: Use coverage_inputs instead.
    pub lcov_texts: Vec<String>,
    /// Paths to LCOV files, for report metadata.
    /// DEPRECATED: Use coverage_inputs instead.
    pub lcov_paths: Vec<String>,
    /// Maximum allowed uncovered lines (optional tolerance buffer).
    pub max_uncovered_lines: Option<u32>,
    /// How to handle missing coverage lines within files.
    pub missing_coverage: MissingBehavior,
    /// How to handle files with no coverage data.
    pub missing_file: MissingBehavior,
    /// Glob patterns to include (allowlist).
    pub include_patterns: Vec<String>,
    /// Glob patterns to exclude.
    pub exclude_patterns: Vec<String>,
    /// Prefixes to strip from LCOV SF paths.
    pub path_strip: Vec<String>,
    /// Minimum diff coverage percentage threshold.
    pub threshold_pct: f64,
    /// Scope of lines to evaluate.
    pub scope: Scope,
    /// Determines when the evaluation should fail.
    pub fail_on: FailOn,
    /// Whether to honor `covguard: ignore` directives.
    pub ignore_directives: bool,
    /// Pre-computed ignored lines (path -> set of line numbers).
    /// If provided, these are used directly instead of reading from source.
    pub ignored_lines: Option<BTreeMap<String, std::collections::BTreeSet<u32>>>,
    /// Emit sensor.report.v1 schema with capabilities block.
    pub sensor_schema: bool,
    /// Renderer budgets used for markdown/annotations/SARIF output.
    pub output: OutputFeatureFlags,
    /// Maximum number of findings to include in the report (truncation).
    pub max_findings: Option<usize>,
}

impl Default for CheckRequest {
    fn default() -> Self {
        Self {
            diff_text: String::new(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            coverage_inputs: Vec::new(),
            lcov_texts: Vec::new(),
            lcov_paths: Vec::new(),
            max_uncovered_lines: None,
            missing_coverage: MissingBehavior::Warn,
            missing_file: MissingBehavior::Warn,
            include_patterns: Vec::new(),
            exclude_patterns: Vec::new(),
            path_strip: Vec::new(),
            threshold_pct: 80.0,
            scope: Scope::Added,
            fail_on: FailOn::Error,
            ignore_directives: true,
            ignored_lines: None,
            sensor_schema: false,
            output: OutputFeatureFlags::default(),
            max_findings: None,
        }
    }
}

/// Result of a coverage check operation.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// The domain report (covguard.report.v1, ALL findings, no capabilities).
    pub report: Report,
    /// Renderer budgets that were used to build outputs for this result.
    pub output: OutputFeatureFlags,
    /// The cockpit receipt (sensor.report.v1, truncated findings, capabilities).
    /// Only populated when `sensor_schema: true` (cockpit mode).
    pub cockpit_receipt: Option<Report>,
    /// Markdown rendering of the report.
    pub markdown: String,
    /// GitHub annotations rendering of the report.
    pub annotations: String,
    /// SARIF rendering of the report.
    pub sarif: String,
    /// Exit code for the CLI.
    /// - 0: pass or warn
    /// - 2: policy fail (blocking findings)
    /// - 1: tool/runtime error (not returned here, only via AppError)
    pub exit_code: i32,
}

/// Errors that can occur during the check operation.
#[derive(Debug, Error)]
pub enum AppError {
    /// Failed to parse the diff.
    #[error("Failed to parse diff: {0}")]
    DiffParse(String),

    /// Failed to parse the LCOV coverage file.
    #[error("Failed to parse LCOV: {0}")]
    LcovParse(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

impl covguard_types::EnhancedError for AppError {
    fn code(&self) -> &'static str {
        match self {
            AppError::DiffParse(_) => covguard_types::CODE_INVALID_DIFF,
            AppError::LcovParse(_) => covguard_types::CODE_INVALID_LCOV,
            AppError::Io(_) => covguard_types::CODE_RUNTIME_ERROR,
        }
    }

    fn description(&self) -> &str {
        match self {
            AppError::DiffParse(_) => "Invalid diff input",
            AppError::LcovParse(_) => "Invalid LCOV input",
            AppError::Io(_) => "Tool runtime error",
        }
    }

    fn remediation(&self) -> &str {
        covguard_types::explain(self.code())
            .map(|info| info.remediation)
            .unwrap_or("No remediation available.")
    }

    fn help_uri(&self) -> &'static str {
        covguard_types::explain(self.code())
            .map(|info| info.help_uri)
            .unwrap_or("https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md")
    }
}
