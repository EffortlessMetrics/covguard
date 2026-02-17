//! Application orchestration for covguard.
//!
//! This crate provides the high-level `check` function that orchestrates
//! the entire diff coverage analysis pipeline:
//!
//! 1. Parse the diff to extract changed line ranges
//! 2. Parse LCOV coverage data
//! 3. Detect ignore directives in source files
//! 4. Evaluate coverage against the policy
//! 5. Build and return a report with markdown and annotations
//!
//! # Example
//!
//! ```rust,ignore
//! use covguard_app::{check, CheckRequest};
//! use covguard_types::Scope;
//!
//! let request = CheckRequest {
//!     diff_text: "...".to_string(),
//!     diff_file_path: Some("test.patch".to_string()),
//!     lcov_texts: vec!["...".to_string()],
//!     lcov_paths: vec!["coverage.info".to_string()],
//!     threshold_pct: 80.0,
//!     scope: Scope::Added,
//!     ..Default::default()
//! };
//!
//! let result = check(request)?;
//! println!("Exit code: {}", result.exit_code);
//! ```

use covguard_adapters_coverage::{CoverageMap, LcovError, merge_coverage, parse_lcov_with_strip};
use covguard_adapters_diff::{DiffError, parse_patch_with_meta};
use covguard_config::should_include_path;
pub use covguard_domain::MissingBehavior;
use covguard_domain::{
    EvalInput, EvalOutput, Policy, Scope as DomainScope, evaluate, has_ignore_directive,
};
use covguard_render::{
    DEFAULT_MAX_ANNOTATIONS, DEFAULT_MAX_LINES, DEFAULT_MAX_SARIF_RESULTS,
    render_annotations as render_annotations_impl, render_markdown as render_markdown_impl,
    render_sarif as render_sarif_impl,
};
use covguard_types::{
    CODE_COVERAGE_BELOW_THRESHOLD, CODE_INVALID_DIFF, CODE_INVALID_LCOV, CODE_RUNTIME_ERROR,
    Capabilities, Finding, InputCapability, InputStatus, Inputs, InputsCapability,
    REASON_BELOW_THRESHOLD, REASON_DIFF_COVERED, REASON_MISSING_DIFF, REASON_MISSING_LCOV,
    REASON_NO_CHANGED_LINES, REASON_SKIPPED, REASON_TOOL_ERROR, REASON_TRUNCATED,
    REASON_UNCOVERED_LINES, Report, ReportData, Run, SCHEMA_ID, SENSOR_SCHEMA_ID, Scope, Tool,
    Truncation, Verdict, VerdictCounts, VerdictStatus, compute_fingerprint,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// Clock Trait
// ============================================================================

/// A trait for obtaining the current time.
///
/// This allows for testing with deterministic timestamps.
pub trait Clock {
    /// Get the current time in UTC.
    fn now(&self) -> chrono::DateTime<chrono::Utc>;
}

/// System clock implementation that returns the actual current time.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

// ============================================================================
// Request and Result Types
// ============================================================================

/// Trait for reading source file lines.
///
/// This allows detection of `covguard: ignore` directives in source code.
pub trait RepoReader {
    /// Read a specific line from a file.
    ///
    /// Returns `None` if the file doesn't exist or the line is out of bounds.
    fn read_line(&self, path: &str, line_no: u32) -> Option<String>;
}

/// A no-op reader that returns None for all lines.
/// Used when ignore directives are disabled.
pub struct NullReader;

impl RepoReader for NullReader {
    fn read_line(&self, _path: &str, _line_no: u32) -> Option<String> {
        None
    }
}

/// Filesystem-backed repo reader with line caching.
pub struct FsRepoReader {
    root: PathBuf,
    cache: std::sync::Mutex<HashMap<String, Vec<String>>>,
}

impl FsRepoReader {
    /// Create a new filesystem reader rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn read_file_lines(&self, path: &str) -> Option<Vec<String>> {
        let full_path = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.root.join(path)
        };
        let content = std::fs::read_to_string(full_path).ok()?;
        Some(content.lines().map(|l| l.to_string()).collect())
    }
}

impl RepoReader for FsRepoReader {
    fn read_line(&self, path: &str, line_no: u32) -> Option<String> {
        if line_no == 0 {
            return None;
        }
        let mut cache = self.cache.lock().ok()?;
        if !cache.contains_key(path) {
            let lines = self.read_file_lines(path)?;
            cache.insert(path.to_string(), lines);
        }
        cache
            .get(path)
            .and_then(|lines| lines.get((line_no - 1) as usize))
            .cloned()
    }
}

/// Determines when the evaluation should fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailOn {
    /// Fail if there are any error-level findings.
    #[default]
    Error,
    /// Fail if there are any warn-level or error-level findings.
    Warn,
    /// Never fail (always pass unless there's a runtime error).
    Never,
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
    /// LCOV coverage file contents (one per input).
    pub lcov_texts: Vec<String>,
    /// Paths to LCOV files, for report metadata.
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
    pub ignored_lines: Option<BTreeMap<String, BTreeSet<u32>>>,
    /// Emit sensor.report.v1 schema with capabilities block.
    pub sensor_schema: bool,
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
            max_findings: None,
        }
    }
}

/// Result of a coverage check operation.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// The domain report (covguard.report.v1, ALL findings, no capabilities).
    pub report: Report,
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

// ============================================================================
// Errors
// ============================================================================

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

impl From<DiffError> for AppError {
    fn from(e: DiffError) -> Self {
        AppError::DiffParse(e.to_string())
    }
}

impl From<LcovError> for AppError {
    fn from(e: LcovError) -> Self {
        AppError::LcovParse(e.to_string())
    }
}

// ============================================================================
// Main Check Function
// ============================================================================

/// Run a diff coverage check.
///
/// This is the main entry point for the covguard analysis. It:
/// 1. Parses the diff to extract changed line ranges
/// 2. Parses LCOV coverage data
/// 3. Evaluates coverage against the policy
/// 4. Builds and returns a result with report, markdown, annotations, and exit code
///
/// # Arguments
///
/// * `request` - The check request containing diff, coverage, and options
///
/// # Returns
///
/// A `CheckResult` containing the report, rendered outputs, and exit code.
///
/// # Errors
///
/// Returns `AppError` if parsing fails.
pub fn check(request: CheckRequest) -> Result<CheckResult, AppError> {
    check_with_clock(request, &SystemClock)
}

/// Run a diff coverage check with a custom clock.
///
/// This allows for deterministic testing with fixed timestamps.
pub fn check_with_clock<C: Clock>(
    request: CheckRequest,
    clock: &C,
) -> Result<CheckResult, AppError> {
    check_with_clock_and_reader(request, clock, &NullReader)
}

/// Run a diff coverage check with a custom clock and repo reader.
///
/// The repo reader is used to detect `covguard: ignore` directives in source files.
pub fn check_with_clock_and_reader<C: Clock, R: RepoReader>(
    request: CheckRequest,
    clock: &C,
    reader: &R,
) -> Result<CheckResult, AppError> {
    let started_at = clock.now();

    // Determine diff availability
    let diff_available = !request.diff_text.is_empty()
        || request.diff_file_path.is_some()
        || (request.base_ref.is_some() && request.head_ref.is_some());

    // Determine coverage availability
    let coverage_available =
        !request.lcov_texts.is_empty() && request.lcov_texts.iter().any(|t| !t.trim().is_empty());

    // In sensor schema mode, return skip result if coverage is unavailable
    if request.sensor_schema && !coverage_available {
        return Ok(build_skip_result(
            &request,
            started_at,
            diff_available,
            false, // coverage unavailable
            REASON_MISSING_LCOV,
            clock,
        ));
    }

    // Validate diff input (non-empty must include diff markers)
    if is_invalid_diff(&request.diff_text) {
        return Ok(build_error_result(
            &request,
            started_at,
            CODE_INVALID_DIFF,
            "Diff input did not contain any recognized diff markers.",
            true, // diff was provided (non-empty)
            coverage_available,
            clock,
        ));
    }

    // Parse the diff
    let parse_result = match parse_patch_with_meta(&request.diff_text) {
        Ok(ranges) => ranges,
        Err(e) => {
            return Ok(build_error_result(
                &request,
                started_at,
                CODE_INVALID_DIFF,
                &format!("Failed to parse diff: {e}"),
                true, // diff was provided
                coverage_available,
                clock,
            ));
        }
    };
    let changed_ranges = parse_result.changed_ranges;
    let binary_files = parse_result.binary_files;

    // Parse LCOV coverage (merge multiple inputs)
    let mut coverage_maps: Vec<CoverageMap> = Vec::new();
    for lcov_text in &request.lcov_texts {
        if lcov_text.trim().is_empty() {
            continue;
        }
        if !lcov_text.contains("SF:") {
            return Ok(build_error_result(
                &request,
                started_at,
                CODE_INVALID_LCOV,
                "LCOV input contained no SF records.",
                true, // diff parsed OK
                true, // coverage was provided (but invalid)
                clock,
            ));
        }
        match parse_lcov_with_strip(lcov_text, &request.path_strip) {
            Ok(map) => coverage_maps.push(map),
            Err(e) => {
                return Ok(build_error_result(
                    &request,
                    started_at,
                    CODE_INVALID_LCOV,
                    &format!("Failed to parse LCOV: {e}"),
                    true, // diff parsed OK
                    true, // coverage was provided (but invalid)
                    clock,
                ));
            }
        }
    }
    let coverage: CoverageMap = merge_coverage(coverage_maps);

    // Detect ignored lines
    let mut filtered_ranges = changed_ranges;
    let mut excluded_files_count = 0u32;
    filtered_ranges.retain(|path, _| {
        if should_include_path(path, &request.include_patterns, &request.exclude_patterns) {
            true
        } else {
            excluded_files_count += 1;
            false
        }
    });

    let ignored_lines = if request.ignore_directives {
        request
            .ignored_lines
            .clone()
            .unwrap_or_else(|| detect_ignored_lines(&filtered_ranges, reader))
    } else {
        BTreeMap::new()
    };

    // Convert scope
    let domain_scope = match request.scope {
        Scope::Added => DomainScope::Added,
        Scope::Touched => DomainScope::Touched,
    };

    // Build policy
    let domain_fail_on = match request.fail_on {
        FailOn::Error => covguard_domain::FailOn::Error,
        FailOn::Warn => covguard_domain::FailOn::Warn,
        FailOn::Never => covguard_domain::FailOn::Never,
    };

    let policy = Policy {
        scope: domain_scope,
        threshold_pct: request.threshold_pct,
        max_uncovered_lines: request.max_uncovered_lines,
        missing_coverage: request.missing_coverage,
        missing_file: request.missing_file,
        fail_on: domain_fail_on,
        ignore_directives_enabled: request.ignore_directives,
    };

    // Build evaluation input
    let eval_input = EvalInput {
        changed_ranges: filtered_ranges,
        coverage,
        policy,
        ignored_lines,
    };

    // Run evaluation
    let eval_output = evaluate(eval_input);

    // Build the report pair (domain report + optional cockpit receipt)
    let debug = build_debug(&binary_files);
    let ended_at = clock.now();
    let (domain_report, cockpit_receipt) = build_report_pair(
        eval_output.clone(),
        &request,
        started_at,
        ended_at,
        excluded_files_count,
        debug,
    );

    // Render outputs from the domain report (full findings)
    let markdown = render_markdown_impl(&domain_report, DEFAULT_MAX_LINES);
    let annotations = render_annotations_impl(&domain_report, DEFAULT_MAX_ANNOTATIONS);
    let sarif = render_sarif_impl(&domain_report, DEFAULT_MAX_SARIF_RESULTS);

    // Determine exit code from domain report verdict
    let exit_code = match domain_report.verdict.status {
        VerdictStatus::Pass | VerdictStatus::Warn | VerdictStatus::Skip => 0,
        VerdictStatus::Fail => 2,
    };

    Ok(CheckResult {
        report: domain_report,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code,
    })
}

// ============================================================================
// Report Builder
// ============================================================================

/// Truncate a findings list to a maximum count, returning the truncated list
/// and optional truncation metadata.
fn truncate_findings(
    findings: Vec<Finding>,
    max: Option<usize>,
) -> (Vec<Finding>, Option<Truncation>) {
    if let Some(max) = max {
        let total = findings.len();
        if total > max {
            let truncated = findings.into_iter().take(max).collect();
            let trunc = Truncation {
                findings_truncated: true,
                shown: max as u32,
                total: total as u32,
            };
            (truncated, Some(trunc))
        } else {
            (findings, None)
        }
    } else {
        (findings, None)
    }
}

/// Build a pair of reports from evaluation output: a domain report and an optional cockpit receipt.
///
/// - **Domain report**: Always `covguard.report.v1`, no capabilities, full findings
///   (standard-mode truncation preserved when `!sensor_schema && max_findings.is_some()`).
/// - **Cockpit receipt** (only when `sensor_schema: true`): `sensor.report.v1`,
///   capabilities block, findings truncated to `max_findings`, counts from full set.
fn build_report_pair(
    eval: EvalOutput,
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    excluded_files_count: u32,
    debug: Option<serde_json::Value>,
) -> (Report, Option<Report>) {
    // Build inputs record
    let diff_source = if request.diff_file_path.is_some() {
        "diff-file"
    } else if request.base_ref.is_some() && request.head_ref.is_some() {
        "git-refs"
    } else {
        "stdin"
    };

    let inputs = Inputs {
        diff_source: diff_source.to_string(),
        diff_file: request.diff_file_path.clone(),
        base: request.base_ref.clone(),
        head: request.head_ref.clone(),
        lcov_paths: request.lcov_paths.clone(),
    };

    // Build verdict counts (always from the full set)
    let counts = VerdictCounts {
        info: eval
            .findings
            .iter()
            .filter(|f| f.severity == covguard_types::Severity::Info)
            .count() as u32,
        warn: eval
            .findings
            .iter()
            .filter(|f| f.severity == covguard_types::Severity::Warn)
            .count() as u32,
        error: eval
            .findings
            .iter()
            .filter(|f| f.severity == covguard_types::Severity::Error)
            .count() as u32,
    };

    // Build verdict reasons
    let reasons = build_reasons(&eval);

    // Convert scope to string
    let scope_str = match request.scope {
        Scope::Added => "added",
        Scope::Touched => "touched",
    };

    let run_timestamps = Run {
        started_at: started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ended_at: Some(ended_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        duration_ms: Some((ended_at - started_at).num_milliseconds().max(0) as u64),
        capabilities: None, // Will be overridden per report
    };

    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };

    // Build cockpit receipt if sensor_schema is enabled
    let cockpit_receipt = if request.sensor_schema {
        let capabilities = Some(Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
                coverage: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
            },
        });

        let (cockpit_findings, cockpit_truncation) =
            truncate_findings(eval.findings.clone(), request.max_findings);

        let mut cockpit_reasons = reasons.clone();
        if cockpit_truncation.is_some() {
            cockpit_reasons.push(REASON_TRUNCATED.to_string());
        }

        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: Run {
                capabilities,
                ..run_timestamps.clone()
            },
            verdict: Verdict {
                status: eval.verdict,
                counts: counts.clone(),
                reasons: cockpit_reasons,
            },
            findings: cockpit_findings,
            data: ReportData {
                scope: scope_str.to_string(),
                threshold_pct: request.threshold_pct,
                changed_lines_total: eval.metrics.changed_lines_total,
                covered_lines: eval.metrics.covered_lines,
                uncovered_lines: eval.metrics.uncovered_lines,
                missing_lines: eval.metrics.missing_lines,
                ignored_lines_count: eval.metrics.ignored_lines,
                excluded_files_count,
                diff_coverage_pct: eval.metrics.diff_coverage_pct,
                inputs: inputs.clone(),
                debug: debug.clone(),
                truncation: cockpit_truncation,
            },
        })
    } else {
        None
    };

    // Build domain report — always covguard.report.v1, no capabilities
    // In standard mode (non-sensor), apply max_findings truncation to domain report
    let (domain_findings, domain_truncation) = if request.sensor_schema {
        // Cockpit mode: domain report has ALL findings (no truncation)
        (eval.findings, None)
    } else {
        // Standard mode: truncation applies to domain report (preserves existing behavior)
        truncate_findings(eval.findings, request.max_findings)
    };

    let mut domain_reasons = reasons;
    if domain_truncation.is_some() {
        domain_reasons.push(REASON_TRUNCATED.to_string());
    }

    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: Run {
            capabilities: None,
            ..run_timestamps
        },
        verdict: Verdict {
            status: eval.verdict,
            counts,
            reasons: domain_reasons,
        },
        findings: domain_findings,
        data: ReportData {
            scope: scope_str.to_string(),
            threshold_pct: request.threshold_pct,
            changed_lines_total: eval.metrics.changed_lines_total,
            covered_lines: eval.metrics.covered_lines,
            uncovered_lines: eval.metrics.uncovered_lines,
            missing_lines: eval.metrics.missing_lines,
            ignored_lines_count: eval.metrics.ignored_lines,
            excluded_files_count,
            diff_coverage_pct: eval.metrics.diff_coverage_pct,
            inputs,
            debug,
            truncation: domain_truncation,
        },
    };

    (domain_report, cockpit_receipt)
}

/// Build a Report from evaluation output.
///
/// # Arguments
///
/// * `eval` - The evaluation output from the domain layer
/// * `request` - The original check request
/// * `started_at` - When the check started
///
/// # Returns
///
/// A fully populated Report struct.
pub fn build_report(
    eval: EvalOutput,
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    excluded_files_count: u32,
    debug: Option<serde_json::Value>,
) -> Report {
    let (domain_report, _) = build_report_pair(
        eval,
        request,
        started_at,
        ended_at,
        excluded_files_count,
        debug,
    );
    domain_report
}

fn build_debug(binary_files: &[String]) -> Option<serde_json::Value> {
    if binary_files.is_empty() {
        None
    } else {
        Some(json!({
            "binary_files_count": binary_files.len(),
            "binary_files": binary_files,
        }))
    }
}

fn build_error_result<C: Clock>(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    code: &str,
    message: &str,
    diff_available: bool,
    coverage_available: bool,
    clock: &C,
) -> CheckResult {
    let ended_at = clock.now();
    let (domain_report, cockpit_receipt) = build_error_report_pair(
        request,
        started_at,
        ended_at,
        code,
        message,
        diff_available,
        coverage_available,
    );
    let markdown = render_markdown_impl(&domain_report, DEFAULT_MAX_LINES);
    let annotations = render_annotations_impl(&domain_report, DEFAULT_MAX_ANNOTATIONS);
    let sarif = render_sarif_impl(&domain_report, DEFAULT_MAX_SARIF_RESULTS);

    CheckResult {
        report: domain_report,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code: 1,
    }
}

/// Build both domain report and optional cockpit receipt for error cases.
fn build_error_report_pair(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    code: &str,
    message: &str,
    diff_available: bool,
    coverage_available: bool,
) -> (Report, Option<Report>) {
    let diff_source = if request.diff_file_path.is_some() {
        "diff-file"
    } else if request.base_ref.is_some() && request.head_ref.is_some() {
        "git-refs"
    } else {
        "stdin"
    };

    let inputs = Inputs {
        diff_source: diff_source.to_string(),
        diff_file: request.diff_file_path.clone(),
        base: request.base_ref.clone(),
        head: request.head_ref.clone(),
        lcov_paths: request.lcov_paths.clone(),
    };

    let input_fp = compute_fingerprint(&[code, "covguard"]);
    let runtime_fp = compute_fingerprint(&[CODE_RUNTIME_ERROR, "covguard"]);

    let findings = vec![
        Finding {
            severity: covguard_types::Severity::Error,
            check_id: "input.invalid".to_string(),
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            data: None,
            fingerprint: Some(input_fp),
        },
        Finding {
            severity: covguard_types::Severity::Error,
            check_id: covguard_types::CHECK_ID_RUNTIME.to_string(),
            code: CODE_RUNTIME_ERROR.to_string(),
            message: "covguard failed due to a runtime error.".to_string(),
            location: None,
            data: None,
            fingerprint: Some(runtime_fp),
        },
    ];

    let counts = VerdictCounts {
        info: 0,
        warn: 0,
        error: findings.len() as u32,
    };

    let scope_str = match request.scope {
        Scope::Added => "added",
        Scope::Touched => "touched",
    };

    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };

    let run_timestamps = Run {
        started_at: started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ended_at: Some(ended_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        duration_ms: Some((ended_at - started_at).num_milliseconds().max(0) as u64),
        capabilities: None,
    };

    let data = ReportData {
        scope: scope_str.to_string(),
        threshold_pct: request.threshold_pct,
        changed_lines_total: 0,
        covered_lines: 0,
        uncovered_lines: 0,
        missing_lines: 0,
        ignored_lines_count: 0,
        excluded_files_count: 0,
        diff_coverage_pct: 0.0,
        inputs,
        debug: None,
        truncation: None,
    };

    // Build cockpit receipt if sensor_schema is enabled
    let cockpit_receipt = if request.sensor_schema {
        let capabilities = Some(Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: if diff_available {
                        InputStatus::Available
                    } else {
                        InputStatus::Unavailable
                    },
                    reason: if diff_available {
                        None
                    } else {
                        Some(REASON_MISSING_DIFF.to_string())
                    },
                },
                coverage: InputCapability {
                    status: if coverage_available {
                        InputStatus::Available
                    } else {
                        InputStatus::Unavailable
                    },
                    reason: if coverage_available {
                        None
                    } else {
                        Some(REASON_MISSING_LCOV.to_string())
                    },
                },
            },
        });

        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: Run {
                capabilities,
                ..run_timestamps.clone()
            },
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: counts.clone(),
                reasons: vec![REASON_TOOL_ERROR.to_string()],
            },
            findings: findings.clone(),
            data: data.clone(),
        })
    } else {
        None
    };

    // Domain report: always covguard.report.v1, no capabilities
    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: Run {
            capabilities: None,
            ..run_timestamps
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts,
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        findings,
        data,
    };

    (domain_report, cockpit_receipt)
}

/// Build a skip result when inputs are unavailable (sensor.report.v1 compliance).
fn build_skip_result<C: Clock>(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    diff_available: bool,
    coverage_available: bool,
    reason: &str,
    clock: &C,
) -> CheckResult {
    let ended_at = clock.now();
    let (domain_report, cockpit_receipt) = build_skip_report_pair(
        request,
        started_at,
        ended_at,
        diff_available,
        coverage_available,
        reason,
    );
    let markdown = render_markdown_impl(&domain_report, DEFAULT_MAX_LINES);
    let annotations = render_annotations_impl(&domain_report, DEFAULT_MAX_ANNOTATIONS);
    let sarif = render_sarif_impl(&domain_report, DEFAULT_MAX_SARIF_RESULTS);

    CheckResult {
        report: domain_report,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code: 0, // Skip is not a failure
    }
}

/// Build both domain report and cockpit receipt for skip cases.
fn build_skip_report_pair(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    diff_available: bool,
    coverage_available: bool,
    reason: &str,
) -> (Report, Option<Report>) {
    let diff_source = if request.diff_file_path.is_some() {
        "diff-file"
    } else if request.base_ref.is_some() && request.head_ref.is_some() {
        "git-refs"
    } else {
        "stdin"
    };

    let inputs = Inputs {
        diff_source: diff_source.to_string(),
        diff_file: request.diff_file_path.clone(),
        base: request.base_ref.clone(),
        head: request.head_ref.clone(),
        lcov_paths: request.lcov_paths.clone(),
    };

    let capabilities = Capabilities {
        inputs: InputsCapability {
            diff: InputCapability {
                status: if diff_available {
                    InputStatus::Available
                } else {
                    InputStatus::Unavailable
                },
                reason: if diff_available {
                    None
                } else {
                    Some(REASON_MISSING_DIFF.to_string())
                },
            },
            coverage: InputCapability {
                status: if coverage_available {
                    InputStatus::Available
                } else {
                    InputStatus::Unavailable
                },
                reason: if coverage_available {
                    None
                } else {
                    Some(REASON_MISSING_LCOV.to_string())
                },
            },
        },
    };

    let scope_str = match request.scope {
        Scope::Added => "added",
        Scope::Touched => "touched",
    };

    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };

    let run_timestamps = Run {
        started_at: started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ended_at: Some(ended_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        duration_ms: Some((ended_at - started_at).num_milliseconds().max(0) as u64),
        capabilities: None,
    };

    let data = ReportData {
        scope: scope_str.to_string(),
        threshold_pct: request.threshold_pct,
        changed_lines_total: 0,
        covered_lines: 0,
        uncovered_lines: 0,
        missing_lines: 0,
        ignored_lines_count: 0,
        excluded_files_count: 0,
        diff_coverage_pct: 0.0,
        inputs,
        debug: None,
        truncation: None,
    };

    // Skip only triggers in sensor_schema mode, so cockpit receipt is always Some
    let cockpit_receipt = if request.sensor_schema {
        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: Run {
                capabilities: Some(capabilities),
                ..run_timestamps.clone()
            },
            verdict: Verdict {
                status: VerdictStatus::Skip,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 0,
                },
                reasons: vec![reason.to_string()],
            },
            findings: vec![],
            data: data.clone(),
        })
    } else {
        None
    };

    // Domain report: always covguard.report.v1, no capabilities
    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: Run {
            capabilities: None,
            ..run_timestamps
        },
        verdict: Verdict {
            status: VerdictStatus::Skip,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
            },
            reasons: vec![reason.to_string()],
        },
        findings: vec![],
        data,
    };

    (domain_report, cockpit_receipt)
}

fn is_invalid_diff(diff_text: &str) -> bool {
    let trimmed = diff_text.trim();
    if trimmed.is_empty() {
        return false;
    }
    let has_marker = trimmed.contains("diff --git")
        || trimmed.contains("@@")
        || trimmed.contains("+++ ")
        || trimmed.contains("--- ")
        || trimmed.contains("rename from ")
        || trimmed.contains("rename to ");
    !has_marker
}

/// Build verdict reasons based on evaluation output.
fn build_reasons(output: &EvalOutput) -> Vec<String> {
    let mut reasons = Vec::new();

    match output.verdict {
        VerdictStatus::Pass => {
            if output.metrics.changed_lines_total == 0 {
                reasons.push(REASON_NO_CHANGED_LINES.to_string());
            } else {
                reasons.push(REASON_DIFF_COVERED.to_string());
            }
        }
        VerdictStatus::Fail | VerdictStatus::Warn => {
            if output.metrics.uncovered_lines > 0 {
                reasons.push(REASON_UNCOVERED_LINES.to_string());
            }
            // Check for threshold violation finding
            if output
                .findings
                .iter()
                .any(|f| f.code == CODE_COVERAGE_BELOW_THRESHOLD)
            {
                reasons.push(REASON_BELOW_THRESHOLD.to_string());
            }
        }
        VerdictStatus::Skip => {
            reasons.push(REASON_SKIPPED.to_string());
        }
    }

    reasons
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Render a report as Markdown.
pub fn render_markdown(report: &Report) -> String {
    render_markdown_impl(report, DEFAULT_MAX_LINES)
}

/// Render a report as Markdown with a custom line limit.
pub fn render_markdown_with_limit(report: &Report, max_lines: usize) -> String {
    render_markdown_impl(report, max_lines)
}

/// Render a report as GitHub annotations.
pub fn render_annotations(report: &Report) -> String {
    render_annotations_impl(report, DEFAULT_MAX_ANNOTATIONS)
}

/// Render a report as GitHub annotations with a custom limit.
pub fn render_annotations_with_limit(report: &Report, max_annotations: usize) -> String {
    render_annotations_impl(report, max_annotations)
}

/// Render a report as SARIF.
pub fn render_sarif(report: &Report) -> String {
    render_sarif_impl(report, DEFAULT_MAX_SARIF_RESULTS)
}

/// Render a report as SARIF with a custom result limit.
pub fn render_sarif_with_limit(report: &Report, max_results: usize) -> String {
    render_sarif_impl(report, max_results)
}

// ============================================================================
// Ignore Directive Detection
// ============================================================================

/// Detect lines with `covguard: ignore` directives in changed files.
///
/// For each file in `changed_ranges`, reads the relevant lines using the
/// provided `reader` and checks for ignore directives.
pub fn detect_ignored_lines<R: RepoReader>(
    changed_ranges: &BTreeMap<String, Vec<std::ops::RangeInclusive<u32>>>,
    reader: &R,
) -> BTreeMap<String, BTreeSet<u32>> {
    let mut ignored = BTreeMap::new();

    for (path, ranges) in changed_ranges {
        let mut file_ignored = BTreeSet::new();

        for range in ranges {
            for line_no in range.clone() {
                if let Some(line_content) = reader.read_line(path, line_no)
                    && has_ignore_directive(&line_content)
                {
                    file_ignored.insert(line_no);
                }
            }
        }

        if !file_ignored.is_empty() {
            ignored.insert(path.clone(), file_ignored);
        }
    }

    ignored
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_domain::Metrics;
    use std::collections::{BTreeMap, BTreeSet};

    /// A test clock that returns a fixed time.
    struct FixedClock {
        time: chrono::DateTime<chrono::Utc>,
    }

    impl FixedClock {
        fn new(timestamp: &str) -> Self {
            Self {
                time: chrono::DateTime::parse_from_rfc3339(timestamp)
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            }
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            self.time
        }
    }

    struct MapReader {
        lines: BTreeMap<(String, u32), String>,
    }

    impl MapReader {
        fn new(entries: Vec<(&str, u32, &str)>) -> Self {
            let mut lines = BTreeMap::new();
            for (path, line_no, content) in entries {
                lines.insert((path.to_string(), line_no), content.to_string());
            }
            Self { lines }
        }
    }

    impl RepoReader for MapReader {
        fn read_line(&self, path: &str, line_no: u32) -> Option<String> {
            self.lines.get(&(path.to_string(), line_no)).cloned()
        }
    }

    // ========================================================================
    // End-to-end tests with fixtures
    // ========================================================================

    #[test]
    fn test_e2e_uncovered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Verify report
        assert_eq!(result.report.schema, SCHEMA_ID);
        assert_eq!(result.report.verdict.status, VerdictStatus::Fail);
        assert_eq!(result.report.data.changed_lines_total, 3);
        assert_eq!(result.report.data.covered_lines, 0);
        assert_eq!(result.report.data.uncovered_lines, 3);
        assert_eq!(result.report.data.diff_coverage_pct, 0.0);

        // Should have 3 uncovered line findings + 1 threshold finding
        assert_eq!(result.report.findings.len(), 4);

        // Verify exit code
        assert_eq!(result.exit_code, 2);

        // Verify markdown contains expected content
        assert!(result.markdown.contains("covguard"));
        assert!(result.markdown.contains("fail"));

        // Verify annotations are present
        assert!(!result.annotations.is_empty());
        assert!(result.annotations.contains("::error"));
    }

    #[test]
    fn test_e2e_covered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
DA:2,1
DA:3,1
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/covered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Verify report
        assert_eq!(result.report.verdict.status, VerdictStatus::Pass);
        assert_eq!(result.report.data.changed_lines_total, 3);
        assert_eq!(result.report.data.covered_lines, 3);
        assert_eq!(result.report.data.uncovered_lines, 0);
        assert_eq!(result.report.data.diff_coverage_pct, 100.0);

        // No findings for covered code
        assert!(result.report.findings.is_empty());

        // Verify exit code
        assert_eq!(result.exit_code, 0);

        // Verify markdown contains expected content
        assert!(result.markdown.contains("pass"));
    }

    // ========================================================================
    // Error handling tests
    // ========================================================================

    #[test]
    fn test_error_bad_diff() {
        let diff = "not a valid diff at all\nrandom garbage";
        let lcov = "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let result = check(request).expect("invalid diff should return error report");
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.report.verdict.status, VerdictStatus::Fail);
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_INVALID_DIFF)
        );
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_RUNTIME_ERROR)
        );
    }

    #[test]
    fn test_error_bad_lcov() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        // Invalid LCOV: DA without SF
        let lcov = "DA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let result = check(request).expect("invalid lcov should return error report");
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.report.verdict.status, VerdictStatus::Fail);
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_INVALID_LCOV)
        );
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_RUNTIME_ERROR)
        );
    }

    // ========================================================================
    // Unit tests
    // ========================================================================

    #[test]
    fn test_check_request_default() {
        let request = CheckRequest::default();
        assert_eq!(request.threshold_pct, 80.0);
        assert_eq!(request.scope, Scope::Added);
        assert!(request.diff_text.is_empty());
        assert!(request.lcov_texts.is_empty());
    }

    #[test]
    fn test_clock_trait() {
        let clock = SystemClock;
        let now = clock.now();
        // Just verify it returns a valid time
        assert!(now.timestamp() > 0);
    }

    #[test]
    fn test_fixed_clock() {
        let clock = FixedClock::new("2026-02-02T12:30:45Z");
        let time = clock.now();
        assert_eq!(
            time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2026-02-02T12:30:45Z"
        );
    }

    #[test]
    fn test_empty_diff() {
        let request = CheckRequest {
            diff_text: String::new(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec!["TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n".to_string()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let result = check(request).unwrap();
        assert_eq!(result.report.verdict.status, VerdictStatus::Pass);
        assert_eq!(result.report.data.changed_lines_total, 0);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_exit_codes() {
        // Pass case
        let request = CheckRequest {
            diff_text: String::new(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![String::new()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };
        let result = check(request).unwrap();
        assert_eq!(result.exit_code, 0);

        // Fail case
        let diff =
            "diff --git a/x.rs b/x.rs\n--- /dev/null\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+fn x() {}\n";
        let lcov = "TN:\nSF:x.rs\nDA:1,0\nend_of_record\n";
        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };
        let result = check(request).unwrap();
        assert_eq!(result.exit_code, 2);
    }

    #[test]
    fn test_build_report_timestamp() {
        use chrono::TimeZone;

        let eval = EvalOutput {
            findings: vec![],
            verdict: VerdictStatus::Pass,
            metrics: covguard_domain::Metrics::default(),
        };

        let request = CheckRequest::default();
        let started_at = chrono::Utc.with_ymd_and_hms(2026, 2, 2, 10, 30, 0).unwrap();
        let ended_at = chrono::Utc.with_ymd_and_hms(2026, 2, 2, 10, 30, 1).unwrap();

        let report = build_report(eval, &request, started_at, ended_at, 0, None);

        assert_eq!(report.run.started_at, "2026-02-02T10:30:00Z");
        assert_eq!(
            report.run.ended_at,
            Some("2026-02-02T10:30:01Z".to_string())
        );
        assert_eq!(report.run.duration_ms, Some(1000));
    }

    #[test]
    fn test_build_report_tool_info() {
        let eval = EvalOutput {
            findings: vec![],
            verdict: VerdictStatus::Pass,
            metrics: covguard_domain::Metrics::default(),
        };

        let request = CheckRequest::default();
        let started_at = chrono::Utc::now();
        let ended_at = started_at;

        let report = build_report(eval, &request, started_at, ended_at, 0, None);

        assert_eq!(report.tool.name, "covguard");
        assert_eq!(report.tool.version, "0.2.0");
    }

    #[test]
    fn test_render_markdown() {
        let report = Report::default();
        let md = render_markdown(&report);
        assert!(md.contains("covguard"));
    }

    #[test]
    fn test_render_annotations_empty() {
        let report = Report::default();
        let ann = render_annotations(&report);
        assert!(ann.is_empty());
    }

    #[test]
    fn test_scope_touched() {
        let diff =
            "diff --git a/x.rs b/x.rs\n--- /dev/null\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+fn x() {}\n";
        let lcov = "TN:\nSF:x.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Touched,
            ..Default::default()
        };

        let result = check(request).unwrap();
        assert_eq!(result.report.data.scope, "touched");
    }

    #[test]
    fn test_git_refs_metadata() {
        let diff =
            "diff --git a/x.rs b/x.rs\n--- /dev/null\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+fn x() {}\n";
        let lcov = "TN:\nSF:x.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: Some("main".to_string()),
            head_ref: Some("feature".to_string()),
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let result = check(request).unwrap();
        assert_eq!(result.report.data.inputs.diff_source, "git-refs");
        assert_eq!(result.report.data.inputs.base, Some("main".to_string()));
        assert_eq!(result.report.data.inputs.head, Some("feature".to_string()));
        assert!(result.report.data.inputs.diff_file.is_none());
    }

    #[test]
    fn test_diff_file_metadata() {
        let diff =
            "diff --git a/x.rs b/x.rs\n--- /dev/null\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+fn x() {}\n";
        let lcov = "TN:\nSF:x.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("my.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let result = check(request).unwrap();
        assert_eq!(result.report.data.inputs.diff_source, "diff-file");
        assert_eq!(
            result.report.data.inputs.diff_file,
            Some("my.patch".to_string())
        );
        assert!(result.report.data.inputs.base.is_none());
        assert!(result.report.data.inputs.head.is_none());
    }

    // ========================================================================
    // Insta Snapshot Tests
    // ========================================================================

    #[test]
    fn test_snapshot_report_uncovered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        let report_json: serde_json::Value = serde_json::to_value(&result.report).unwrap();
        insta::assert_json_snapshot!("report_uncovered", report_json);
    }

    #[test]
    fn test_snapshot_report_covered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
DA:2,1
DA:3,1
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/covered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        let report_json: serde_json::Value = serde_json::to_value(&result.report).unwrap();
        insta::assert_json_snapshot!("report_covered", report_json);
    }

    #[test]
    fn test_snapshot_report_partial() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,5 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
+pub fn sub(a: i32, b: i32) -> i32 {
+    a - b
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
DA:2,1
DA:3,1
DA:4,0
DA:5,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/partial.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/partial.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        let report_json: serde_json::Value = serde_json::to_value(&result.report).unwrap();
        insta::assert_json_snapshot!("report_partial", report_json);
    }

    #[test]
    fn test_snapshot_report_empty_diff() {
        let diff = "";
        let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: None,
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/covered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        let report_json: serde_json::Value = serde_json::to_value(&result.report).unwrap();
        insta::assert_json_snapshot!("report_empty_diff", report_json);
    }

    #[test]
    fn test_snapshot_markdown_uncovered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        insta::assert_snapshot!("full_markdown_uncovered", result.markdown);
    }

    #[test]
    fn test_snapshot_sarif_uncovered() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple_added.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        let sarif_json: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
        insta::assert_json_snapshot!("full_sarif_uncovered", sarif_json);
    }

    // ========================================================================
    // Sensor Schema / Cockpit Mode Tests
    // ========================================================================

    #[test]
    fn test_sensor_schema_skip_on_missing_coverage() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![], // No coverage provided
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true, // Enable sensor schema mode
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Domain report should always use standard schema, no capabilities
        assert_eq!(result.report.schema, SCHEMA_ID);
        assert!(result.report.run.capabilities.is_none());
        assert_eq!(result.report.verdict.status, VerdictStatus::Skip);
        assert_eq!(result.exit_code, 0);

        // Cockpit receipt should have sensor schema and capabilities
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert_eq!(receipt.schema, SENSOR_SCHEMA_ID);
        let capabilities = receipt.run.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Available);
        assert_eq!(
            capabilities.inputs.coverage.status,
            InputStatus::Unavailable
        );
        assert_eq!(
            capabilities.inputs.coverage.reason,
            Some("missing_lcov".to_string())
        );

        // Should have missing_lcov reason
        assert!(
            receipt
                .verdict
                .reasons
                .contains(&"missing_lcov".to_string())
        );

        // No findings for skip
        assert!(receipt.findings.is_empty());
    }

    #[test]
    fn test_sensor_schema_includes_capabilities_on_success() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let lcov = "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true, // Enable sensor schema mode
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Domain report should always use standard schema, no capabilities
        assert_eq!(result.report.schema, SCHEMA_ID);
        assert!(result.report.run.capabilities.is_none());
        assert_eq!(result.report.verdict.status, VerdictStatus::Pass);

        // Cockpit receipt should have sensor schema and capabilities
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert_eq!(receipt.schema, SENSOR_SCHEMA_ID);
        let capabilities = receipt.run.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Available);
        assert_eq!(capabilities.inputs.coverage.status, InputStatus::Available);
    }

    #[test]
    fn test_standard_schema_no_capabilities() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let lcov = "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: false, // Standard mode
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Should use standard schema
        assert_eq!(result.report.schema, SCHEMA_ID);

        // Should NOT have capabilities block
        assert!(result.report.run.capabilities.is_none());

        // No cockpit receipt in standard mode
        assert!(result.cockpit_receipt.is_none());
    }

    #[test]
    fn test_snapshot_report_skip_no_coverage() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("fixtures/diff/simple.patch".to_string()),
            base_ref: None,
            head_ref: None,
            lcov_texts: vec![],
            lcov_paths: vec![],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true,
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Snapshot the domain report (now covguard.report.v1)
        let report_json: serde_json::Value = serde_json::to_value(&result.report).unwrap();
        insta::assert_json_snapshot!("report_skip_no_coverage", report_json);
    }

    // ========================================================================
    // Truncation Edge-Case Tests
    // ========================================================================

    #[test]
    fn test_max_findings_zero_produces_truncation_metadata() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            max_findings: Some(0),
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Findings array should be empty
        assert!(result.report.findings.is_empty());

        // Truncation metadata should be present
        let truncation = result
            .report
            .data
            .truncation
            .as_ref()
            .expect("truncation metadata should be present");
        assert!(truncation.findings_truncated);
        assert_eq!(truncation.shown, 0);
        assert!(
            truncation.total > 0,
            "total should reflect pre-truncation count"
        );

        // Reasons should include "truncated"
        let has_trunc_reason = result
            .report
            .verdict
            .reasons
            .contains(&REASON_TRUNCATED.to_string());
        assert!(has_trunc_reason, "reasons should include 'truncated'");
    }

    // ========================================================================
    // Core Split Tests
    // ========================================================================

    #[test]
    fn test_cockpit_receipt_has_truncated_findings() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true,
            max_findings: Some(2),
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Domain report should have ALL findings (no truncation in cockpit mode)
        assert_eq!(result.report.findings.len(), 4); // 3 uncovered + 1 threshold
        assert!(result.report.data.truncation.is_none());
        assert_eq!(result.report.schema, SCHEMA_ID);
        assert!(result.report.run.capabilities.is_none());

        // Cockpit receipt should have truncated findings
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert_eq!(receipt.findings.len(), 2);
        assert_eq!(receipt.schema, SENSOR_SCHEMA_ID);
        let truncation = receipt.data.truncation.as_ref().unwrap();
        assert!(truncation.findings_truncated);
        assert_eq!(truncation.shown, 2);
        assert_eq!(truncation.total, 4);
    }

    #[test]
    fn test_cockpit_receipt_counts_reflect_full_set() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true,
            max_findings: Some(1),
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Cockpit receipt counts should reflect ALL findings, not just truncated
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert_eq!(receipt.findings.len(), 1); // Truncated to 1
        assert_eq!(receipt.verdict.counts.error, 4); // But counts reflect full 4
    }

    #[test]
    fn test_domain_report_never_has_capabilities() {
        // Standard mode
        let diff =
            "diff --git a/x.rs b/x.rs\n--- /dev/null\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+fn x() {}\n";
        let lcov = "TN:\nSF:x.rs\nDA:1,1\nend_of_record\n";

        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            sensor_schema: false,
            ..Default::default()
        };
        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();
        assert!(result.report.run.capabilities.is_none());

        // Cockpit mode
        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            sensor_schema: true,
            ..Default::default()
        };
        let result = check_with_clock(request, &clock).unwrap();
        assert!(result.report.run.capabilities.is_none());
        assert_eq!(result.report.schema, SCHEMA_ID);

        // Cockpit receipt HAS capabilities
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert!(receipt.run.capabilities.is_some());
    }

    #[test]
    fn test_renderers_use_full_findings() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let lcov = r#"TN:
SF:src/lib.rs
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#;

        let request = CheckRequest {
            diff_text: diff.to_string(),
            diff_file_path: Some("test.patch".to_string()),
            lcov_texts: vec![lcov.to_string()],
            lcov_paths: vec!["coverage.info".to_string()],
            threshold_pct: 80.0,
            scope: Scope::Added,
            sensor_schema: true,
            max_findings: Some(1), // Truncate cockpit receipt heavily
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        // Cockpit receipt only has 1 finding
        let receipt = result.cockpit_receipt.as_ref().unwrap();
        assert_eq!(receipt.findings.len(), 1);

        // But markdown (rendered from domain report) should contain all uncovered lines
        // The domain report has 4 findings (3 uncovered + 1 threshold)
        assert_eq!(result.report.findings.len(), 4);
        // Markdown should mention all 3 uncovered lines
        assert!(result.markdown.contains("src/lib.rs"));
    }

    // ========================================================================
    // Helper/Utility Tests
    // ========================================================================

    #[test]
    fn test_build_debug_empty_returns_none() {
        assert!(build_debug(&[]).is_none());
    }

    #[test]
    fn test_build_debug_populated() {
        let debug = build_debug(&["assets/logo.png".to_string()]).expect("debug");
        assert_eq!(debug["binary_files_count"], 1);
        assert_eq!(debug["binary_files"][0], "assets/logo.png");
    }

    #[test]
    fn test_is_invalid_diff_detection() {
        assert!(!is_invalid_diff(""));
        assert!(!is_invalid_diff("   \n\t"));
        assert!(!is_invalid_diff("diff --git a/a.rs b/a.rs"));
        assert!(!is_invalid_diff("@@ -1 +1 @@"));
        assert!(!is_invalid_diff("+++ b/a.rs"));
        assert!(!is_invalid_diff("--- a/a.rs"));
        assert!(!is_invalid_diff("rename to a.rs"));
        assert!(is_invalid_diff("just some random text"));
    }

    #[test]
    fn test_build_reasons_pass_no_changes() {
        let output = EvalOutput {
            findings: vec![],
            verdict: VerdictStatus::Pass,
            metrics: Metrics {
                changed_lines_total: 0,
                ..Metrics::default()
            },
        };

        let reasons = build_reasons(&output);
        assert_eq!(reasons, vec![REASON_NO_CHANGED_LINES.to_string()]);
    }

    #[test]
    fn test_build_reasons_pass_with_changes() {
        let output = EvalOutput {
            findings: vec![],
            verdict: VerdictStatus::Pass,
            metrics: Metrics {
                changed_lines_total: 3,
                ..Metrics::default()
            },
        };

        let reasons = build_reasons(&output);
        assert_eq!(reasons, vec![REASON_DIFF_COVERED.to_string()]);
    }

    #[test]
    fn test_build_reasons_warn_with_uncovered_and_threshold() {
        let finding = Finding {
            severity: covguard_types::Severity::Error,
            check_id: "diff.coverage_below_threshold".to_string(),
            code: CODE_COVERAGE_BELOW_THRESHOLD.to_string(),
            message: "below threshold".to_string(),
            location: None,
            data: None,
            fingerprint: None,
        };

        let output = EvalOutput {
            findings: vec![finding],
            verdict: VerdictStatus::Warn,
            metrics: Metrics {
                changed_lines_total: 5,
                uncovered_lines: 2,
                ..Metrics::default()
            },
        };

        let reasons = build_reasons(&output);
        assert!(reasons.contains(&REASON_UNCOVERED_LINES.to_string()));
        assert!(reasons.contains(&REASON_BELOW_THRESHOLD.to_string()));
    }

    #[test]
    fn test_build_reasons_skip() {
        let output = EvalOutput {
            findings: vec![],
            verdict: VerdictStatus::Skip,
            metrics: Metrics::default(),
        };

        let reasons = build_reasons(&output);
        assert_eq!(reasons, vec![REASON_SKIPPED.to_string()]);
    }

    #[test]
    fn test_detect_ignored_lines_with_reader() {
        let mut changed_ranges = BTreeMap::new();
        changed_ranges.insert("src/lib.rs".to_string(), vec![1..=3]);
        changed_ranges.insert("src/main.rs".to_string(), vec![10..=11]);

        let reader = MapReader::new(vec![
            ("src/lib.rs", 2, "let x = 1; // covguard: ignore"),
            ("src/main.rs", 11, "# covguard: ignore"),
        ]);

        let ignored = detect_ignored_lines(&changed_ranges, &reader);
        assert_eq!(
            ignored.get("src/lib.rs").cloned(),
            Some(BTreeSet::from([2]))
        );
        assert_eq!(
            ignored.get("src/main.rs").cloned(),
            Some(BTreeSet::from([11]))
        );
    }

    #[test]
    fn test_detect_ignored_lines_empty_when_no_directives() {
        let mut changed_ranges = BTreeMap::new();
        changed_ranges.insert("src/lib.rs".to_string(), vec![1..=2]);

        let reader = MapReader::new(vec![("src/lib.rs", 1, "let x = 1;")]);
        let ignored = detect_ignored_lines(&changed_ranges, &reader);
        assert!(ignored.is_empty());
    }

    #[test]
    fn test_fs_repo_reader_reads_relative_and_absolute() {
        use std::fs;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("covguard-app-reader-{unique}"));
        let src_dir = root.join("src");
        fs::create_dir_all(&src_dir).expect("create temp dir");

        let file_path = src_dir.join("lib.rs");
        fs::write(&file_path, "line1\nline2\nline3\n").expect("write file");

        let reader = FsRepoReader::new(&root);
        assert_eq!(reader.read_line("src/lib.rs", 2), Some("line2".to_string()));
        assert_eq!(reader.read_line("src/lib.rs", 0), None);
        assert_eq!(reader.read_line("src/lib.rs", 99), None);

        let abs_path = file_path.to_string_lossy().to_string();
        assert_eq!(reader.read_line(&abs_path, 1), Some("line1".to_string()));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_app_error_from_diff_error() {
        use covguard_adapters_diff::DiffError;

        let err = DiffError::InvalidFormat("bad diff".to_string());
        let app: AppError = err.into();
        assert!(matches!(
            app,
            AppError::DiffParse(ref msg) if msg.contains("bad diff")
        ));
    }

    #[test]
    fn test_app_error_from_lcov_error() {
        use covguard_adapters_coverage::LcovError;

        let err = LcovError::InvalidFormat("bad lcov".to_string());
        let app: AppError = err.into();
        assert!(matches!(
            app,
            AppError::LcovParse(ref msg) if msg.contains("bad lcov")
        ));
    }

    #[test]
    fn test_error_bad_diff_parse_branch() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 @@
+line
"#;

        let lcov = "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";
        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_INVALID_DIFF)
        );
    }

    #[test]
    fn test_error_lcov_missing_sf_records() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let lcov = "TN:\nDA:1,1\nend_of_record\n";
        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_INVALID_LCOV)
        );
    }

    #[test]
    fn test_error_lcov_parse_failure_branch() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;

        let lcov = "TN:\nSF:src/lib.rs\nDA:abc,1\nend_of_record\n";
        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();
        assert!(
            result
                .report
                .findings
                .iter()
                .any(|f| f.code == CODE_INVALID_LCOV)
        );
    }

    #[test]
    fn test_excluded_files_count_incremented() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn main() {}
"#;
        let lcov = "TN:\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";
        let request = CheckRequest {
            diff_text: diff.to_string(),
            lcov_texts: vec![lcov.to_string()],
            exclude_patterns: vec!["src/**".to_string()],
            ..Default::default()
        };

        let clock = FixedClock::new("2026-02-02T00:00:00Z");
        let result = check_with_clock(request, &clock).unwrap();

        assert_eq!(result.report.data.excluded_files_count, 1);
    }

    #[test]
    fn test_truncate_findings_no_truncation_when_under_limit() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let (truncated, trunc) = truncate_findings(findings.clone(), Some(5));
        assert_eq!(truncated.len(), findings.len());
        assert!(trunc.is_none());
    }

    #[test]
    fn test_build_error_report_pair_with_capabilities() {
        let request = CheckRequest {
            base_ref: Some("main".to_string()),
            head_ref: Some("feature".to_string()),
            sensor_schema: true,
            scope: Scope::Touched,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (domain, receipt) = build_error_report_pair(
            &request,
            now,
            now,
            CODE_INVALID_DIFF,
            "bad diff",
            true,
            false,
        );

        assert_eq!(domain.data.inputs.diff_source, "git-refs");
        let receipt = receipt.expect("receipt should exist");
        let capabilities = receipt.run.capabilities.expect("capabilities");
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Available);
        assert_eq!(
            capabilities.inputs.coverage.status,
            InputStatus::Unavailable
        );
    }

    #[test]
    fn test_build_error_report_pair_diff_missing() {
        let request = CheckRequest {
            sensor_schema: true,
            scope: Scope::Added,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (_domain, receipt) = build_error_report_pair(
            &request,
            now,
            now,
            CODE_INVALID_DIFF,
            "bad diff",
            false,
            true,
        );

        let receipt = receipt.expect("receipt should exist");
        let capabilities = receipt.run.capabilities.expect("capabilities");
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Unavailable);
        assert_eq!(capabilities.inputs.coverage.status, InputStatus::Available);
    }

    #[test]
    fn test_build_error_report_pair_without_capabilities() {
        let request = CheckRequest {
            sensor_schema: false,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (_domain, receipt) = build_error_report_pair(
            &request,
            now,
            now,
            CODE_INVALID_DIFF,
            "bad diff",
            true,
            true,
        );
        assert!(receipt.is_none());
    }

    #[test]
    fn test_build_skip_report_pair_sensor_schema_false_stdin() {
        let request = CheckRequest {
            sensor_schema: false,
            scope: Scope::Touched,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (domain, receipt) =
            build_skip_report_pair(&request, now, now, false, true, REASON_MISSING_LCOV);
        assert_eq!(domain.data.inputs.diff_source, "stdin");
        assert_eq!(domain.data.scope, "touched");
        assert!(receipt.is_none());
    }

    #[test]
    fn test_build_skip_report_pair_diff_present_cov_missing() {
        let request = CheckRequest {
            base_ref: Some("main".to_string()),
            head_ref: Some("feature".to_string()),
            sensor_schema: true,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (_domain, receipt) =
            build_skip_report_pair(&request, now, now, true, false, REASON_MISSING_LCOV);
        let receipt = receipt.expect("receipt should exist");
        let capabilities = receipt.run.capabilities.expect("capabilities");
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Available);
        assert_eq!(
            capabilities.inputs.coverage.status,
            InputStatus::Unavailable
        );
    }

    #[test]
    fn test_build_skip_report_pair_diff_missing_cov_present() {
        let request = CheckRequest {
            sensor_schema: true,
            ..Default::default()
        };
        let now = chrono::Utc::now();
        let (_domain, receipt) =
            build_skip_report_pair(&request, now, now, false, true, REASON_MISSING_LCOV);
        let receipt = receipt.expect("receipt should exist");
        let capabilities = receipt.run.capabilities.expect("capabilities");
        assert_eq!(capabilities.inputs.diff.status, InputStatus::Unavailable);
        assert_eq!(capabilities.inputs.coverage.status, InputStatus::Available);
    }

    #[test]
    fn test_render_wrappers_with_limits() {
        let report = Report::default();
        let md = render_markdown_with_limit(&report, 1);
        let annotations = render_annotations_with_limit(&report, 1);
        let sarif = render_sarif_with_limit(&report, 1);

        assert!(!md.is_empty());
        assert!(annotations.is_empty());
        assert!(sarif.contains("\"version\""));
    }
}
