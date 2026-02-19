//! Core types and DTOs for covguard.
//!
//! This crate defines the data transfer objects used throughout covguard,
//! including the report schema, findings, verdicts, and error codes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// Schema and Code Constants
// ============================================================================

/// Schema identifier for the covguard report format.
pub const SCHEMA_ID: &str = "covguard.report.v1";

/// Schema identifier for the sensor.report.v1 format (Cockpit ecosystem).
pub const SENSOR_SCHEMA_ID: &str = "sensor.report.v1";

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
// Fingerprint
// ============================================================================

/// Compute a SHA-256 fingerprint from pipe-delimited parts.
///
/// Joins all parts with `|`, hashes with SHA-256, and returns lowercase hex.
pub fn compute_fingerprint(parts: &[&str]) -> String {
    let input = parts.join("|");
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

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
        full_description: "A changed line has zero hits in LCOV coverage data.",
        remediation: "Add tests to execute the line, or use covguard: ignore / exclude the path.",
        help_anchor: "uncovered_line",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#uncovered_line",
    },
    CodeInfo {
        code: CODE_COVERAGE_BELOW_THRESHOLD,
        name: "CoverageBelowThreshold",
        short_description: "Diff coverage below threshold",
        full_description: "Diff-scoped coverage percentage is below the configured threshold.",
        remediation: "Add tests for changed lines or adjust coverage configuration/normalization.",
        help_anchor: "coverage_below_threshold",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#coverage_below_threshold",
    },
    CodeInfo {
        code: CODE_MISSING_COVERAGE_FOR_FILE,
        name: "MissingCoverageForFile",
        short_description: "Missing coverage for file",
        full_description: "A changed file has no LCOV record.",
        remediation: "Ensure coverage includes the file, or exclude the path if appropriate.",
        help_anchor: "missing_coverage_for_file",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#missing_coverage_for_file",
    },
    CodeInfo {
        code: CODE_INVALID_LCOV,
        name: "InvalidLcov",
        short_description: "Invalid LCOV input",
        full_description: "LCOV input could not be parsed as valid LCOV format.",
        remediation: "Regenerate LCOV and ensure the file is not truncated or corrupted.",
        help_anchor: "invalid_lcov",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#invalid_lcov",
    },
    CodeInfo {
        code: CODE_INVALID_DIFF,
        name: "InvalidDiff",
        short_description: "Invalid diff input",
        full_description: "Diff input could not be parsed as a unified diff.",
        remediation: "Ensure a valid unified diff is provided or use --base/--head.",
        help_anchor: "invalid_diff",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#invalid_diff",
    },
    CodeInfo {
        code: CODE_RUNTIME_ERROR,
        name: "RuntimeError",
        short_description: "Tool runtime error",
        full_description: "covguard failed due to a runtime or internal error.",
        remediation: "Re-run with raw inputs captured and file a bug if reproducible.",
        help_anchor: "runtime_error",
        help_uri: "https://github.com/covguard/covguard/blob/main/docs/codes.md#runtime_error",
    },
];

/// Lookup code metadata by code string.
pub fn explain(code: &str) -> Option<&'static CodeInfo> {
    CODE_REGISTRY.iter().find(|info| info.code == code)
}

// ============================================================================
// Enums
// ============================================================================

/// Severity level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

/// Status of the overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

/// Scope of lines to evaluate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Only evaluate added lines.
    #[default]
    Added,
    /// Evaluate all touched (added + modified) lines.
    Touched,
}

/// Input availability status for capabilities block.
///
/// Used to implement "No Green By Omission" - explicitly report input availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputStatus {
    /// Input was available and processed.
    Available,
    /// Input was not available (file missing, not provided).
    Unavailable,
    /// Input was available but skipped (e.g., disabled by configuration).
    Skipped,
}

/// Capabilities block for sensor.report.v1 compliance.
///
/// Reports what inputs were available and processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Status of each input type.
    pub inputs: InputsCapability,
}

/// A single input capability with status and optional reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputCapability {
    /// Availability status of the input.
    pub status: InputStatus,
    /// Reason for the status (e.g., "missing_lcov" when unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Input availability for the capabilities block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputsCapability {
    /// Diff input availability.
    pub diff: InputCapability,
    /// Coverage input availability.
    pub coverage: InputCapability,
}

// ============================================================================
// Structs
// ============================================================================

/// Information about the tool that generated the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Name of the tool.
    pub name: String,
    /// Version of the tool.
    pub version: String,
    /// Git commit hash of the tool, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

impl Default for Tool {
    fn default() -> Self {
        Self {
            name: "covguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: None,
        }
    }
}

/// Information about the run timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// ISO 8601 timestamp when the run started.
    pub started_at: String,
    /// ISO 8601 timestamp when the run ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// Duration of the run in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Capabilities block for sensor.report.v1 compliance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
}

impl Default for Run {
    fn default() -> Self {
        Self {
            started_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ended_at: None,
            duration_ms: None,
            capabilities: None,
        }
    }
}

/// Counts of findings by severity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerdictCounts {
    /// Number of info-level findings.
    pub info: u32,
    /// Number of warn-level findings.
    pub warn: u32,
    /// Number of error-level findings.
    pub error: u32,
}

/// The overall verdict of the coverage check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// Overall status of the check.
    pub status: VerdictStatus,
    /// Counts of findings by severity.
    pub counts: VerdictCounts,
    /// Reasons for the verdict.
    pub reasons: Vec<String>,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            status: VerdictStatus::Pass,
            counts: VerdictCounts::default(),
            reasons: Vec::new(),
        }
    }
}

/// Location of a finding in the source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Repo-relative path to the file (forward slashes, no ./ prefix).
    pub path: String,
    /// Line number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Column number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

/// A single finding from the coverage analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Severity of the finding.
    pub severity: Severity,
    /// Check identifier (e.g., "diff.uncovered_line").
    pub check_id: String,
    /// Full error code (e.g., "covguard.diff.uncovered_line").
    pub code: String,
    /// Human-readable message describing the finding.
    pub message: String,
    /// Location of the finding in source code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Additional structured data about the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// SHA-256 fingerprint for deduplication (`^[a-f0-9]{64}$`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl Finding {
    /// Create a finding for an uncovered line.
    pub fn uncovered_line(path: impl Into<String>, line: u32, hits: u64) -> Self {
        Self {
            severity: Severity::Error,
            check_id: "diff.uncovered_line".to_string(),
            code: CODE_UNCOVERED_LINE.to_string(),
            message: format!("Uncovered changed line (hits={}).", hits),
            location: Some(Location {
                path: path.into(),
                line: Some(line),
                col: None,
            }),
            data: Some(serde_json::json!({ "hits": hits })),
            fingerprint: None,
        }
    }
}

/// Information about the inputs used for the analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Source of the diff ("diff-file", "git-refs", etc.).
    pub diff_source: String,
    /// Path to the diff file, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_file: Option<String>,
    /// Base git ref, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Head git ref, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Paths to LCOV coverage files.
    pub lcov_paths: Vec<String>,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            diff_source: "diff-file".to_string(),
            diff_file: None,
            base: None,
            head: None,
            lcov_paths: Vec::new(),
        }
    }
}

/// Truncation metadata when findings exceed `max_findings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Truncation {
    /// Whether findings were truncated.
    pub findings_truncated: bool,
    /// Number of findings shown in the report.
    pub shown: u32,
    /// Total number of findings before truncation.
    pub total: u32,
}

/// Aggregated data about the coverage analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    /// Scope of lines evaluated ("added" or "touched").
    pub scope: String,
    /// Coverage threshold percentage.
    pub threshold_pct: f64,
    /// Total number of changed lines in scope.
    pub changed_lines_total: u32,
    /// Number of covered lines.
    pub covered_lines: u32,
    /// Number of uncovered lines.
    pub uncovered_lines: u32,
    /// Number of lines with missing coverage data.
    pub missing_lines: u32,
    /// Number of lines ignored via `covguard: ignore` directive.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ignored_lines_count: u32,
    /// Number of files excluded via include/exclude filtering.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub excluded_files_count: u32,
    /// Diff coverage percentage.
    pub diff_coverage_pct: f64,
    /// Information about the inputs.
    pub inputs: Inputs,
    /// Optional debug payload (opaque).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<serde_json::Value>,
    /// Truncation metadata (populated when findings exceed max_findings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation: Option<Truncation>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Default for ReportData {
    fn default() -> Self {
        Self {
            scope: "added".to_string(),
            threshold_pct: 80.0,
            changed_lines_total: 0,
            covered_lines: 0,
            uncovered_lines: 0,
            missing_lines: 0,
            ignored_lines_count: 0,
            excluded_files_count: 0,
            diff_coverage_pct: 0.0,
            inputs: Inputs::default(),
            debug: None,
            truncation: None,
        }
    }
}

/// The full coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Schema identifier.
    pub schema: String,
    /// Tool information.
    pub tool: Tool,
    /// Run timing information.
    pub run: Run,
    /// Overall verdict.
    pub verdict: Verdict,
    /// List of findings.
    pub findings: Vec<Finding>,
    /// Aggregated data.
    pub data: ReportData,
}

impl Report {
    /// Create a new report with default values.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for Report {
    fn default() -> Self {
        Self {
            schema: SCHEMA_ID.to_string(),
            tool: Tool::default(),
            run: Run::default(),
            verdict: Verdict::default(),
            findings: Vec::new(),
            data: ReportData::default(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint_known_values() {
        assert_eq!(
            compute_fingerprint(&["a", "b"]),
            "0eab8a0a3380abf4c7d1fb0b43b66aafbb64a4b953e4eb2dccca579461912d0c"
        );
        assert_eq!(
            compute_fingerprint(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_explain_returns_code_info() {
        let info = explain(CODE_UNCOVERED_LINE).expect("code should exist");
        assert_eq!(info.code, CODE_UNCOVERED_LINE);
        assert_eq!(info.name, "UncoveredLine");
        assert!(explain("covguard.missing.code").is_none());
    }

    #[test]
    fn test_severity_serialization() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"warn\"");
        assert_eq!(
            serde_json::to_string(&Severity::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn test_severity_deserialization() {
        assert_eq!(
            serde_json::from_str::<Severity>("\"info\"").unwrap(),
            Severity::Info
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"warn\"").unwrap(),
            Severity::Warn
        );
        assert_eq!(
            serde_json::from_str::<Severity>("\"error\"").unwrap(),
            Severity::Error
        );
    }

    #[test]
    fn test_verdict_status_serialization() {
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Skip).unwrap(),
            "\"skip\""
        );
    }

    #[test]
    fn test_scope_serialization() {
        assert_eq!(serde_json::to_string(&Scope::Added).unwrap(), "\"added\"");
        assert_eq!(
            serde_json::to_string(&Scope::Touched).unwrap(),
            "\"touched\""
        );
    }

    #[test]
    fn test_finding_uncovered_line() {
        let finding = Finding::uncovered_line("src/lib.rs", 42, 0);

        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.check_id, "diff.uncovered_line");
        assert_eq!(finding.code, CODE_UNCOVERED_LINE);
        assert_eq!(finding.message, "Uncovered changed line (hits=0).");

        let location = finding.location.unwrap();
        assert_eq!(location.path, "src/lib.rs");
        assert_eq!(location.line, Some(42));
        assert_eq!(location.col, None);

        let data = finding.data.unwrap();
        assert_eq!(data["hits"], 0);
    }

    #[test]
    fn test_report_default() {
        let report = Report::new();

        assert_eq!(report.schema, SCHEMA_ID);
        assert_eq!(report.tool.name, "covguard");
        assert_eq!(report.verdict.status, VerdictStatus::Pass);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_optional_fields_not_serialized() {
        let tool = Tool {
            name: "covguard".to_string(),
            version: "0.2.0".to_string(),
            commit: None,
        };

        let json = serde_json::to_string(&tool).unwrap();
        assert!(!json.contains("commit"));
    }

    #[test]
    fn test_location_serialization() {
        let location = Location {
            path: "src/main.rs".to_string(),
            line: Some(10),
            col: None,
        };

        let json = serde_json::to_string(&location).unwrap();
        assert!(json.contains("\"path\":\"src/main.rs\""));
        assert!(json.contains("\"line\":10"));
        assert!(!json.contains("col"));
    }

    #[test]
    fn test_report_matches_expected_json_structure() {
        // Build a report matching fixtures/expected/report_uncovered.json
        let report = Report {
            schema: SCHEMA_ID.to_string(),
            tool: Tool {
                name: "covguard".to_string(),
                version: "0.2.0".to_string(),
                commit: None,
            },
            run: Run {
                started_at: "2026-02-02T00:00:00Z".to_string(),
                ended_at: None,
                duration_ms: None,
                capabilities: None,
            },
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 3,
                },
                reasons: vec!["uncovered_lines".to_string()],
            },
            findings: vec![
                Finding::uncovered_line("src/lib.rs", 1, 0),
                Finding::uncovered_line("src/lib.rs", 2, 0),
                Finding::uncovered_line("src/lib.rs", 3, 0),
            ],
            data: ReportData {
                scope: "added".to_string(),
                threshold_pct: 80.0,
                changed_lines_total: 3,
                covered_lines: 0,
                uncovered_lines: 3,
                missing_lines: 0,
                ignored_lines_count: 0,
                excluded_files_count: 0,
                diff_coverage_pct: 0.0,
                inputs: Inputs {
                    diff_source: "diff-file".to_string(),
                    diff_file: Some("fixtures/diff/simple_added.patch".to_string()),
                    base: None,
                    head: None,
                    lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
                },
                debug: None,
                truncation: None,
            },
        };

        let json = serde_json::to_value(&report).unwrap();

        // Verify structure matches expected
        assert_eq!(json["schema"], "covguard.report.v1");
        assert_eq!(json["tool"]["name"], "covguard");
        assert_eq!(json["tool"]["version"], "0.2.0");
        assert_eq!(json["run"]["started_at"], "2026-02-02T00:00:00Z");
        assert_eq!(json["verdict"]["status"], "fail");
        assert_eq!(json["verdict"]["counts"]["error"], 3);
        assert_eq!(json["findings"].as_array().unwrap().len(), 3);
        assert_eq!(json["findings"][0]["severity"], "error");
        assert_eq!(json["findings"][0]["location"]["path"], "src/lib.rs");
        assert_eq!(json["findings"][0]["location"]["line"], 1);
        assert_eq!(json["data"]["scope"], "added");
        assert_eq!(json["data"]["threshold_pct"], 80.0);
        assert_eq!(json["data"]["inputs"]["diff_source"], "diff-file");
    }

    #[test]
    fn test_full_report_roundtrip() {
        let report = Report::new();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: Report = serde_json::from_str(&json).unwrap();

        assert_eq!(report.schema, parsed.schema);
        assert_eq!(report.tool.name, parsed.tool.name);
        assert_eq!(report.verdict.status, parsed.verdict.status);
    }

    // ========================================================================
    // Severity Ordering Tests
    // ========================================================================

    #[test]
    fn test_severity_ordering() {
        // Info < Warn < Error
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Error);
        assert!(Severity::Info < Severity::Error);
    }

    #[test]
    fn test_severity_sorting() {
        let mut severities = vec![
            Severity::Error,
            Severity::Info,
            Severity::Warn,
            Severity::Error,
        ];
        severities.sort();
        assert_eq!(
            severities,
            vec![
                Severity::Info,
                Severity::Warn,
                Severity::Error,
                Severity::Error
            ]
        );
    }

    #[test]
    fn test_severity_equality() {
        assert_eq!(Severity::Info, Severity::Info);
        assert_eq!(Severity::Warn, Severity::Warn);
        assert_eq!(Severity::Error, Severity::Error);
        assert_ne!(Severity::Info, Severity::Warn);
    }

    // ========================================================================
    // Deserialization Error Tests
    // ========================================================================

    #[test]
    fn test_invalid_severity_deserialization() {
        let result = serde_json::from_str::<Severity>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_verdict_status_deserialization() {
        let result = serde_json::from_str::<VerdictStatus>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_scope_deserialization() {
        let result = serde_json::from_str::<Scope>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_field() {
        // Report missing schema field
        let json = r#"{"tool": {"name": "covguard", "version": "0.1.0"}}"#;
        let result = serde_json::from_str::<Report>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_type_field() {
        // Severity should be string, not number
        let result = serde_json::from_str::<Severity>("123");
        assert!(result.is_err());
    }

    // ========================================================================
    // Scope Tests
    // ========================================================================

    #[test]
    fn test_scope_default() {
        assert_eq!(Scope::default(), Scope::Added);
    }

    #[test]
    fn test_scope_deserialization() {
        assert_eq!(
            serde_json::from_str::<Scope>("\"added\"").unwrap(),
            Scope::Added
        );
        assert_eq!(
            serde_json::from_str::<Scope>("\"touched\"").unwrap(),
            Scope::Touched
        );
    }

    // ========================================================================
    // VerdictCounts Tests
    // ========================================================================

    #[test]
    fn test_verdict_counts_default() {
        let counts = VerdictCounts::default();
        assert_eq!(counts.info, 0);
        assert_eq!(counts.warn, 0);
        assert_eq!(counts.error, 0);
    }

    #[test]
    fn test_verdict_counts_serialization() {
        let counts = VerdictCounts {
            info: 1,
            warn: 2,
            error: 3,
        };
        let json = serde_json::to_value(&counts).unwrap();
        assert_eq!(json["info"], 1);
        assert_eq!(json["warn"], 2);
        assert_eq!(json["error"], 3);
    }

    #[test]
    fn test_verdict_counts_large_values() {
        let counts = VerdictCounts {
            info: u32::MAX,
            warn: u32::MAX,
            error: u32::MAX,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let parsed: VerdictCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.info, u32::MAX);
        assert_eq!(parsed.warn, u32::MAX);
        assert_eq!(parsed.error, u32::MAX);
    }

    // ========================================================================
    // Tool Tests
    // ========================================================================

    #[test]
    fn test_tool_default() {
        let tool = Tool::default();
        assert_eq!(tool.name, "covguard");
        assert!(!tool.version.is_empty());
        assert!(tool.commit.is_none());
    }

    #[test]
    fn test_tool_with_commit() {
        let tool = Tool {
            name: "covguard".to_string(),
            version: "1.0.0".to_string(),
            commit: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("commit"));
        assert!(json.contains("abc123"));
    }

    // ========================================================================
    // Run Tests
    // ========================================================================

    #[test]
    fn test_run_default_has_timestamp() {
        let run = Run::default();
        assert!(!run.started_at.is_empty());
        assert!(run.started_at.contains("T")); // ISO 8601 format
        assert!(run.ended_at.is_none());
        assert!(run.duration_ms.is_none());
    }

    #[test]
    fn test_run_with_duration() {
        let run = Run {
            started_at: "2026-02-02T00:00:00Z".to_string(),
            ended_at: Some("2026-02-02T00:00:01Z".to_string()),
            duration_ms: Some(1000),
            capabilities: None,
        };
        let json = serde_json::to_value(&run).unwrap();
        assert_eq!(json["duration_ms"], 1000);
    }

    // ========================================================================
    // Verdict Tests
    // ========================================================================

    #[test]
    fn test_verdict_default() {
        let verdict = Verdict::default();
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert!(verdict.reasons.is_empty());
    }

    #[test]
    fn test_verdict_all_statuses() {
        for status in [
            VerdictStatus::Pass,
            VerdictStatus::Warn,
            VerdictStatus::Fail,
            VerdictStatus::Skip,
        ] {
            let verdict = Verdict {
                status,
                counts: VerdictCounts::default(),
                reasons: Vec::new(),
            };
            let json = serde_json::to_string(&verdict).unwrap();
            let parsed: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(verdict.status, parsed.status);
        }
    }

    // ========================================================================
    // Location Tests
    // ========================================================================

    #[test]
    fn test_location_minimal() {
        let location = Location {
            path: "src/lib.rs".to_string(),
            line: None,
            col: None,
        };
        let json = serde_json::to_string(&location).unwrap();
        assert!(!json.contains("line"));
        assert!(!json.contains("col"));
    }

    #[test]
    fn test_location_full() {
        let location = Location {
            path: "src/lib.rs".to_string(),
            line: Some(42),
            col: Some(10),
        };
        let json = serde_json::to_value(&location).unwrap();
        assert_eq!(json["path"], "src/lib.rs");
        assert_eq!(json["line"], 42);
        assert_eq!(json["col"], 10);
    }

    #[test]
    fn test_location_with_unicode_path() {
        let location = Location {
            path: "src/日本語/lib.rs".to_string(),
            line: Some(1),
            col: None,
        };
        let json = serde_json::to_string(&location).unwrap();
        let parsed: Location = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, "src/日本語/lib.rs");
    }

    // ========================================================================
    // Finding Tests
    // ========================================================================

    #[test]
    fn test_finding_uncovered_line_structure() {
        let finding = Finding::uncovered_line("src/lib.rs", 42, 0);

        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.check_id, "diff.uncovered_line");
        assert_eq!(finding.code, CODE_UNCOVERED_LINE);
        assert!(finding.message.contains("hits=0"));
    }

    #[test]
    fn test_finding_uncovered_line_with_nonzero_hits() {
        // Edge case: technically impossible but test the formatting
        let finding = Finding::uncovered_line("src/lib.rs", 42, 5);
        assert!(finding.message.contains("hits=5"));

        let data = finding.data.unwrap();
        assert_eq!(data["hits"], 5);
    }

    #[test]
    fn test_finding_without_location() {
        let finding = Finding {
            severity: Severity::Error,
            check_id: "diff.coverage_below_threshold".to_string(),
            code: CODE_COVERAGE_BELOW_THRESHOLD.to_string(),
            message: "Coverage 50% is below threshold 80%".to_string(),
            location: None,
            data: None,
            fingerprint: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("location"));
    }

    #[test]
    fn test_finding_large_line_number() {
        let finding = Finding::uncovered_line("src/lib.rs", u32::MAX, 0);
        let location = finding.location.unwrap();
        assert_eq!(location.line, Some(u32::MAX));
    }

    // ========================================================================
    // Inputs Tests
    // ========================================================================

    #[test]
    fn test_inputs_default() {
        let inputs = Inputs::default();
        assert_eq!(inputs.diff_source, "diff-file");
        assert!(inputs.diff_file.is_none());
        assert!(inputs.base.is_none());
        assert!(inputs.head.is_none());
        assert!(inputs.lcov_paths.is_empty());
    }

    #[test]
    fn test_inputs_with_git_refs() {
        let inputs = Inputs {
            diff_source: "git-refs".to_string(),
            diff_file: None,
            base: Some("main".to_string()),
            head: Some("feature".to_string()),
            lcov_paths: vec!["coverage.info".to_string()],
        };
        let json = serde_json::to_value(&inputs).unwrap();
        assert_eq!(json["diff_source"], "git-refs");
        assert_eq!(json["base"], "main");
        assert_eq!(json["head"], "feature");
    }

    #[test]
    fn test_inputs_with_multiple_lcov_paths() {
        let inputs = Inputs {
            diff_source: "diff-file".to_string(),
            diff_file: Some("changes.patch".to_string()),
            base: None,
            head: None,
            lcov_paths: vec![
                "unit.info".to_string(),
                "integration.info".to_string(),
                "e2e.info".to_string(),
            ],
        };
        let json = serde_json::to_value(&inputs).unwrap();
        let lcov_paths = json["lcov_paths"].as_array().unwrap();
        assert_eq!(lcov_paths.len(), 3);
    }

    // ========================================================================
    // ReportData Tests
    // ========================================================================

    #[test]
    fn test_report_data_default() {
        let data = ReportData::default();
        assert_eq!(data.scope, "added");
        assert_eq!(data.threshold_pct, 80.0);
        assert_eq!(data.changed_lines_total, 0);
        assert_eq!(data.covered_lines, 0);
        assert_eq!(data.uncovered_lines, 0);
        assert_eq!(data.missing_lines, 0);
        assert_eq!(data.ignored_lines_count, 0);
        assert_eq!(data.diff_coverage_pct, 0.0);
    }

    #[test]
    fn test_report_data_ignored_lines_not_serialized_when_zero() {
        let data = ReportData {
            ignored_lines_count: 0,
            ..Default::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(!json.contains("ignored_lines_count"));
    }

    #[test]
    fn test_report_data_ignored_lines_serialized_when_nonzero() {
        let data = ReportData {
            ignored_lines_count: 5,
            ..Default::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("ignored_lines_count"));
    }

    #[test]
    fn test_report_data_excluded_files_count_serialization() {
        let data = ReportData {
            excluded_files_count: 2,
            ..Default::default()
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("excluded_files_count"));
    }

    #[test]
    fn test_code_registry_contains_known_codes() {
        let codes: Vec<&str> = CODE_REGISTRY.iter().map(|c| c.code).collect();
        assert!(codes.contains(&CODE_UNCOVERED_LINE));
        assert!(codes.contains(&CODE_COVERAGE_BELOW_THRESHOLD));
        assert!(codes.contains(&CODE_MISSING_COVERAGE_FOR_FILE));
        assert!(codes.contains(&CODE_INVALID_LCOV));
        assert!(codes.contains(&CODE_INVALID_DIFF));
        assert!(codes.contains(&CODE_RUNTIME_ERROR));
    }

    #[test]
    fn test_registry_covers_fixture_and_snapshot_codes() {
        use std::collections::BTreeSet;
        use std::fs;
        use std::path::PathBuf;

        fn workspace_root() -> PathBuf {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("crates directory")
                .parent()
                .expect("workspace root")
                .to_path_buf()
        }

        fn extract_codes(content: &str) -> BTreeSet<String> {
            let mut codes = BTreeSet::new();
            let bytes = content.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i..].starts_with(b"covguard.") {
                    let mut j = i + "covguard.".len();
                    while j < bytes.len() {
                        let c = bytes[j] as char;
                        if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    if let Ok(code) = std::str::from_utf8(&bytes[i..j]) {
                        codes.insert(code.to_string());
                    }
                    i = j;
                    continue;
                }
                if bytes[i..].starts_with(CODE_RUNTIME_ERROR.as_bytes()) {
                    codes.insert(CODE_RUNTIME_ERROR.to_string());
                    i += CODE_RUNTIME_ERROR.len();
                    continue;
                }
                i += 1;
            }
            codes
        }

        fn scan_dir(root: &PathBuf, rel: &str) -> BTreeSet<String> {
            let mut found = BTreeSet::new();
            let dir = root.join(rel);
            if !dir.exists() {
                return found;
            }
            let entries = fs::read_dir(&dir).expect("read_dir failed");
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let sub_rel = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string();
                    found.extend(scan_dir(root, &sub_rel));
                } else if let Ok(content) = fs::read_to_string(&path) {
                    found.extend(extract_codes(&content));
                }
            }
            found
        }

        let root = workspace_root();
        let mut codes = BTreeSet::new();
        codes.extend(scan_dir(&root, "fixtures/expected"));
        codes.extend(scan_dir(&root, "crates/covguard-render/src/snapshots"));
        codes.extend(scan_dir(&root, "crates/covguard-app/src/snapshots"));
        let temp_root = std::env::temp_dir().join(format!("covguard-types-{}", std::process::id()));
        let nested_dir = temp_root.join("nested").join("inner");
        fs::create_dir_all(&nested_dir).expect("create temp nested dir");
        fs::write(nested_dir.join("codes.txt"), "covguard.diff.uncovered_line")
            .expect("write temp codes file");
        codes.extend(scan_dir(&temp_root, "nested"));
        let _ = fs::remove_dir_all(&temp_root);

        // Filter out schema ID which isn't an error code
        codes.remove(SCHEMA_ID);

        let registry: BTreeSet<&'static str> = CODE_REGISTRY.iter().map(|c| c.code).collect();
        for code in codes {
            assert!(registry.contains(code.as_str()));
        }
    }

    #[test]
    fn test_report_data_100_percent_coverage() {
        let data = ReportData {
            changed_lines_total: 10,
            covered_lines: 10,
            uncovered_lines: 0,
            diff_coverage_pct: 100.0,
            ..Default::default()
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["diff_coverage_pct"], 100.0);
    }

    #[test]
    fn test_report_data_zero_coverage() {
        let data = ReportData {
            changed_lines_total: 10,
            covered_lines: 0,
            uncovered_lines: 10,
            diff_coverage_pct: 0.0,
            ..Default::default()
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["diff_coverage_pct"], 0.0);
    }

    // ========================================================================
    // Constants Tests
    // ========================================================================

    #[test]
    fn test_schema_id_constant() {
        assert_eq!(SCHEMA_ID, "covguard.report.v1");
    }

    #[test]
    fn test_error_code_constants() {
        assert!(CODE_UNCOVERED_LINE.starts_with("covguard."));
        assert!(CODE_COVERAGE_BELOW_THRESHOLD.starts_with("covguard."));
        assert!(CODE_MISSING_COVERAGE_FOR_FILE.starts_with("covguard."));
        assert!(CODE_INVALID_LCOV.starts_with("covguard."));
        assert!(CODE_INVALID_DIFF.starts_with("covguard."));
        assert!(CODE_RUNTIME_ERROR.starts_with("tool."));
    }

    // ========================================================================
    // Report Tests
    // ========================================================================

    #[test]
    fn test_report_new_equals_default() {
        let new = Report::new();
        let default = Report::default();
        assert_eq!(new.schema, default.schema);
        assert_eq!(new.tool.name, default.tool.name);
        assert_eq!(new.verdict.status, default.verdict.status);
    }

    #[test]
    fn test_report_with_many_findings() {
        let findings: Vec<_> = (1..=1000)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();

        let report = Report {
            findings,
            ..Default::default()
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.findings.len(), 1000);
    }

    #[test]
    fn test_report_empty_findings() {
        let report = Report {
            findings: Vec::new(),
            ..Default::default()
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["findings"].as_array().unwrap().len(), 0);
    }

    // ========================================================================
    // Capabilities Tests (sensor.report.v1)
    // ========================================================================

    #[test]
    fn test_sensor_schema_id_constant() {
        assert_eq!(SENSOR_SCHEMA_ID, "sensor.report.v1");
    }

    #[test]
    fn test_input_status_serialization() {
        assert_eq!(
            serde_json::to_string(&InputStatus::Available).unwrap(),
            "\"available\""
        );
        assert_eq!(
            serde_json::to_string(&InputStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&InputStatus::Skipped).unwrap(),
            "\"skipped\""
        );
    }

    #[test]
    fn test_input_status_deserialization() {
        assert_eq!(
            serde_json::from_str::<InputStatus>("\"available\"").unwrap(),
            InputStatus::Available
        );
        assert_eq!(
            serde_json::from_str::<InputStatus>("\"unavailable\"").unwrap(),
            InputStatus::Unavailable
        );
        assert_eq!(
            serde_json::from_str::<InputStatus>("\"skipped\"").unwrap(),
            InputStatus::Skipped
        );
    }

    #[test]
    fn test_input_status_invalid_deserialization() {
        let result = serde_json::from_str::<InputStatus>("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_capabilities_serialization() {
        let capabilities = Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
                coverage: InputCapability {
                    status: InputStatus::Unavailable,
                    reason: Some("missing_lcov".to_string()),
                },
            },
        };
        let json = serde_json::to_value(&capabilities).unwrap();
        assert_eq!(json["inputs"]["diff"]["status"], "available");
        assert_eq!(json["inputs"]["coverage"]["status"], "unavailable");
        assert_eq!(json["inputs"]["coverage"]["reason"], "missing_lcov");
        // reason should not be present when None
        assert!(json["inputs"]["diff"].get("reason").is_none());
    }

    #[test]
    fn test_capabilities_roundtrip() {
        let capabilities = Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
                coverage: InputCapability {
                    status: InputStatus::Skipped,
                    reason: Some("disabled".to_string()),
                },
            },
        };
        let json = serde_json::to_string(&capabilities).unwrap();
        let parsed: Capabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.inputs.diff.status, InputStatus::Available);
        assert_eq!(parsed.inputs.coverage.status, InputStatus::Skipped);
        assert_eq!(parsed.inputs.coverage.reason, Some("disabled".to_string()));
    }

    #[test]
    fn test_run_with_capabilities() {
        let run = Run {
            started_at: "2026-02-02T00:00:00Z".to_string(),
            ended_at: None,
            duration_ms: None,
            capabilities: Some(Capabilities {
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
            }),
        };
        let json = serde_json::to_value(&run).unwrap();
        assert!(json.get("capabilities").is_some());
        assert_eq!(
            json["capabilities"]["inputs"]["diff"]["status"],
            "available"
        );
        assert_eq!(
            json["capabilities"]["inputs"]["coverage"]["status"],
            "available"
        );
    }

    #[test]
    fn test_run_without_capabilities_omits_field() {
        let run = Run {
            started_at: "2026-02-02T00:00:00Z".to_string(),
            ended_at: None,
            duration_ms: None,
            capabilities: None,
        };
        let json = serde_json::to_string(&run).unwrap();
        assert!(!json.contains("capabilities"));
    }

    // ========================================================================
    // Token & Code Hygiene Tests
    // ========================================================================

    #[test]
    fn test_reason_tokens_match_pattern() {
        let reason_re = regex_lite::Regex::new(r"^[a-z0-9_]+$").unwrap();
        let reasons = [
            REASON_MISSING_LCOV,
            REASON_MISSING_DIFF,
            REASON_NO_CHANGED_LINES,
            REASON_DIFF_COVERED,
            REASON_UNCOVERED_LINES,
            REASON_BELOW_THRESHOLD,
            REASON_TOOL_ERROR,
            REASON_SKIPPED,
            REASON_TRUNCATED,
        ];
        for reason in &reasons {
            assert!(reason_re.is_match(reason));
        }
    }

    #[test]
    fn test_code_constants_match_pattern() {
        let code_re = regex_lite::Regex::new(r"^[a-z0-9_.]+$").unwrap();
        let codes = [
            CODE_UNCOVERED_LINE,
            CODE_COVERAGE_BELOW_THRESHOLD,
            CODE_MISSING_COVERAGE_FOR_FILE,
            CODE_INVALID_LCOV,
            CODE_INVALID_DIFF,
            CODE_RUNTIME_ERROR,
        ];
        for code in &codes {
            assert!(code_re.is_match(code));
        }
    }

    #[test]
    fn test_code_registry_entries_have_valid_codes() {
        let code_re = regex_lite::Regex::new(r"^[a-z0-9_.]+$").unwrap();
        for entry in CODE_REGISTRY {
            assert!(code_re.is_match(entry.code));
        }
    }
}
