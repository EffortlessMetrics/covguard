//! Rendering utilities for covguard reports.
//!
//! This crate provides renderers that convert a `Report` into various output formats:
//! - Markdown for PR comments
//! - GitHub workflow annotation commands
//! - SARIF (Static Analysis Results Interchange Format)
//!
//! # Example
//!
//! ```rust
//! use covguard_render::{render_markdown, render_annotations, render_sarif};
//! use covguard_types::Report;
//!
//! let report = Report::default();
//! let markdown = render_markdown(&report, 10);
//! let annotations = render_annotations(&report, 25);
//! let sarif = render_sarif(&report, 1000);
//! ```

use covguard_types::{CODE_REGISTRY, CodeInfo, Report, Severity, VerdictStatus};
use serde::Serialize;

/// Default maximum number of lines to show in markdown table.
pub const DEFAULT_MAX_LINES: usize = 10;

/// Default maximum number of GitHub annotations to emit.
pub const DEFAULT_MAX_ANNOTATIONS: usize = 25;

/// Returns an emoji representing the verdict status.
///
/// # Examples
///
/// ```rust
/// use covguard_render::status_emoji;
/// use covguard_types::VerdictStatus;
///
/// assert_eq!(status_emoji(&VerdictStatus::Pass), "\u{2705}");
/// assert_eq!(status_emoji(&VerdictStatus::Fail), "\u{274C}");
/// ```
pub fn status_emoji(status: &VerdictStatus) -> &'static str {
    match status {
        VerdictStatus::Pass => "\u{2705}",
        VerdictStatus::Warn => "\u{26A0}\u{FE0F}",
        VerdictStatus::Fail => "\u{274C}",
        VerdictStatus::Skip => "\u{23ED}\u{FE0F}",
    }
}

/// Returns a human-readable status label.
fn status_label(status: &VerdictStatus) -> &'static str {
    match status {
        VerdictStatus::Pass => "pass",
        VerdictStatus::Warn => "warn",
        VerdictStatus::Fail => "fail",
        VerdictStatus::Skip => "skip",
    }
}

/// Renders the report as a Markdown comment for pull requests.
///
/// # Arguments
///
/// * `report` - The coverage report to render.
/// * `max_lines` - Maximum number of uncovered lines to show in the table (default 10).
///
/// # Returns
///
/// A Markdown-formatted string suitable for a PR comment.
///
/// # Example Output
///
/// ```markdown
/// ## covguard: Diff Coverage Report
///
/// **Status**: [emoji] [status]
///
/// ### Summary
/// - **Diff coverage**: X.X%
/// - **Changed lines**: N
/// - **Covered**: N
/// - **Uncovered**: N
///
/// ### Uncovered Lines
///
/// | File | Line | Hits |
/// |------|------|------|
/// | src/lib.rs | 1 | 0 |
///
/// *Showing N of M uncovered lines*
///
/// <details>
/// <summary>Reproduce locally</summary>
///
/// ```bash
/// covguard check --diff-file <file> --lcov <lcov>
/// ```
///
/// </details>
/// ```
pub fn render_markdown(report: &Report, max_lines: usize) -> String {
    let mut output = String::new();

    // Header
    output.push_str("## covguard: Diff Coverage Report\n\n");

    // Status line
    let emoji = status_emoji(&report.verdict.status);
    let label = status_label(&report.verdict.status);
    output.push_str(&format!("**Status**: {} {}\n\n", emoji, label));

    // Summary section
    output.push_str("### Summary\n");
    output.push_str(&format!(
        "- **Diff coverage**: {:.1}%\n",
        report.data.diff_coverage_pct
    ));
    output.push_str(&format!(
        "- **Changed lines**: {}\n",
        report.data.changed_lines_total
    ));
    output.push_str(&format!("- **Covered**: {}\n", report.data.covered_lines));
    output.push_str(&format!(
        "- **Uncovered**: {}\n",
        report.data.uncovered_lines
    ));

    // Uncovered lines table (only if there are findings with locations)
    let uncovered_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.location.is_some())
        .collect();

    if !uncovered_findings.is_empty() {
        output.push_str("\n### Uncovered Lines\n\n");
        output.push_str("| File | Line | Hits |\n");
        output.push_str("|------|------|------|\n");

        let total_findings = uncovered_findings.len();
        let shown = total_findings.min(max_lines);

        for finding in uncovered_findings.iter().take(max_lines) {
            if let Some(location) = &finding.location {
                let line_str = location
                    .line
                    .map(|l| l.to_string())
                    .unwrap_or_else(|| "-".to_string());

                // Extract hits from finding data
                let hits = finding
                    .data
                    .as_ref()
                    .and_then(|d| d.get("hits"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                output.push_str(&format!(
                    "| {} | {} | {} |\n",
                    location.path, line_str, hits
                ));
            }
        }

        if total_findings > max_lines {
            output.push('\n');
            output.push_str(&format!(
                "*Showing {} of {} uncovered lines*\n",
                shown, total_findings
            ));
        }
    }

    // Reproduce locally section
    output.push_str("\n<details>\n");
    output.push_str("<summary>Reproduce locally</summary>\n\n");
    output.push_str("```bash\n");

    // Build the command based on inputs
    let inputs = &report.data.inputs;
    let mut cmd_parts = vec!["covguard check".to_string()];

    if let Some(diff_file) = &inputs.diff_file {
        cmd_parts.push(format!("--diff-file {}", diff_file));
    } else if inputs.base.is_some() || inputs.head.is_some() {
        if let Some(base) = &inputs.base {
            cmd_parts.push(format!("--base {}", base));
        }
        if let Some(head) = &inputs.head {
            cmd_parts.push(format!("--head {}", head));
        }
    } else {
        cmd_parts.push("--diff-file <file>".to_string());
    }

    if inputs.lcov_paths.is_empty() {
        cmd_parts.push("--lcov <lcov>".to_string());
    } else {
        for lcov_path in &inputs.lcov_paths {
            cmd_parts.push(format!("--lcov {}", lcov_path));
        }
    }

    output.push_str(&cmd_parts.join(" \\\n  "));
    output.push_str("\n```\n\n");
    output.push_str("</details>\n");

    output
}

/// Renders the report as GitHub workflow annotation commands.
///
/// # Arguments
///
/// * `report` - The coverage report to render.
/// * `max_annotations` - Maximum number of annotations to emit (default 25).
///
/// # Returns
///
/// A string containing newline-separated GitHub workflow commands.
///
/// # Example Output
///
/// ```text
/// ::warning file=src/lib.rs,line=1::Uncovered changed line (hits=0)
/// ::error file=src/lib.rs,line=2::Uncovered changed line (hits=0)
/// ```
pub fn render_annotations(report: &Report, max_annotations: usize) -> String {
    let mut output = String::new();

    for finding in report.findings.iter().take(max_annotations) {
        if let Some(location) = &finding.location {
            let level = match finding.severity {
                Severity::Error => "error",
                Severity::Warn => "warning",
                Severity::Info => "notice",
            };

            // Build location parameters
            let mut params = vec![format!("file={}", location.path)];

            if let Some(line) = location.line {
                params.push(format!("line={}", line));
            }

            if let Some(col) = location.col {
                params.push(format!("col={}", col));
            }

            // Extract hits for the message
            let hits = finding
                .data
                .as_ref()
                .and_then(|d| d.get("hits"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let message = format!("Uncovered changed line (hits={})", hits);

            output.push_str(&format!("::{} {}::{}\n", level, params.join(","), message));
        }
    }

    output
}

// ============================================================================
// SARIF Types
// ============================================================================

/// Default maximum number of SARIF results to emit.
pub const DEFAULT_MAX_SARIF_RESULTS: usize = 1000;

/// SARIF report version 2.1.0
#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run
#[derive(Debug, Clone, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// SARIF tool information
#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// SARIF tool driver (main component)
#[derive(Debug, Clone, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// SARIF rule definition
#[derive(Debug, Clone, Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfiguration,
}

/// SARIF rule configuration
#[derive(Debug, Clone, Serialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
}

/// SARIF message
#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// SARIF result (a finding)
#[derive(Debug, Clone, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

/// SARIF location
#[derive(Debug, Clone, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// SARIF physical location
#[derive(Debug, Clone, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// SARIF artifact location
#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
}

/// SARIF region
#[derive(Debug, Clone, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

// ============================================================================
// SARIF Rendering
// ============================================================================

/// Renders the report as a SARIF 2.1.0 JSON document.
///
/// # Arguments
///
/// * `report` - The coverage report to render.
/// * `max_results` - Maximum number of results to emit (default 1000).
///
/// # Returns
///
/// A JSON string containing the SARIF report.
pub fn render_sarif(report: &Report, max_results: usize) -> String {
    let sarif = build_sarif_report(report, max_results);
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

/// Build a SARIF report from a covguard report.
fn build_sarif_report(report: &Report, max_results: usize) -> SarifReport {
    let rules: Vec<SarifRule> = CODE_REGISTRY.iter().map(codeinfo_to_rule).collect();

    // Build rule index map
    let rule_index_map: std::collections::HashMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();

    // Convert findings to SARIF results
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .take(max_results)
        .filter_map(|finding| {
            let rule_index = rule_index_map.get(finding.code.as_str()).copied()?;

            let level = match finding.severity {
                Severity::Error => "error",
                Severity::Warn => "warning",
                Severity::Info => "note",
            };

            let locations = if let Some(ref loc) = finding.location {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: loc.path.clone(),
                            uri_base_id: "%SRCROOT%".to_string(),
                        },
                        region: loc.line.map(|line| SarifRegion {
                            start_line: line,
                            start_column: loc.col,
                        }),
                    },
                }]
            } else {
                vec![]
            };

            Some(SarifResult {
                rule_id: finding.code.clone(),
                rule_index,
                level: level.to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations,
            })
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "covguard".to_string(),
                    version: report.tool.version.clone(),
                    information_uri: "https://github.com/covguard/covguard".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

fn codeinfo_to_rule(info: &CodeInfo) -> SarifRule {
    SarifRule {
        id: info.code.to_string(),
        name: info.name.to_string(),
        short_description: SarifMessage {
            text: info.short_description.to_string(),
        },
        full_description: SarifMessage {
            text: info.full_description.to_string(),
        },
        help_uri: info.help_uri.to_string(),
        default_configuration: SarifRuleConfiguration {
            level: "error".to_string(),
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_types::{
        Finding, Inputs, ReportData, Run, Severity, Tool, Verdict, VerdictCounts, VerdictStatus,
    };

    fn make_test_report(
        status: VerdictStatus,
        findings: Vec<Finding>,
        covered: u32,
        uncovered: u32,
    ) -> Report {
        Report {
            schema: "covguard.report.v1".to_string(),
            tool: Tool {
                name: "covguard".to_string(),
                version: "0.1.0".to_string(),
                commit: None,
            },
            run: Run {
                started_at: "2026-02-02T00:00:00Z".to_string(),
                ended_at: None,
                duration_ms: None,
                capabilities: None,
            },
            verdict: Verdict {
                status,
                counts: VerdictCounts {
                    info: 0,
                    warn: findings
                        .iter()
                        .filter(|f| f.severity == Severity::Warn)
                        .count() as u32,
                    error: findings
                        .iter()
                        .filter(|f| f.severity == Severity::Error)
                        .count() as u32,
                },
                reasons: if uncovered > 0 {
                    vec!["uncovered_lines".to_string()]
                } else {
                    Vec::new()
                },
            },
            findings,
            data: ReportData {
                scope: "added".to_string(),
                threshold_pct: 80.0,
                changed_lines_total: covered + uncovered,
                covered_lines: covered,
                uncovered_lines: uncovered,
                missing_lines: 0,
                ignored_lines_count: 0,
                excluded_files_count: 0,
                diff_coverage_pct: if covered + uncovered > 0 {
                    (covered as f64 / (covered + uncovered) as f64) * 100.0
                } else {
                    100.0
                },
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
        }
    }

    // ========================================================================
    // status_emoji tests
    // ========================================================================

    #[test]
    fn test_status_emoji_pass() {
        assert_eq!(status_emoji(&VerdictStatus::Pass), "\u{2705}");
    }

    #[test]
    fn test_status_emoji_warn() {
        assert_eq!(status_emoji(&VerdictStatus::Warn), "\u{26A0}\u{FE0F}");
    }

    #[test]
    fn test_status_emoji_fail() {
        assert_eq!(status_emoji(&VerdictStatus::Fail), "\u{274C}");
    }

    #[test]
    fn test_status_emoji_skip() {
        assert_eq!(status_emoji(&VerdictStatus::Skip), "\u{23ED}\u{FE0F}");
    }

    // ========================================================================
    // render_markdown tests
    // ========================================================================

    #[test]
    fn test_markdown_header_present() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let md = render_markdown(&report, 10);
        assert!(md.contains("## covguard: Diff Coverage Report"));
    }

    #[test]
    fn test_markdown_status_pass() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let md = render_markdown(&report, 10);
        assert!(md.contains("**Status**: \u{2705} pass"));
    }

    #[test]
    fn test_markdown_status_fail() {
        let report = make_test_report(VerdictStatus::Fail, vec![], 0, 5);
        let md = render_markdown(&report, 10);
        assert!(md.contains("**Status**: \u{274C} fail"));
    }

    #[test]
    fn test_markdown_status_warn() {
        let report = make_test_report(VerdictStatus::Warn, vec![], 3, 2);
        let md = render_markdown(&report, 10);
        assert!(md.contains("**Status**: \u{26A0}\u{FE0F} warn"));
    }

    #[test]
    fn test_markdown_status_skip() {
        let report = make_test_report(VerdictStatus::Skip, vec![], 0, 0);
        let md = render_markdown(&report, 10);
        assert!(md.contains("**Status**: \u{23ED}\u{FE0F} skip"));
    }

    #[test]
    fn test_markdown_summary_section() {
        let report = make_test_report(VerdictStatus::Fail, vec![], 7, 3);
        let md = render_markdown(&report, 10);

        assert!(md.contains("### Summary"));
        assert!(md.contains("- **Diff coverage**: 70.0%"));
        assert!(md.contains("- **Changed lines**: 10"));
        assert!(md.contains("- **Covered**: 7"));
        assert!(md.contains("- **Uncovered**: 3"));
    }

    #[test]
    fn test_markdown_uncovered_lines_table() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 2);
        let md = render_markdown(&report, 10);

        assert!(md.contains("### Uncovered Lines"));
        assert!(md.contains("| File | Line | Hits |"));
        assert!(md.contains("| src/lib.rs | 1 | 0 |"));
        assert!(md.contains("| src/lib.rs | 2 | 0 |"));
    }

    #[test]
    fn test_markdown_no_uncovered_lines_table_when_empty() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let md = render_markdown(&report, 10);

        // Table header should not be present when there are no findings
        assert!(!md.contains("### Uncovered Lines"));
        assert!(!md.contains("| File | Line | Hits |"));
    }

    #[test]
    fn test_markdown_truncation() {
        let findings: Vec<_> = (1..=15)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 15);
        let md = render_markdown(&report, 10);

        // Should only show 10 lines
        assert!(md.contains("| src/lib.rs | 10 | 0 |"));
        assert!(!md.contains("| src/lib.rs | 11 | 0 |"));

        // Should show truncation message
        assert!(md.contains("*Showing 10 of 15 uncovered lines*"));
    }

    #[test]
    fn test_markdown_no_truncation_message_when_under_limit() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 2);
        let md = render_markdown(&report, 10);

        // Should not show truncation message
        assert!(!md.contains("*Showing"));
    }

    #[test]
    fn test_markdown_reproduce_section_with_diff_file() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let md = render_markdown(&report, 10);

        assert!(md.contains("<details>"));
        assert!(md.contains("<summary>Reproduce locally</summary>"));
        assert!(md.contains("covguard check"));
        assert!(md.contains("--diff-file fixtures/diff/simple_added.patch"));
        assert!(md.contains("--lcov fixtures/lcov/uncovered.info"));
        assert!(md.contains("</details>"));
    }

    #[test]
    fn test_markdown_reproduce_section_with_git_refs() {
        let mut report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        report.data.inputs.diff_file = None;
        report.data.inputs.diff_source = "git-refs".to_string();
        report.data.inputs.base = Some("abc123".to_string());
        report.data.inputs.head = Some("def456".to_string());

        let md = render_markdown(&report, 10);

        assert!(md.contains("--base abc123"));
        assert!(md.contains("--head def456"));
    }

    #[test]
    fn test_markdown_reproduce_section_placeholder_when_no_inputs() {
        let mut report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        report.data.inputs.diff_file = None;
        report.data.inputs.lcov_paths = vec![];

        let md = render_markdown(&report, 10);

        assert!(md.contains("--diff-file <file>"));
        assert!(md.contains("--lcov <lcov>"));
    }

    #[test]
    fn test_markdown_output_format() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 2, 1);
        let md = render_markdown(&report, 10);

        // Check overall structure
        let expected_sections = [
            "## covguard: Diff Coverage Report",
            "**Status**:",
            "### Summary",
            "### Uncovered Lines",
            "<details>",
            "</details>",
        ];

        for section in expected_sections {
            assert!(
                md.contains(section),
                "Missing section: {}\nActual output:\n{}",
                section,
                md
            );
        }
    }

    // ========================================================================
    // render_annotations tests
    // ========================================================================

    #[test]
    fn test_annotations_error_level() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 42, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let annotations = render_annotations(&report, 25);

        assert!(
            annotations
                .contains("::error file=src/lib.rs,line=42::Uncovered changed line (hits=0)")
        );
    }

    #[test]
    fn test_annotations_warning_level() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 42, 0);
        finding.severity = Severity::Warn;

        let report = make_test_report(VerdictStatus::Warn, vec![finding], 0, 1);
        let annotations = render_annotations(&report, 25);

        assert!(annotations.contains("::warning file=src/lib.rs,line=42::"));
    }

    #[test]
    fn test_annotations_info_level() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 42, 0);
        finding.severity = Severity::Info;

        let report = make_test_report(VerdictStatus::Pass, vec![finding], 0, 1);
        let annotations = render_annotations(&report, 25);

        assert!(annotations.contains("::notice file=src/lib.rs,line=42::"));
    }

    #[test]
    fn test_annotations_multiple_findings() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/main.rs", 10, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let annotations = render_annotations(&report, 25);

        let lines: Vec<_> = annotations.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("src/lib.rs,line=1"));
        assert!(lines[1].contains("src/lib.rs,line=2"));
        assert!(lines[2].contains("src/main.rs,line=10"));
    }

    #[test]
    fn test_annotations_truncation() {
        let findings: Vec<_> = (1..=30)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 30);
        let annotations = render_annotations(&report, 25);

        let lines: Vec<_> = annotations.lines().collect();
        assert_eq!(lines.len(), 25);
        assert!(lines.last().unwrap().contains("line=25"));
    }

    #[test]
    fn test_annotations_empty_when_no_findings() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let annotations = render_annotations(&report, 25);

        assert!(annotations.is_empty());
    }

    #[test]
    fn test_annotations_skip_findings_without_location() {
        let finding_without_location = Finding {
            severity: Severity::Error,
            check_id: "diff.coverage_below_threshold".to_string(),
            code: "covguard.diff.coverage_below_threshold".to_string(),
            message: "Coverage below threshold".to_string(),
            location: None,
            data: None,
            fingerprint: None,
        };

        let findings = vec![
            finding_without_location,
            Finding::uncovered_line("src/lib.rs", 1, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let annotations = render_annotations(&report, 25);

        let lines: Vec<_> = annotations.lines().collect();
        // Should only have one annotation (the one with location)
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("src/lib.rs,line=1"));
    }

    #[test]
    fn test_annotations_with_column() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 42, 0);
        finding.location.as_mut().unwrap().col = Some(10);

        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let annotations = render_annotations(&report, 25);

        assert!(annotations.contains("file=src/lib.rs,line=42,col=10"));
    }

    #[test]
    fn test_annotations_format_correctness() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let annotations = render_annotations(&report, 25);

        // GitHub annotation format: ::level file=path,line=num::message
        let line = annotations.lines().next().unwrap();
        assert!(line.starts_with("::error "));
        assert!(line.contains("file="));
        assert!(line.contains("line="));
        assert!(line.contains("::Uncovered changed line"));
    }

    // ========================================================================
    // Integration-style tests
    // ========================================================================

    #[test]
    fn test_full_report_rendering() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/lib.rs", 3, 0),
        ];

        let report = Report {
            schema: "covguard.report.v1".to_string(),
            tool: Tool {
                name: "covguard".to_string(),
                version: "0.1.0".to_string(),
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
            findings,
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

        let md = render_markdown(&report, 10);
        let annotations = render_annotations(&report, 25);

        // Verify markdown
        assert!(md.contains("## covguard: Diff Coverage Report"));
        assert!(md.contains("**Status**: \u{274C} fail"));
        assert!(md.contains("- **Diff coverage**: 0.0%"));
        assert!(md.contains("- **Changed lines**: 3"));
        assert!(md.contains("- **Uncovered**: 3"));
        assert!(md.contains("| src/lib.rs | 1 | 0 |"));
        assert!(md.contains("| src/lib.rs | 2 | 0 |"));
        assert!(md.contains("| src/lib.rs | 3 | 0 |"));

        // Verify annotations
        let ann_lines: Vec<_> = annotations.lines().collect();
        assert_eq!(ann_lines.len(), 3);
        assert!(ann_lines.iter().all(|l| l.starts_with("::error ")));
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_MAX_LINES, 10);
        assert_eq!(DEFAULT_MAX_ANNOTATIONS, 25);
        assert_eq!(DEFAULT_MAX_SARIF_RESULTS, 1000);
    }

    // ========================================================================
    // SARIF tests
    // ========================================================================

    #[test]
    fn test_sarif_basic_structure() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let sarif = render_sarif(&report, 1000);

        // Parse as JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert!(
            parsed["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );
        assert_eq!(parsed["runs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_sarif_tool_info() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let driver = &parsed["runs"][0]["tool"]["driver"];

        assert_eq!(driver["name"], "covguard");
        assert_eq!(driver["version"], "0.1.0");
        assert!(driver["informationUri"].as_str().is_some());
    }

    #[test]
    fn test_sarif_rules() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        // Should have a rule for each code
        assert_eq!(rules.len(), CODE_REGISTRY.len());

        // Check uncovered_line rule
        let rule = &rules[0];
        assert_eq!(rule["id"], "covguard.diff.uncovered_line");
        assert_eq!(rule["name"], "UncoveredLine");
        assert!(rule["shortDescription"]["text"].as_str().is_some());
        assert!(rule["helpUri"].as_str().is_some());
    }

    #[test]
    fn test_sarif_results_with_findings() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/main.rs", 10, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results.len(), 3);

        // Check first result
        let result = &results[0];
        assert_eq!(result["ruleId"], "covguard.diff.uncovered_line");
        assert_eq!(result["level"], "error");
        assert!(result["message"]["text"].as_str().is_some());

        // Check location
        let loc = &result["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/lib.rs");
        assert_eq!(loc["region"]["startLine"], 1);
    }

    #[test]
    fn test_sarif_empty_when_no_findings() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_sarif_truncation() {
        // Create 15 findings
        let findings: Vec<_> = (1..=15)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 15);

        // Limit to 10 results
        let sarif = render_sarif(&report, 10);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        // Should only have 10 results
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_sarif_severity_levels() {
        let mut error_finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        error_finding.severity = Severity::Error;

        let mut warn_finding = Finding::uncovered_line("src/lib.rs", 2, 0);
        warn_finding.severity = Severity::Warn;

        let mut info_finding = Finding::uncovered_line("src/lib.rs", 3, 0);
        info_finding.severity = Severity::Info;

        let findings = vec![error_finding, warn_finding, info_finding];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn test_sarif_finding_without_location() {
        let finding_without_location = Finding {
            severity: Severity::Error,
            check_id: "diff.coverage_below_threshold".to_string(),
            code: "covguard.diff.coverage_below_threshold".to_string(),
            message: "Coverage 50% is below threshold 80%".to_string(),
            location: None,
            data: None,
            fingerprint: None,
        };

        let findings = vec![
            finding_without_location,
            Finding::uncovered_line("src/lib.rs", 1, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let sarif = render_sarif(&report, 1000);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        // Both findings should be included (one without location, one with)
        assert_eq!(results.len(), 2);

        // First result (coverage_below_threshold) should have empty locations
        assert!(results[0]["locations"].as_array().unwrap().is_empty());

        // Second result should have a location
        assert_eq!(results[1]["locations"].as_array().unwrap().len(), 1);
    }

    // ========================================================================
    // Insta Snapshot Tests
    // ========================================================================

    #[test]
    fn test_snapshot_markdown_fail() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/lib.rs", 3, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let md = render_markdown(&report, 10);
        insta::assert_snapshot!("markdown_fail", md);
    }

    #[test]
    fn test_snapshot_markdown_pass() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 3, 0);
        let md = render_markdown(&report, 10);
        insta::assert_snapshot!("markdown_pass", md);
    }

    #[test]
    fn test_snapshot_markdown_warn() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        finding.severity = Severity::Warn;
        let report = make_test_report(VerdictStatus::Warn, vec![finding], 2, 1);
        let md = render_markdown(&report, 10);
        insta::assert_snapshot!("markdown_warn", md);
    }

    #[test]
    fn test_snapshot_markdown_truncated() {
        let findings: Vec<_> = (1..=15)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 15);
        let md = render_markdown(&report, 10);
        insta::assert_snapshot!("markdown_truncated", md);
    }

    #[test]
    fn test_snapshot_annotations_multiple() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/main.rs", 10, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let annotations = render_annotations(&report, 25);
        insta::assert_snapshot!("annotations_multiple", annotations);
    }

    #[test]
    fn test_snapshot_annotations_empty() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let annotations = render_annotations(&report, 25);
        insta::assert_snapshot!("annotations_empty", annotations);
    }

    #[test]
    fn test_snapshot_sarif_with_findings() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
            Finding::uncovered_line("src/main.rs", 10, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let sarif = render_sarif(&report, 1000);
        let sarif_value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        insta::assert_json_snapshot!("sarif_with_findings", sarif_value);
    }

    #[test]
    fn test_snapshot_sarif_empty() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);
        let sarif_value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        insta::assert_json_snapshot!("sarif_empty", sarif_value);
    }

    #[test]
    fn test_snapshot_sarif_mixed_severity() {
        let mut error_finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        error_finding.severity = Severity::Error;

        let mut warn_finding = Finding::uncovered_line("src/lib.rs", 2, 0);
        warn_finding.severity = Severity::Warn;

        let mut info_finding = Finding::uncovered_line("src/lib.rs", 3, 0);
        info_finding.severity = Severity::Info;

        let findings = vec![error_finding, warn_finding, info_finding];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 3);
        let sarif = render_sarif(&report, 1000);
        let sarif_value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        insta::assert_json_snapshot!("sarif_mixed_severity", sarif_value);
    }

    // ========================================================================
    // Semantic Validation Tests - Markdown
    // ========================================================================

    #[test]
    fn test_markdown_table_row_count_matches_findings() {
        let findings: Vec<_> = (1..=5)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 5);
        let md = render_markdown(&report, 100);

        // Count table rows (excluding header and separator)
        let table_rows: Vec<_> = md.lines().filter(|l| l.starts_with("| src/")).collect();
        assert_eq!(table_rows.len(), 5);
    }

    #[test]
    fn test_markdown_coverage_percentage_precision() {
        let mut report = make_test_report(VerdictStatus::Fail, vec![], 1, 2);
        report.data.diff_coverage_pct = 33.333333333;
        let md = render_markdown(&report, 10);

        // Should format to one decimal place
        assert!(md.contains("33.3%"));
        assert!(!md.contains("33.333333333"));
    }

    #[test]
    fn test_markdown_100_percent_coverage_display() {
        let mut report = make_test_report(VerdictStatus::Pass, vec![], 10, 0);
        report.data.diff_coverage_pct = 100.0;
        let md = render_markdown(&report, 10);

        assert!(md.contains("100.0%"));
    }

    #[test]
    fn test_markdown_zero_percent_coverage_display() {
        let mut report = make_test_report(VerdictStatus::Fail, vec![], 0, 10);
        report.data.diff_coverage_pct = 0.0;
        let md = render_markdown(&report, 10);

        assert!(md.contains("0.0%"));
    }

    #[test]
    fn test_markdown_table_alignment() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let md = render_markdown(&report, 10);

        // Verify table separator has correct format
        assert!(md.contains("|------|------|------|"));
    }

    #[test]
    fn test_markdown_hits_value_displayed() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        finding.data = Some(serde_json::json!({ "hits": 42 }));
        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        // Table should show the hits value
        assert!(md.contains("| 42 |"));
    }

    #[test]
    fn test_markdown_multiple_lcov_paths_in_reproduce() {
        let mut report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        report.data.inputs.lcov_paths =
            vec!["unit.info".to_string(), "integration.info".to_string()];
        let md = render_markdown(&report, 10);

        assert!(md.contains("--lcov unit.info"));
        assert!(md.contains("--lcov integration.info"));
    }

    #[test]
    fn test_markdown_unicode_in_file_path() {
        let finding = Finding::uncovered_line("src/日本語/テスト.rs", 1, 0);
        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        assert!(md.contains("src/日本語/テスト.rs"));
    }

    #[test]
    fn test_markdown_special_characters_in_path() {
        let finding = Finding::uncovered_line("src/path with spaces/file.rs", 1, 0);
        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        assert!(md.contains("path with spaces"));
    }

    #[test]
    fn test_markdown_sections_in_order() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 2, 1);
        let md = render_markdown(&report, 10);

        let header_pos = md.find("## covguard: Diff Coverage Report").unwrap();
        let status_pos = md.find("**Status**").unwrap();
        let summary_pos = md.find("### Summary").unwrap();
        let uncovered_pos = md.find("### Uncovered Lines").unwrap();
        let details_pos = md.find("<details>").unwrap();

        assert!(header_pos < status_pos);
        assert!(status_pos < summary_pos);
        assert!(summary_pos < uncovered_pos);
        assert!(uncovered_pos < details_pos);
    }

    // ========================================================================
    // Semantic Validation Tests - Annotations
    // ========================================================================

    #[test]
    fn test_annotations_format_github_valid() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 42, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let annotations = render_annotations(&report, 25);

        // GitHub annotation format: ::level file=path,line=num::message
        let line = annotations.lines().next().unwrap();

        // Must start with ::
        assert!(line.starts_with("::"));

        // Must have level (error, warning, notice)
        assert!(
            line.starts_with("::error ")
                || line.starts_with("::warning ")
                || line.starts_with("::notice ")
        );

        // Must have file= parameter
        assert!(line.contains("file="));

        // Must have double colon before message
        let parts: Vec<_> = line.split("::").collect();
        assert!(parts.len() >= 3);
    }

    #[test]
    fn test_annotations_each_on_separate_line() {
        let findings: Vec<_> = (1..=5)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 5);
        let annotations = render_annotations(&report, 25);

        let lines: Vec<_> = annotations.lines().collect();
        assert_eq!(lines.len(), 5);

        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("line={}", i + 1)));
        }
    }

    #[test]
    fn test_annotations_severity_mapping() {
        let mut error_finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        error_finding.severity = Severity::Error;

        let mut warn_finding = Finding::uncovered_line("src/lib.rs", 2, 0);
        warn_finding.severity = Severity::Warn;

        let mut info_finding = Finding::uncovered_line("src/lib.rs", 3, 0);
        info_finding.severity = Severity::Info;

        let report = make_test_report(
            VerdictStatus::Fail,
            vec![error_finding, warn_finding, info_finding],
            0,
            3,
        );
        let annotations = render_annotations(&report, 25);
        let lines: Vec<_> = annotations.lines().collect();

        assert!(lines[0].starts_with("::error "));
        assert!(lines[1].starts_with("::warning "));
        assert!(lines[2].starts_with("::notice "));
    }

    #[test]
    fn test_annotations_no_trailing_whitespace() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let annotations = render_annotations(&report, 25);

        for line in annotations.lines() {
            assert!(
                !line.ends_with(' '),
                "Line should not end with whitespace: {:?}",
                line
            );
        }
    }

    // ========================================================================
    // Semantic Validation Tests - SARIF
    // ========================================================================

    #[test]
    fn test_sarif_valid_json() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let sarif = render_sarif(&report, 1000);

        // Must be valid JSON
        let result: Result<serde_json::Value, _> = serde_json::from_str(&sarif);
        assert!(result.is_ok(), "SARIF output must be valid JSON");
    }

    #[test]
    fn test_sarif_version_is_2_1_0() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn test_sarif_schema_uri_valid() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let schema = parsed["$schema"].as_str().unwrap();
        assert!(schema.contains("sarif-schema-2.1.0"));
        assert!(schema.starts_with("https://"));
    }

    #[test]
    fn test_sarif_has_exactly_one_run() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let runs = parsed["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn test_sarif_rule_index_matches_findings() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 2);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        for result in results {
            let rule_id = result["ruleId"].as_str().unwrap();
            let rule_index = result["ruleIndex"].as_u64().unwrap() as usize;

            // Verify rule_index points to correct rule
            assert!(rule_index < rules.len());
            assert_eq!(rules[rule_index]["id"], rule_id);
        }
    }

    #[test]
    fn test_sarif_location_uri_is_relative() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let uri =
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .unwrap();

        // URI should be relative (not absolute)
        assert!(!uri.starts_with('/'));
        assert!(!uri.contains(":\\"));
    }

    #[test]
    fn test_sarif_uri_base_id_is_srcroot() {
        let findings = vec![Finding::uncovered_line("src/lib.rs", 1, 0)];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 1);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let uri_base_id =
            parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uriBaseId"]
                .as_str()
                .unwrap();

        assert_eq!(uri_base_id, "%SRCROOT%");
    }

    #[test]
    fn test_sarif_start_line_is_positive() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 100, 0),
        ];
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 2);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        for result in results {
            if let Some(locations) = result["locations"].as_array() {
                for loc in locations {
                    if let Some(region) = loc["physicalLocation"].get("region") {
                        let start_line = region["startLine"].as_u64().unwrap();
                        assert!(start_line > 0, "startLine must be positive");
                    }
                }
            }
        }
    }

    #[test]
    fn test_sarif_level_is_valid() {
        let mut error_finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        error_finding.severity = Severity::Error;

        let mut warn_finding = Finding::uncovered_line("src/lib.rs", 2, 0);
        warn_finding.severity = Severity::Warn;

        let mut info_finding = Finding::uncovered_line("src/lib.rs", 3, 0);
        info_finding.severity = Severity::Info;

        let report = make_test_report(
            VerdictStatus::Fail,
            vec![error_finding, warn_finding, info_finding],
            0,
            3,
        );
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        let valid_levels = ["error", "warning", "note", "none"];

        for result in results {
            let level = result["level"].as_str().unwrap();
            assert!(
                valid_levels.contains(&level),
                "Invalid SARIF level: {}",
                level
            );
        }
    }

    #[test]
    fn test_sarif_rules_have_required_fields() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 5, 0);
        let sarif = render_sarif(&report, 1000);
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();

        for rule in rules {
            // Required fields per SARIF spec
            assert!(rule.get("id").is_some(), "Rule must have id");
            assert!(rule.get("shortDescription").is_some());
            assert!(rule["shortDescription"].get("text").is_some());
        }
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_markdown_with_very_long_path() {
        let long_path = format!("src/{}/lib.rs", "very_long_directory_name".repeat(10));
        let finding = Finding::uncovered_line(&long_path, 1, 0);
        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        // Should still contain the full path
        assert!(md.contains(&long_path));
    }

    #[test]
    fn test_markdown_max_lines_zero() {
        let findings: Vec<_> = (1..=5)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 5);
        let md = render_markdown(&report, 0);

        // Table header should still be present but no data rows
        assert!(md.contains("| File | Line | Hits |"));
        assert!(md.contains("*Showing 0 of 5 uncovered lines*"));
    }

    #[test]
    fn test_annotations_max_annotations_zero() {
        let findings: Vec<_> = (1..=5)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 5);
        let annotations = render_annotations(&report, 0);

        assert!(annotations.is_empty());
    }

    #[test]
    fn test_sarif_max_results_zero() {
        let findings: Vec<_> = (1..=5)
            .map(|i| Finding::uncovered_line("src/lib.rs", i, 0))
            .collect();
        let report = make_test_report(VerdictStatus::Fail, findings, 0, 5);
        let sarif = render_sarif(&report, 0);

        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_markdown_line_without_number() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        finding.location.as_mut().unwrap().line = None;

        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        // Should show "-" for missing line number
        assert!(md.contains("| - |"));
    }

    #[test]
    fn test_markdown_finding_without_data() {
        let mut finding = Finding::uncovered_line("src/lib.rs", 1, 0);
        finding.data = None;

        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let md = render_markdown(&report, 10);

        // Should show 0 for missing hits data
        assert!(md.contains("| 0 |"));
    }
}
