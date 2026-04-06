//! Rendering utilities for covguard reports.
//!
//! This crate provides a unified facade for various renderers:
//! - Markdown for PR comments (via `covguard-render-markdown`)
//! - GitHub workflow annotation commands (via `covguard-render-annotations`)
//! - SARIF output (via `covguard-render-sarif`)

pub use covguard_render_annotations::{DEFAULT_MAX_ANNOTATIONS, render_annotations};
pub use covguard_render_markdown::{DEFAULT_MAX_LINES, render_markdown, status_emoji};
pub use covguard_render_sarif::{DEFAULT_MAX_SARIF_RESULTS, render_sarif};

// Re-export constants with names used by orchestrator if they differ
pub const DEFAULT_MAX_SARIF_RESULTS_FACADE: usize = DEFAULT_MAX_SARIF_RESULTS;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_types::{
        Finding, Inputs, Report, ReportData, Run, Severity, Tool, Verdict, VerdictCounts,
        VerdictStatus,
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
                ended_at: Some("2026-02-02T00:00:01Z".to_string()),
                duration_ms: Some(0),
                capabilities: None,
            },
            verdict: Verdict {
                status,
                counts: VerdictCounts {
                    error: 0,
                    warn: 0,
                    info: 0,
                },
                reasons: vec!["test".to_string()],
            },
            data: ReportData {
                scope: "added".to_string(),
                threshold_pct: 80.0,
                diff_coverage_pct: if covered + uncovered > 0 {
                    (covered as f64 / (covered + uncovered) as f64) * 100.0
                } else {
                    100.0
                },
                changed_lines_total: covered + uncovered,
                covered_lines: covered,
                uncovered_lines: uncovered,
                missing_lines: 0,
                ignored_lines_count: 0,
                excluded_files_count: 0,
                inputs: Inputs {
                    diff_source: "diff-file".to_string(),
                    diff_file: Some("test.patch".to_string()),
                    base: None,
                    head: None,
                    lcov_paths: vec!["lcov.info".to_string()],
                },
                debug: None,
                truncation: None,
            },
            findings,
        }
    }

    #[test]
    fn test_render_markdown_basic() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 10, 0);
        let md = render_markdown(&report, 10);
        assert!(md.contains("## covguard: Diff Coverage Report"));
        assert!(md.contains("Status**: \u{2705} pass"));
        assert!(md.contains("Diff coverage**: 100.0%"));
    }

    #[test]
    fn test_render_annotations_basic() {
        let finding = Finding {
            check_id: "diff.uncovered_line".to_string(),
            code: "covguard.diff.uncovered_line".to_string(),
            message: "Uncovered changed line (hits=0)".to_string(),
            severity: Severity::Error,
            location: Some(covguard_types::Location {
                path: "src/lib.rs".to_string(),
                line: Some(10),
                col: None,
            }),
            data: None,
            fingerprint: None,
        };
        let report = make_test_report(VerdictStatus::Fail, vec![finding], 0, 1);
        let annotations = render_annotations(&report, 10);
        assert!(
            annotations
                .contains("::error file=src/lib.rs,line=10::Uncovered changed line (hits=0)")
        );
    }

    #[test]
    fn test_render_sarif_basic() {
        let report = make_test_report(VerdictStatus::Pass, vec![], 10, 0);
        let sarif = render_sarif(&report, 1000);
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("\"name\": \"covguard\""));
    }
}
