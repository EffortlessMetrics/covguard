//! Output rendering utilities and feature flags for covguard reports.
//!
//! This crate centralizes report rendering defaults and renderer budget flags.
//! Feature contracts are delegated to `covguard-output-features`.

use covguard_render::{
    render_annotations as render_annotations_impl, render_markdown as render_markdown_impl,
    render_sarif as render_sarif_impl,
};
use covguard_types::Report;

pub use covguard_output_features::{
    DEFAULT_ANNOTATION_LIMIT, DEFAULT_MARKDOWN_LINES, DEFAULT_SARIF_RESULTS, OutputFeatureConfig,
    OutputFeatureFlags, truncate_findings,
};

/// Backward-compatible markdown renderer with project-wide default limit.
pub fn render_markdown(report: &Report) -> String {
    render_markdown_with_limit(report, DEFAULT_MARKDOWN_LINES)
}

/// Markdown renderer with configurable budget.
pub fn render_markdown_with_limit(report: &Report, max_lines: usize) -> String {
    render_markdown_impl(report, max_lines)
}

/// Backward-compatible annotation renderer with project-wide default limit.
pub fn render_annotations(report: &Report) -> String {
    render_annotations_with_limit(report, DEFAULT_ANNOTATION_LIMIT)
}

/// Annotation renderer with configurable budget.
pub fn render_annotations_with_limit(report: &Report, max_annotations: usize) -> String {
    render_annotations_impl(report, max_annotations)
}

/// Backward-compatible SARIF renderer with project-wide default limit.
pub fn render_sarif(report: &Report) -> String {
    render_sarif_with_limit(report, DEFAULT_SARIF_RESULTS)
}

/// SARIF renderer with configurable budget.
pub fn render_sarif_with_limit(report: &Report, max_results: usize) -> String {
    render_sarif_impl(report, max_results)
}

/// Render all output formats using an explicit flag set.
pub fn render_all(report: &Report, flags: &OutputFeatureFlags) -> (String, String, String) {
    (
        render_markdown_with_limit(report, flags.max_markdown_lines),
        render_annotations_with_limit(report, flags.max_annotations),
        render_sarif_with_limit(report, flags.max_sarif_results),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_types::Finding;

    #[test]
    fn test_default_feature_flags() {
        let flags = OutputFeatureFlags::default();
        assert_eq!(flags.max_markdown_lines, DEFAULT_MARKDOWN_LINES);
        assert_eq!(flags.max_annotations, DEFAULT_ANNOTATION_LIMIT);
        assert_eq!(flags.max_sarif_results, DEFAULT_SARIF_RESULTS);
    }

    #[test]
    fn test_output_feature_config_materializes_defaults() {
        let base = OutputFeatureFlags::default();
        let config = OutputFeatureConfig {
            max_markdown_lines: Some(3),
            max_annotations: None,
            max_sarif_results: Some(5),
        };
        let materialized = config.materialize(base);

        assert_eq!(materialized.max_markdown_lines, 3);
        assert_eq!(materialized.max_annotations, DEFAULT_ANNOTATION_LIMIT);
        assert_eq!(materialized.max_sarif_results, 5);
    }

    #[test]
    fn test_output_feature_config_full_passthrough() {
        let base = OutputFeatureFlags::default();
        let config = OutputFeatureConfig {
            max_markdown_lines: Some(11),
            max_annotations: Some(22),
            max_sarif_results: Some(33),
        };
        let materialized = config.materialize(base);

        assert_eq!(materialized.max_markdown_lines, 11);
        assert_eq!(materialized.max_annotations, 22);
        assert_eq!(materialized.max_sarif_results, 33);
    }

    #[test]
    fn test_truncate_findings_caps_results() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
        ];
        let (truncated, trunc) = truncate_findings(findings.clone(), Some(1));

        assert_eq!(truncated.len(), 1);
        assert!(trunc.is_some());
        let trunc = trunc.expect("truncation metadata");
        assert!(trunc.findings_truncated);
        assert_eq!(trunc.shown, 1);
        assert_eq!(trunc.total, findings.len() as u32);
    }

    #[test]
    fn test_truncate_findings_passthrough_when_under_limit() {
        let findings = vec![
            Finding::uncovered_line("src/lib.rs", 1, 0),
            Finding::uncovered_line("src/lib.rs", 2, 0),
        ];
        let (truncated, trunc) = truncate_findings(findings.clone(), Some(5));

        assert_eq!(truncated.len(), findings.len());
        assert!(trunc.is_none());
    }
}
