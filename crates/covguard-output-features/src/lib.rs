//! Shared output feature-flag contracts for covguard rendering.
//!
//! This crate is intentionally tiny so it can be used as a stable interoperability
//! boundary by callers that only need output budget configuration.

use serde::{Deserialize, Serialize};

use covguard_render::{DEFAULT_MAX_ANNOTATIONS, DEFAULT_MAX_LINES, DEFAULT_MAX_SARIF_RESULTS};
use covguard_types::Truncation;

/// Partial output configuration from external sources (config / CLI overrides).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputFeatureConfig {
    /// Optional maximum number of uncovered lines rendered in markdown.
    #[serde(default)]
    pub max_markdown_lines: Option<usize>,
    /// Optional maximum number of GitHub annotations to emit.
    #[serde(default)]
    pub max_annotations: Option<usize>,
    /// Optional maximum number of SARIF results to emit.
    #[serde(default)]
    pub max_sarif_results: Option<usize>,
}

impl OutputFeatureConfig {
    /// Materialize this partial configuration over base flags.
    pub fn materialize(self, base: OutputFeatureFlags) -> OutputFeatureFlags {
        OutputFeatureFlags {
            max_markdown_lines: self.max_markdown_lines.unwrap_or(base.max_markdown_lines),
            max_annotations: self.max_annotations.unwrap_or(base.max_annotations),
            max_sarif_results: self.max_sarif_results.unwrap_or(base.max_sarif_results),
        }
    }
}

/// Domain-level feature flags for rendering output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFeatureFlags {
    /// Maximum number of uncovered lines rendered in markdown.
    pub max_markdown_lines: usize,
    /// Maximum number of GitHub annotations to emit.
    pub max_annotations: usize,
    /// Maximum number of SARIF results to emit.
    pub max_sarif_results: usize,
}

impl Default for OutputFeatureFlags {
    fn default() -> Self {
        Self {
            max_markdown_lines: DEFAULT_MAX_LINES,
            max_annotations: DEFAULT_MAX_ANNOTATIONS,
            max_sarif_results: DEFAULT_MAX_SARIF_RESULTS,
        }
    }
}

/// Backward-compatible constant aliases for output budgets.
pub const DEFAULT_ANNOTATION_LIMIT: usize = DEFAULT_MAX_ANNOTATIONS;
pub const DEFAULT_MARKDOWN_LINES: usize = DEFAULT_MAX_LINES;
pub const DEFAULT_SARIF_RESULTS: usize = DEFAULT_MAX_SARIF_RESULTS;

/// Truncate findings with optional max cap and return truncation metadata.
pub fn truncate_findings<T>(
    findings: Vec<T>,
    max: Option<usize>,
) -> (Vec<T>, Option<Truncation>) {
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
