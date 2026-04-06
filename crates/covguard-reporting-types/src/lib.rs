//! Shared types for covguard reporting.

use covguard_types::{Inputs, Scope};

/// Context needed to materialize reports from `EvalOutput`.
#[derive(Debug, Clone)]
pub struct ReportContext {
    /// Coverage threshold used for the run.
    pub threshold_pct: f64,
    /// Evaluation scope (`added` or `touched`).
    pub scope: Scope,
    /// Emit `sensor.report.v1` with capability metadata.
    pub sensor_schema: bool,
    /// Optional findings cap for standard-mode reports.
    pub max_findings: Option<usize>,
    /// Path to a diff file, if available.
    pub diff_file_path: Option<String>,
    /// Base ref in git-diff mode.
    pub base_ref: Option<String>,
    /// Head ref in git-diff mode.
    pub head_ref: Option<String>,
    /// LCOV paths to include in report metadata.
    pub lcov_paths: Vec<String>,
}

impl ReportContext {
    pub fn diff_source(&self) -> &'static str {
        if self.diff_file_path.is_some() {
            "diff-file"
        } else if self.base_ref.is_some() && self.head_ref.is_some() {
            "git-refs"
        } else {
            "stdin"
        }
    }

    pub fn scope_str(&self) -> &str {
        self.scope.as_str()
    }

    pub fn inputs(&self) -> Inputs {
        Inputs {
            diff_source: self.diff_source().to_string(),
            diff_file: self.diff_file_path.clone(),
            base: self.base_ref.clone(),
            head: self.head_ref.clone(),
            lcov_paths: self.lcov_paths.clone(),
        }
    }
}
