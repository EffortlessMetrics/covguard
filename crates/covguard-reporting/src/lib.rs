//! Report assembly and schema composition for covguard.

pub use covguard_reporting_core::{
    build_error_report_pair, build_reasons, build_report, build_report_pair,
    build_skip_report_pair, finding_counts, is_invalid_diff, report_run,
};
pub use covguard_reporting_types::ReportContext;

pub fn build_debug(binary_files: &[String]) -> Option<serde_json::Value> {
    if binary_files.is_empty() {
        None
    } else {
        Some(serde_json::json!({
            "binary_files_count": binary_files.len(),
            "binary_files": binary_files,
        }))
    }
}

pub mod debug {
    pub use covguard_reporting_core::finding_counts;
}
