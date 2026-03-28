//! GitHub workflow annotations renderer for covguard reports.

use covguard_types::{Report, Severity};

/// Default maximum number of GitHub annotations to emit.
pub const DEFAULT_MAX_ANNOTATIONS: usize = 25;

/// Renders the report as GitHub workflow annotation commands.
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
