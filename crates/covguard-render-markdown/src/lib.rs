//! Markdown renderer for covguard reports.

use covguard_types::{Report, VerdictStatus};

/// Default maximum number of lines to show in markdown table.
pub const DEFAULT_MAX_LINES: usize = 10;

/// Returns an emoji representing the verdict status.
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
            let location = finding
                .location
                .as_ref()
                .expect("filtered to only findings with locations");
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
