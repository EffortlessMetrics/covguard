//! Pure domain evaluation logic for covguard.
//!
//! This crate implements the core policy evaluation with no side effects.
//! It takes changed line ranges and coverage data, applies a policy,
//! and produces findings with a verdict.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use covguard_types::{
    CODE_COVERAGE_BELOW_THRESHOLD, CODE_MISSING_COVERAGE_FOR_FILE, CODE_UNCOVERED_LINE, Finding,
    Location, Severity, VerdictStatus, compute_fingerprint,
};

// ============================================================================
// Policy Configuration
// ============================================================================

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

/// How to handle missing coverage data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingBehavior {
    /// Skip missing coverage (do not count toward percentage, no findings).
    Skip,
    /// Warn on missing coverage.
    #[default]
    Warn,
    /// Fail on missing coverage.
    Fail,
}

/// Scope of lines to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Scope {
    /// Only evaluate added lines.
    #[default]
    Added,
    /// Evaluate all touched (added + modified) lines.
    Touched,
}

impl Scope {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Added => "added",
            Scope::Touched => "touched",
        }
    }
}

/// Policy configuration for coverage evaluation.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Scope of lines to evaluate.
    pub scope: Scope,
    /// Minimum diff coverage percentage threshold.
    pub threshold_pct: f64,
    /// Maximum allowed uncovered lines (optional).
    pub max_uncovered_lines: Option<u32>,
    /// How to handle missing coverage lines in files with coverage data.
    pub missing_coverage: MissingBehavior,
    /// How to handle files with no coverage data at all.
    pub missing_file: MissingBehavior,
    /// Determines when the evaluation should fail.
    pub fail_on: FailOn,
    /// Whether to honor `covguard: ignore` directives in source comments.
    pub ignore_directives_enabled: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            scope: Scope::Added,
            threshold_pct: 80.0,
            max_uncovered_lines: None,
            fail_on: FailOn::Error,
            missing_coverage: MissingBehavior::Warn,
            missing_file: MissingBehavior::Warn,
            ignore_directives_enabled: true,
        }
    }
}

// ============================================================================
// Evaluation Input/Output
// ============================================================================

/// Input for policy evaluation.
#[derive(Debug, Clone)]
pub struct EvalInput {
    /// Changed line ranges per file (repo-relative paths).
    /// Key: file path, Value: list of inclusive line ranges.
    pub changed_ranges: BTreeMap<String, Vec<RangeInclusive<u32>>>,
    /// Coverage data per file.
    /// Key: file path, Value: map of line number to hit count.
    pub coverage: BTreeMap<String, BTreeMap<u32, u32>>,
    /// Policy configuration.
    pub policy: Policy,
    /// Lines to ignore (from `covguard: ignore` directives).
    /// Key: file path, Value: set of line numbers to skip.
    pub ignored_lines: BTreeMap<String, std::collections::BTreeSet<u32>>,
}

/// Metrics from the evaluation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    /// Total number of changed lines in scope.
    pub changed_lines_total: u32,
    /// Number of covered lines (hits > 0).
    pub covered_lines: u32,
    /// Number of uncovered lines (hits == 0).
    pub uncovered_lines: u32,
    /// Number of lines with missing coverage data (no record).
    pub missing_lines: u32,
    /// Number of lines ignored via `covguard: ignore` directive.
    pub ignored_lines: u32,
    /// Diff coverage percentage.
    pub diff_coverage_pct: f64,
}

/// Output from policy evaluation.
#[derive(Debug, Clone)]
pub struct EvalOutput {
    /// List of findings (sorted deterministically).
    pub findings: Vec<Finding>,
    /// Overall verdict.
    pub verdict: VerdictStatus,
    /// Aggregated metrics.
    pub metrics: Metrics,
}

// ============================================================================
// Evaluation Logic
// ============================================================================

/// Evaluate changed lines against coverage data under the given policy.
///
/// This is the main entry point for policy evaluation. It:
/// 1. Iterates through all changed lines
/// 2. Skips lines with `covguard: ignore` directives (if enabled)
/// 3. Checks coverage status for each line
/// 4. Creates findings for uncovered lines
/// 5. Calculates metrics
/// 6. Determines the verdict
/// 7. Sorts findings deterministically
pub fn evaluate(input: EvalInput) -> EvalOutput {
    let mut findings = Vec::new();
    let mut covered_lines = 0u32;
    let mut uncovered_lines = 0u32;
    let mut missing_lines = 0u32;
    let mut ignored_lines_count = 0u32;
    let mut missing_files: BTreeMap<String, u32> = BTreeMap::new();
    let mut missing_lines_for_pct = 0u32;
    let mut uncovered_details: Vec<(String, u32, u32)> = Vec::new();

    // Evaluate each file
    for (path, ranges) in &input.changed_ranges {
        let file_coverage = input.coverage.get(path);
        let file_ignored = input.ignored_lines.get(path);

        // Process each range
        for range in ranges {
            for line in range.clone() {
                // Check if this line should be ignored
                if input.policy.ignore_directives_enabled
                    && file_ignored.is_some_and(|ignored| ignored.contains(&line))
                {
                    ignored_lines_count += 1;
                    continue;
                }

                match file_coverage {
                    Some(coverage_map) => {
                        match coverage_map.get(&line) {
                            Some(&hits) if hits > 0 => {
                                // Line is covered
                                covered_lines += 1;
                            }
                            Some(&hits) => {
                                // Line is uncovered (hits == 0)
                                uncovered_lines += 1;
                                uncovered_details.push((path.clone(), line, hits));
                            }
                            None => {
                                // No coverage data for this line (missing)
                                missing_lines += 1;
                                if input.policy.missing_coverage != MissingBehavior::Skip {
                                    missing_lines_for_pct += 1;
                                }
                            }
                        }
                    }
                    None => {
                        // No coverage data for this file (missing)
                        missing_lines += 1;
                        if input.policy.missing_file != MissingBehavior::Skip {
                            missing_lines_for_pct += 1;
                        }
                        *missing_files.entry(path.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    let changed_lines_total = covered_lines + uncovered_lines + missing_lines;
    let diff_coverage_pct =
        calc_coverage_pct(covered_lines, uncovered_lines, missing_lines_for_pct);

    let uncovered_severity = match input.policy.max_uncovered_lines {
        Some(max) if uncovered_lines <= max => Severity::Info,
        _ => Severity::Error,
    };

    for (path, line, hits) in uncovered_details {
        let line_str = line.to_string();
        let fp = compute_fingerprint(&[CODE_UNCOVERED_LINE, &path, &line_str]);
        findings.push(Finding {
            severity: uncovered_severity,
            check_id: "diff.uncovered_line".to_string(),
            code: CODE_UNCOVERED_LINE.to_string(),
            message: format!("Uncovered changed line (hits={}).", hits),
            location: Some(Location {
                path,
                line: Some(line),
                col: None,
            }),
            data: Some(serde_json::json!({ "hits": hits })),
            fingerprint: Some(fp),
        });
    }

    // Missing file findings (file-level)
    if input.policy.missing_file != MissingBehavior::Skip {
        let severity = match input.policy.missing_file {
            MissingBehavior::Warn => Severity::Warn,
            MissingBehavior::Fail => Severity::Error,
            MissingBehavior::Skip => Severity::Info,
        };
        for (path, count) in &missing_files {
            let fp = compute_fingerprint(&[CODE_MISSING_COVERAGE_FOR_FILE, path]);
            findings.push(Finding {
                severity,
                check_id: "diff.missing_coverage_for_file".to_string(),
                code: CODE_MISSING_COVERAGE_FOR_FILE.to_string(),
                message: format!(
                    "Missing coverage data for file ({} line(s) without coverage).",
                    count
                ),
                location: Some(Location {
                    path: path.clone(),
                    line: None,
                    col: None,
                }),
                data: Some(serde_json::json!({
                    "missing_lines": count,
                    "missing_file": true
                })),
                fingerprint: Some(fp),
            });
        }
    }

    // Check if below threshold
    if changed_lines_total > 0 && diff_coverage_pct < input.policy.threshold_pct {
        let fp = compute_fingerprint(&[CODE_COVERAGE_BELOW_THRESHOLD, "covguard"]);
        findings.push(Finding {
            severity: Severity::Error,
            check_id: "diff.coverage_below_threshold".to_string(),
            code: CODE_COVERAGE_BELOW_THRESHOLD.to_string(),
            message: format!(
                "Diff coverage {:.1}% is below threshold {:.1}%.",
                diff_coverage_pct, input.policy.threshold_pct
            ),
            location: None,
            data: Some(serde_json::json!({
                "actual_pct": diff_coverage_pct,
                "threshold_pct": input.policy.threshold_pct
            })),
            fingerprint: Some(fp),
        });
    }

    // Sort findings deterministically
    sort_findings(&mut findings);

    // Determine verdict
    let verdict = determine_verdict(&findings, &input.policy);

    let metrics = Metrics {
        changed_lines_total,
        covered_lines,
        uncovered_lines,
        missing_lines,
        ignored_lines: ignored_lines_count,
        diff_coverage_pct,
    };

    EvalOutput {
        findings,
        verdict,
        metrics,
    }
}

/// Calculate coverage percentage.
///
/// Returns 100.0 if there are no lines to evaluate (vacuous truth).
pub fn calc_coverage_pct(covered: u32, uncovered: u32, missing: u32) -> f64 {
    let total = covered + uncovered + missing;
    if total == 0 {
        return 100.0;
    }
    (covered as f64 / total as f64) * 100.0
}

/// Sort findings deterministically.
///
/// Order: severity (error > warn > info) > path > line > check_id > code > message
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        // Severity: error > warn > info (reverse order of Ord)
        let severity_cmp = b.severity.cmp(&a.severity);
        if severity_cmp != std::cmp::Ordering::Equal {
            return severity_cmp;
        }

        // Path (lexical)
        let path_a = a.location.as_ref().map(|l| l.path.as_str()).unwrap_or("");
        let path_b = b.location.as_ref().map(|l| l.path.as_str()).unwrap_or("");
        let path_cmp = path_a.cmp(path_b);
        if path_cmp != std::cmp::Ordering::Equal {
            return path_cmp;
        }

        // Line (ascending, None last)
        let line_a = a.location.as_ref().and_then(|l| l.line).unwrap_or(u32::MAX);
        let line_b = b.location.as_ref().and_then(|l| l.line).unwrap_or(u32::MAX);
        let line_cmp = line_a.cmp(&line_b);
        if line_cmp != std::cmp::Ordering::Equal {
            return line_cmp;
        }

        // check_id
        let check_id_cmp = a.check_id.cmp(&b.check_id);
        if check_id_cmp != std::cmp::Ordering::Equal {
            return check_id_cmp;
        }

        // code
        let code_cmp = a.code.cmp(&b.code);
        if code_cmp != std::cmp::Ordering::Equal {
            return code_cmp;
        }

        // message
        a.message.cmp(&b.message)
    });
}

/// Determine the verdict based on findings and policy.
fn determine_verdict(findings: &[Finding], policy: &Policy) -> VerdictStatus {
    let has_errors = findings.iter().any(|f| f.severity == Severity::Error);
    let has_warns = findings.iter().any(|f| f.severity == Severity::Warn);

    match policy.fail_on {
        FailOn::Error => {
            if has_errors {
                VerdictStatus::Fail
            } else if has_warns {
                VerdictStatus::Warn
            } else {
                VerdictStatus::Pass
            }
        }
        FailOn::Warn => {
            if has_errors || has_warns {
                VerdictStatus::Fail
            } else {
                VerdictStatus::Pass
            }
        }
        FailOn::Never => {
            if has_errors || has_warns {
                VerdictStatus::Warn
            } else {
                VerdictStatus::Pass
            }
        }
    }
}

// ============================================================================
// Ignore Directive Detection
// ============================================================================

/// Check if a line contains a `covguard: ignore` directive.
///
/// The directive can appear in any comment style:
/// - `// covguard: ignore` (Rust, C, JS, etc.)
/// - `# covguard: ignore` (Python, Shell, YAML, etc.)
/// - `-- covguard: ignore` (SQL, Haskell, Lua)
/// - `/* covguard: ignore */` (block comments)
///
/// Matching is case-insensitive and tolerant of whitespace.
///
/// # Examples
///
/// ```
/// use covguard_domain::has_ignore_directive;
///
/// assert!(has_ignore_directive("let x = 1; // covguard: ignore"));
/// assert!(has_ignore_directive("# covguard:ignore"));
/// assert!(has_ignore_directive("/* COVGUARD: IGNORE */"));
/// assert!(!has_ignore_directive("let x = 1;"));
/// ```
pub fn has_ignore_directive(line: &str) -> bool {
    let line_lower = line.to_lowercase();

    // Look for "covguard:" followed by optional whitespace and "ignore"
    // This handles various comment styles automatically since we just
    // search for the directive pattern anywhere in the line
    if let Some(pos) = line_lower.find("covguard:") {
        let after = &line_lower[pos + 9..]; // len("covguard:") = 9
        let trimmed = after.trim_start();
        return trimmed.starts_with("ignore");
    }

    // Also support "covguard-ignore" syntax (hyphen instead of colon)
    if let Some(pos) = line_lower.find("covguard-ignore") {
        // Make sure it's in a comment context (has a comment marker before it)
        let before = &line_lower[..pos];
        return before.contains("//")
            || before.contains('#')
            || before.contains("--")
            || before.contains("/*");
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a simple EvalInput.
    fn make_input(
        changed: Vec<(&str, Vec<RangeInclusive<u32>>)>,
        coverage: Vec<(&str, Vec<(u32, u32)>)>,
    ) -> EvalInput {
        let changed_ranges = changed
            .into_iter()
            .map(|(path, ranges)| (path.to_string(), ranges))
            .collect();

        let coverage = coverage
            .into_iter()
            .map(|(path, lines)| {
                let line_map = lines.into_iter().collect();
                (path.to_string(), line_map)
            })
            .collect();

        EvalInput {
            changed_ranges,
            coverage,
            policy: Policy::default(),
            ignored_lines: BTreeMap::new(),
        }
    }

    /// Helper to create an EvalInput with ignored lines.
    fn make_input_with_ignored(
        changed: Vec<(&str, Vec<RangeInclusive<u32>>)>,
        coverage: Vec<(&str, Vec<(u32, u32)>)>,
        ignored: Vec<(&str, Vec<u32>)>,
    ) -> EvalInput {
        let mut input = make_input(changed, coverage);
        input.ignored_lines = ignored
            .into_iter()
            .map(|(path, lines)| (path.to_string(), lines.into_iter().collect()))
            .collect();
        input
    }

    #[test]
    fn test_all_lines_covered_pass() {
        let input = make_input(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 1), (2, 2), (3, 1)])],
        );

        let output = evaluate(input);

        assert_eq!(output.verdict, VerdictStatus::Pass);
        // Only check that there are no uncovered line findings
        assert!(
            !output
                .findings
                .iter()
                .any(|f| f.code == CODE_UNCOVERED_LINE),
            "Should have no uncovered line findings"
        );
        assert_eq!(output.metrics.covered_lines, 3);
        assert_eq!(output.metrics.uncovered_lines, 0);
        assert_eq!(output.metrics.missing_lines, 0);
        assert_eq!(output.metrics.diff_coverage_pct, 100.0);
    }

    #[test]
    fn test_all_lines_uncovered_fail() {
        let input = make_input(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 0), (2, 0), (3, 0)])],
        );

        let output = evaluate(input);

        assert_eq!(output.verdict, VerdictStatus::Fail);
        // Should have uncovered line findings (one per line) + threshold finding
        let uncovered_findings: Vec<_> = output
            .findings
            .iter()
            .filter(|f| f.code == CODE_UNCOVERED_LINE)
            .collect();
        assert_eq!(uncovered_findings.len(), 3);
        assert_eq!(output.metrics.covered_lines, 0);
        assert_eq!(output.metrics.uncovered_lines, 3);
        assert_eq!(output.metrics.diff_coverage_pct, 0.0);
    }

    #[test]
    fn test_mixed_coverage() {
        let input = make_input(
            vec![("src/lib.rs", vec![1..=4])],
            vec![("src/lib.rs", vec![(1, 1), (2, 0), (3, 1), (4, 0)])],
        );

        let output = evaluate(input);

        assert_eq!(output.verdict, VerdictStatus::Fail);
        assert_eq!(output.metrics.covered_lines, 2);
        assert_eq!(output.metrics.uncovered_lines, 2);
        assert_eq!(output.metrics.diff_coverage_pct, 50.0);

        // Check that uncovered lines have findings
        let uncovered_findings: Vec<_> = output
            .findings
            .iter()
            .filter(|f| f.code == CODE_UNCOVERED_LINE)
            .collect();
        assert_eq!(uncovered_findings.len(), 2);
    }

    #[test]
    fn test_empty_diff_pass() {
        let input = make_input(vec![], vec![("src/lib.rs", vec![(1, 0)])]);

        let output = evaluate(input);

        assert_eq!(output.verdict, VerdictStatus::Pass);
        assert!(output.findings.is_empty());
        assert_eq!(output.metrics.changed_lines_total, 0);
        assert_eq!(output.metrics.diff_coverage_pct, 100.0);
    }

    #[test]
    fn test_missing_coverage_data() {
        // Changed lines with no coverage data for file
        let input = make_input(vec![("src/new.rs", vec![1..=2])], vec![]);

        let output = evaluate(input);

        // Missing lines affect metrics and create missing file findings
        assert_eq!(output.metrics.missing_lines, 2);
        assert_eq!(output.metrics.covered_lines, 0);
        assert_eq!(output.metrics.uncovered_lines, 0);
        // 0 covered out of 2 missing = 0%
        assert_eq!(output.metrics.diff_coverage_pct, 0.0);
        assert!(
            output
                .findings
                .iter()
                .any(|f| f.code == CODE_MISSING_COVERAGE_FOR_FILE)
        );
    }

    #[test]
    fn test_missing_coverage_skip_excludes_from_percentage() {
        let mut input = make_input(vec![("src/new.rs", vec![1..=2])], vec![]);
        input.policy.missing_file = MissingBehavior::Skip;
        input.policy.missing_coverage = MissingBehavior::Skip;

        let output = evaluate(input);

        // Missing lines still counted in metrics
        assert_eq!(output.metrics.missing_lines, 2);
        // But excluded from coverage percentage (no covered/uncovered)
        assert_eq!(output.metrics.diff_coverage_pct, 100.0);
    }

    #[test]
    fn test_max_uncovered_lines_tolerance_marks_info() {
        let mut input = make_input(
            vec![("src/lib.rs", vec![1..=2])],
            vec![("src/lib.rs", vec![(1, 0), (2, 0)])],
        );
        input.policy.max_uncovered_lines = Some(5);

        let output = evaluate(input);

        // Uncovered lines within tolerance become info findings
        assert!(
            output
                .findings
                .iter()
                .filter(|f| f.code == CODE_UNCOVERED_LINE)
                .all(|f| f.severity == Severity::Info)
        );
    }

    #[test]
    fn test_below_threshold_finding() {
        let mut input = make_input(
            vec![("src/lib.rs", vec![1..=10])],
            vec![(
                "src/lib.rs",
                vec![
                    (1, 1),
                    (2, 1),
                    (3, 1),
                    (4, 1),
                    (5, 1),
                    (6, 1),
                    (7, 1),
                    (8, 0),
                    (9, 0),
                    (10, 0),
                ],
            )],
        );
        input.policy.threshold_pct = 80.0;

        let output = evaluate(input);

        // 70% coverage < 80% threshold
        assert_eq!(output.verdict, VerdictStatus::Fail);
        assert!(
            output
                .findings
                .iter()
                .any(|f| f.code == CODE_COVERAGE_BELOW_THRESHOLD)
        );
    }

    #[test]
    fn test_above_threshold_pass() {
        let mut input = make_input(
            vec![("src/lib.rs", vec![1..=10])],
            vec![(
                "src/lib.rs",
                vec![
                    (1, 1),
                    (2, 1),
                    (3, 1),
                    (4, 1),
                    (5, 1),
                    (6, 1),
                    (7, 1),
                    (8, 1),
                    (9, 1),
                    (10, 0),
                ],
            )],
        );
        input.policy.threshold_pct = 80.0;

        let output = evaluate(input);

        // 90% coverage >= 80% threshold, but still has uncovered line
        assert_eq!(output.metrics.diff_coverage_pct, 90.0);
        // Still fails because of uncovered line finding
        assert_eq!(output.verdict, VerdictStatus::Fail);
    }

    #[test]
    fn test_deterministic_ordering() {
        let input = make_input(
            vec![("src/z.rs", vec![1..=1]), ("src/a.rs", vec![2..=2, 1..=1])],
            vec![
                ("src/z.rs", vec![(1, 0)]),
                ("src/a.rs", vec![(1, 0), (2, 0)]),
            ],
        );

        let output = evaluate(input);

        // Filter to just uncovered line findings
        let uncovered: Vec<_> = output
            .findings
            .iter()
            .filter(|f| f.code == CODE_UNCOVERED_LINE)
            .collect();

        // Should be sorted: src/a.rs:1, src/a.rs:2, src/z.rs:1
        assert_eq!(uncovered.len(), 3);

        let paths_lines: Vec<_> = uncovered
            .iter()
            .map(|f| {
                let loc = f.location.as_ref().unwrap();
                (loc.path.as_str(), loc.line.unwrap())
            })
            .collect();

        assert_eq!(
            paths_lines,
            vec![("src/a.rs", 1), ("src/a.rs", 2), ("src/z.rs", 1)]
        );
    }

    #[test]
    fn test_fail_on_never() {
        let mut input = make_input(
            vec![("src/lib.rs", vec![1..=1])],
            vec![("src/lib.rs", vec![(1, 0)])],
        );
        input.policy.fail_on = FailOn::Never;

        let output = evaluate(input);

        // Even with errors, verdict should be warn (not fail)
        assert_eq!(output.verdict, VerdictStatus::Warn);
    }

    #[test]
    fn test_fail_on_warn() {
        let mut input = make_input(
            vec![("src/lib.rs", vec![1..=1])],
            vec![("src/lib.rs", vec![(1, 1)])],
        );
        input.policy.fail_on = FailOn::Warn;
        input.policy.threshold_pct = 100.0;

        let output = evaluate(input);

        // All lines covered, threshold met
        assert_eq!(output.verdict, VerdictStatus::Pass);
    }

    #[test]
    fn test_calc_coverage_pct_zero_total() {
        assert_eq!(calc_coverage_pct(0, 0, 0), 100.0);
    }

    #[test]
    fn test_calc_coverage_pct_all_covered() {
        assert_eq!(calc_coverage_pct(10, 0, 0), 100.0);
    }

    #[test]
    fn test_calc_coverage_pct_none_covered() {
        assert_eq!(calc_coverage_pct(0, 10, 0), 0.0);
    }

    #[test]
    fn test_calc_coverage_pct_half_covered() {
        assert_eq!(calc_coverage_pct(5, 5, 0), 50.0);
    }

    #[test]
    fn test_calc_coverage_pct_with_missing() {
        // 5 covered, 3 uncovered, 2 missing = 10 total
        // 5/10 = 50%
        assert_eq!(calc_coverage_pct(5, 3, 2), 50.0);
    }

    #[test]
    fn test_multiple_files() {
        let input = make_input(
            vec![("src/a.rs", vec![1..=2]), ("src/b.rs", vec![1..=2])],
            vec![
                ("src/a.rs", vec![(1, 1), (2, 1)]),
                ("src/b.rs", vec![(1, 0), (2, 0)]),
            ],
        );

        let output = evaluate(input);

        assert_eq!(output.metrics.covered_lines, 2);
        assert_eq!(output.metrics.uncovered_lines, 2);
        assert_eq!(output.metrics.diff_coverage_pct, 50.0);
    }

    #[test]
    fn test_non_contiguous_ranges() {
        let input = make_input(
            vec![("src/lib.rs", vec![1..=2, 10..=12])],
            vec![(
                "src/lib.rs",
                vec![(1, 1), (2, 1), (10, 0), (11, 0), (12, 0)],
            )],
        );

        let output = evaluate(input);

        assert_eq!(output.metrics.changed_lines_total, 5);
        assert_eq!(output.metrics.covered_lines, 2);
        assert_eq!(output.metrics.uncovered_lines, 3);
    }

    // ========================================================================
    // Ignore Directive Tests
    // ========================================================================

    #[test]
    fn test_has_ignore_directive_rust_comment() {
        assert!(has_ignore_directive("let x = 1; // covguard: ignore"));
        assert!(has_ignore_directive("// covguard: ignore"));
        assert!(has_ignore_directive("    // covguard: ignore"));
        assert!(has_ignore_directive("// COVGUARD: IGNORE"));
        assert!(has_ignore_directive("// covguard:ignore")); // no space after colon
    }

    #[test]
    fn test_has_ignore_directive_python_comment() {
        assert!(has_ignore_directive("x = 1  # covguard: ignore"));
        assert!(has_ignore_directive("# covguard: ignore"));
        assert!(has_ignore_directive("#covguard:ignore"));
    }

    #[test]
    fn test_has_ignore_directive_block_comment() {
        assert!(has_ignore_directive("/* covguard: ignore */"));
        assert!(has_ignore_directive("int x = 1; /* covguard: ignore */"));
    }

    #[test]
    fn test_has_ignore_directive_sql_comment() {
        assert!(has_ignore_directive("-- covguard: ignore"));
        assert!(has_ignore_directive("SELECT 1; -- covguard: ignore"));
    }

    #[test]
    fn test_has_ignore_directive_hyphen_syntax() {
        assert!(has_ignore_directive("// covguard-ignore"));
        assert!(has_ignore_directive("# covguard-ignore"));
    }

    #[test]
    fn test_has_ignore_directive_negative_cases() {
        assert!(!has_ignore_directive("let x = 1;"));
        assert!(!has_ignore_directive("// some other comment"));
        assert!(!has_ignore_directive("// covguard")); // missing ignore
        assert!(!has_ignore_directive("// ignore covguard")); // wrong order
    }

    #[test]
    fn test_ignored_lines_skipped() {
        let input = make_input_with_ignored(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 0), (2, 0), (3, 0)])],
            vec![("src/lib.rs", vec![2])], // Line 2 is ignored
        );

        let output = evaluate(input);

        // Line 2 should be ignored, so only 2 uncovered lines
        assert_eq!(output.metrics.uncovered_lines, 2);
        assert_eq!(output.metrics.ignored_lines, 1);
        assert_eq!(output.metrics.changed_lines_total, 2); // Only non-ignored lines counted
    }

    #[test]
    fn test_ignored_lines_all_ignored() {
        let input = make_input_with_ignored(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 0), (2, 0), (3, 0)])],
            vec![("src/lib.rs", vec![1, 2, 3])], // All lines ignored
        );

        let output = evaluate(input);

        // All lines ignored, so no findings
        assert_eq!(output.verdict, VerdictStatus::Pass);
        assert_eq!(output.metrics.uncovered_lines, 0);
        assert_eq!(output.metrics.ignored_lines, 3);
        assert_eq!(output.metrics.changed_lines_total, 0);
        assert!(output.findings.is_empty());
    }

    #[test]
    fn test_ignored_lines_disabled_in_policy() {
        let mut input = make_input_with_ignored(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 0), (2, 0), (3, 0)])],
            vec![("src/lib.rs", vec![1, 2, 3])], // All lines ignored
        );
        input.policy.ignore_directives_enabled = false;

        let output = evaluate(input);

        // Ignore directives disabled, so all lines should be evaluated
        assert_eq!(output.metrics.uncovered_lines, 3);
        assert_eq!(output.metrics.ignored_lines, 0);
    }

    #[test]
    fn test_ignored_lines_pass_when_uncovered_ignored() {
        // 2 covered lines, 1 uncovered but ignored line
        let input = make_input_with_ignored(
            vec![("src/lib.rs", vec![1..=3])],
            vec![("src/lib.rs", vec![(1, 1), (2, 1), (3, 0)])],
            vec![("src/lib.rs", vec![3])], // Line 3 is ignored
        );

        let output = evaluate(input);

        // Should pass because the uncovered line is ignored
        assert_eq!(output.verdict, VerdictStatus::Pass);
        assert_eq!(output.metrics.covered_lines, 2);
        assert_eq!(output.metrics.uncovered_lines, 0);
        assert_eq!(output.metrics.ignored_lines, 1);
        assert_eq!(output.metrics.diff_coverage_pct, 100.0);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn coverage_pct_always_in_range(covered in 0u32..1000, uncovered in 0u32..1000, missing in 0u32..1000) {
            let pct = calc_coverage_pct(covered, uncovered, missing);
            prop_assert!(pct >= 0.0);
            prop_assert!(pct <= 100.0);
        }

        #[test]
        fn coverage_pct_is_deterministic(covered in 0u32..1000, uncovered in 0u32..1000, missing in 0u32..1000) {
            let pct1 = calc_coverage_pct(covered, uncovered, missing);
            let pct2 = calc_coverage_pct(covered, uncovered, missing);
            prop_assert_eq!(pct1, pct2);
        }

        #[test]
        fn findings_order_is_deterministic(
            path1 in "[a-z]{1,10}",
            path2 in "[a-z]{1,10}",
            line1 in 1u32..100,
            line2 in 1u32..100,
        ) {
            let mut findings = vec![
                Finding {
                    severity: Severity::Error,
                    check_id: "test".to_string(),
                    code: "test.code".to_string(),
                    message: "msg".to_string(),
                    location: Some(Location { path: path1.clone(), line: Some(line1), col: None }),
                    data: None,
                    fingerprint: None,
                },
                Finding {
                    severity: Severity::Error,
                    check_id: "test".to_string(),
                    code: "test.code".to_string(),
                    message: "msg".to_string(),
                    location: Some(Location { path: path2.clone(), line: Some(line2), col: None }),
                    data: None,
                    fingerprint: None,
                },
            ];

            let mut findings_copy = findings.clone();

            sort_findings(&mut findings);
            sort_findings(&mut findings_copy);

            // Order should be the same
            for (f1, f2) in findings.iter().zip(findings_copy.iter()) {
                prop_assert_eq!(
                    f1.location.as_ref().map(|l| (&l.path, l.line)),
                    f2.location.as_ref().map(|l| (&l.path, l.line))
                );
            }
        }
    }
}
