//! Application orchestration for covguard.
//!
//! This crate provides the `check_with_providers_and_reader` function that orchestrates
//! the entire diff coverage analysis pipeline in a port-driven, generic way.

pub use covguard_orchestrator_types::{AppError, CheckRequest, CheckResult, CoverageInput};

use covguard_config::should_include_path;
pub use covguard_directives::detect_ignored_lines;
pub use covguard_domain::MissingBehavior;
use covguard_domain::{EvalInput, EvalOutput, Policy, evaluate};
pub use covguard_output::{
    DEFAULT_ANNOTATION_LIMIT as DEFAULT_MAX_ANNOTATIONS,
    DEFAULT_MARKDOWN_LINES as DEFAULT_MAX_LINES,
    DEFAULT_SARIF_RESULTS as DEFAULT_MAX_SARIF_RESULTS, render_annotations,
    render_annotations_with_limit, render_markdown, render_markdown_with_limit, render_sarif,
    render_sarif_with_limit,
};
pub use covguard_policy::FailOn;
pub use covguard_ports::{
    Clock, CoverageMap, CoverageProvider, DiffParseResult, DiffProvider, RepoReader,
};
use covguard_reporting::{
    ReportContext, build_debug as reporting_build_debug,
    build_error_report_pair as reporting_build_error_report_pair,
    build_report_pair as reporting_build_report_pair,
    build_skip_report_pair as reporting_build_skip_report_pair,
    is_invalid_diff as reporting_is_invalid_diff,
};
use covguard_types::{
    CODE_INVALID_DIFF, CODE_INVALID_LCOV, REASON_MISSING_LCOV, Report, VerdictStatus,
};
use std::collections::BTreeMap;

// ============================================================================
// Clock Trait
// ============================================================================

/// System clock implementation that returns the actual current time.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

// ============================================================================
// Main Orchestration Function
// ============================================================================

/// Run a diff coverage check with pluggable diff and coverage providers.
///
/// This enables fully port-driven orchestration.
pub fn check_with_providers_and_reader<
    C: Clock,
    R: RepoReader,
    D: DiffProvider,
    P: CoverageProvider,
>(
    request: CheckRequest,
    clock: &C,
    reader: &R,
    diff_provider: &D,
    coverage_provider: &P,
) -> Result<CheckResult, AppError> {
    let started_at = clock.now();

    // Determine diff availability
    let diff_available = !request.diff_text.is_empty()
        || request.diff_file_path.is_some()
        || (request.base_ref.is_some() && request.head_ref.is_some());

    // Determine coverage availability
    let mut coverage_inputs = request.coverage_inputs.clone();

    // Migrate deprecated lcov_texts to coverage_inputs for backward compatibility
    for (i, text) in request.lcov_texts.iter().enumerate() {
        if !text.trim().is_empty() {
            let path = request
                .lcov_paths
                .get(i)
                .cloned()
                .unwrap_or_else(|| "coverage.info".to_string());
            coverage_inputs.push(CoverageInput {
                content: text.clone(),
                path,
                format: covguard_types::CoverageFormat::Lcov,
            });
        }
    }

    let coverage_available = !coverage_inputs.is_empty();

    // In sensor schema mode, return skip result if coverage is unavailable
    if request.sensor_schema && !coverage_available {
        return Ok(build_skip_result(
            &request,
            started_at,
            diff_available,
            false, // coverage unavailable
            REASON_MISSING_LCOV,
            clock,
        ));
    }

    // Validate diff input (non-empty must include diff markers)
    if is_invalid_diff(&request.diff_text) {
        return Ok(build_error_result(
            &request,
            started_at,
            CODE_INVALID_DIFF,
            "Diff input did not contain any recognized diff markers.",
            true, // diff was provided (non-empty)
            coverage_available,
            clock,
        ));
    }

    // Parse the diff
    let parse_result = match diff_provider.parse_patch(&request.diff_text) {
        Ok(ranges) => ranges,
        Err(e) => {
            return Ok(build_error_result(
                &request,
                started_at,
                CODE_INVALID_DIFF,
                &format!("Failed to parse diff: {e}"),
                true, // diff was provided
                coverage_available,
                clock,
            ));
        }
    };
    let changed_ranges = parse_result.changed_ranges;
    let binary_files = parse_result.binary_files;

    // Parse coverage (merge multiple inputs)
    let mut coverage_maps: Vec<CoverageMap> = Vec::new();
    for input in coverage_inputs {
        match coverage_provider.parse_coverage(&input.content, input.format, &request.path_strip) {
            Ok(map) => coverage_maps.push(map),
            Err(e) => {
                return Ok(build_error_result(
                    &request,
                    started_at,
                    CODE_INVALID_LCOV,
                    &format!("Failed to parse coverage ({}): {}", input.path, e),
                    true, // diff parsed OK
                    true, // coverage was provided (but invalid)
                    clock,
                ));
            }
        }
    }
    let coverage: CoverageMap = coverage_provider.merge_coverage(coverage_maps);

    // Detect ignored lines
    let mut filtered_ranges = changed_ranges;
    let mut excluded_files_count = 0u32;
    filtered_ranges.retain(|path, _| {
        if should_include_path(path, &request.include_patterns, &request.exclude_patterns) {
            true
        } else {
            excluded_files_count += 1;
            false
        }
    });

    let ignored_lines = if request.ignore_directives {
        request
            .ignored_lines
            .clone()
            .unwrap_or_else(|| detect_ignored_lines(&filtered_ranges, reader))
    } else {
        BTreeMap::new()
    };

    let policy = Policy {
        scope: request.scope,
        threshold_pct: request.threshold_pct,
        max_uncovered_lines: request.max_uncovered_lines,
        missing_coverage: request.missing_coverage,
        missing_file: request.missing_file,
        fail_on: request.fail_on,
        ignore_directives_enabled: request.ignore_directives,
    };

    // Build evaluation input
    let eval_input = EvalInput {
        changed_ranges: filtered_ranges,
        coverage,
        policy,
        ignored_lines,
    };

    // Run evaluation
    let eval_output = evaluate(eval_input);

    // Build the report pair (domain report + optional cockpit receipt)
    let debug = build_debug(&binary_files);
    let ended_at = clock.now();
    let output_flags = request.output;
    let (domain_report, cockpit_receipt) = build_report_pair(
        eval_output,
        &request,
        started_at,
        ended_at,
        excluded_files_count,
        debug,
    );

    // Render outputs from the domain report (full findings)
    let markdown = render_markdown_with_limit(&domain_report, output_flags.max_markdown_lines);
    let annotations = render_annotations_with_limit(&domain_report, output_flags.max_annotations);
    let sarif = render_sarif_with_limit(&domain_report, output_flags.max_sarif_results);

    // Determine exit code from domain report verdict
    let exit_code = match domain_report.verdict.status {
        VerdictStatus::Pass | VerdictStatus::Warn | VerdictStatus::Skip => 0,
        VerdictStatus::Fail => 2,
    };

    Ok(CheckResult {
        report: domain_report,
        output: output_flags,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code,
    })
}

// ============================================================================
// Report Builder
// ============================================================================

fn build_report_context(request: &CheckRequest) -> ReportContext {
    let mut lcov_paths = request.lcov_paths.clone();
    for input in &request.coverage_inputs {
        if !lcov_paths.contains(&input.path) {
            lcov_paths.push(input.path.clone());
        }
    }

    ReportContext {
        threshold_pct: request.threshold_pct,
        scope: request.scope,
        sensor_schema: request.sensor_schema,
        max_findings: request.max_findings,
        diff_file_path: request.diff_file_path.clone(),
        base_ref: request.base_ref.clone(),
        head_ref: request.head_ref.clone(),
        lcov_paths,
    }
}

fn build_report_pair(
    eval: EvalOutput,
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    excluded_files_count: u32,
    debug: Option<serde_json::Value>,
) -> (Report, Option<Report>) {
    reporting_build_report_pair(
        eval,
        &build_report_context(request),
        started_at,
        ended_at,
        excluded_files_count,
        debug,
    )
}

fn build_debug(binary_files: &[String]) -> Option<serde_json::Value> {
    reporting_build_debug(binary_files)
}

fn build_error_result<C: Clock>(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    code: &str,
    message: &str,
    diff_available: bool,
    coverage_available: bool,
    clock: &C,
) -> CheckResult {
    let ended_at = clock.now();
    let (domain_report, cockpit_receipt) = build_error_report_pair(
        request,
        started_at,
        ended_at,
        code,
        message,
        diff_available,
        coverage_available,
    );
    let markdown = render_markdown_with_limit(&domain_report, request.output.max_markdown_lines);
    let annotations = render_annotations_with_limit(&domain_report, request.output.max_annotations);
    let sarif = render_sarif_with_limit(&domain_report, request.output.max_sarif_results);

    CheckResult {
        report: domain_report,
        output: request.output,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code: 1,
    }
}

fn build_error_report_pair(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    code: &str,
    message: &str,
    diff_available: bool,
    coverage_available: bool,
) -> (Report, Option<Report>) {
    reporting_build_error_report_pair(
        &build_report_context(request),
        started_at,
        ended_at,
        code,
        message,
        diff_available,
        coverage_available,
    )
}

fn build_skip_result<C: Clock>(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    diff_available: bool,
    coverage_available: bool,
    reason: &str,
    clock: &C,
) -> CheckResult {
    let ended_at = clock.now();
    let (domain_report, cockpit_receipt) = build_skip_report_pair(
        request,
        started_at,
        ended_at,
        diff_available,
        coverage_available,
        reason,
    );
    let markdown = render_markdown_with_limit(&domain_report, request.output.max_markdown_lines);
    let annotations = render_annotations_with_limit(&domain_report, request.output.max_annotations);
    let sarif = render_sarif_with_limit(&domain_report, request.output.max_sarif_results);

    CheckResult {
        report: domain_report,
        output: request.output,
        cockpit_receipt,
        markdown,
        annotations,
        sarif,
        exit_code: 0,
    }
}

fn build_skip_report_pair(
    request: &CheckRequest,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
    diff_available: bool,
    coverage_available: bool,
    reason: &str,
) -> (Report, Option<Report>) {
    reporting_build_skip_report_pair(
        &build_report_context(request),
        started_at,
        ended_at,
        diff_available,
        coverage_available,
        reason,
    )
}

fn is_invalid_diff(diff_text: &str) -> bool {
    reporting_is_invalid_diff(diff_text)
}
