//! Opinionated orchestration for covguard.
//!
//! This crate provides the high-level `check` function that orchestrates
//! the entire diff coverage analysis pipeline using default adapters.

pub use covguard_orchestrator::*;

use covguard_adapters_composite::CompositeCoverageProvider;
use covguard_adapters_diff::GitDiffProvider;

/// Run a diff coverage check.
///
/// This is the main entry point for the covguard analysis. It:
/// 1. Parses the diff to extract changed line ranges
/// 2. Parses LCOV, JaCoCo, or coverage.py data
/// 3. Evaluates coverage against the policy
/// 4. Builds and returns a result with report, markdown, annotations, and exit code
///
/// # Arguments
///
/// * `request` - The check request containing diff, coverage, and options
///
/// # Returns
///
/// A `CheckResult` containing the report, rendered outputs, and exit code.
///
/// # Errors
///
/// Returns `AppError` if parsing fails.
pub fn check(request: CheckRequest) -> Result<CheckResult, AppError> {
    check_with_clock(request, &SystemClock)
}

/// Run a diff coverage check with a custom clock.
///
/// This allows for deterministic testing with fixed timestamps.
pub fn check_with_clock<C: Clock>(
    request: CheckRequest,
    clock: &C,
) -> Result<CheckResult, AppError> {
    check_with_clock_and_reader(request, clock, &NullReader)
}

/// A no-op reader that returns None for all lines.
/// Used when ignore directives are disabled.
struct NullReader;

impl RepoReader for NullReader {
    fn read_line(&self, _path: &str, _line_no: u32) -> Option<String> {
        None
    }
}

/// Run a diff coverage check with a custom clock and repo reader.
///
/// The repo reader is used to detect `covguard: ignore` directives in source files.
pub fn check_with_clock_and_reader<C: Clock, R: RepoReader>(
    request: CheckRequest,
    clock: &C,
    reader: &R,
) -> Result<CheckResult, AppError> {
    let diff_provider = GitDiffProvider;
    let coverage_provider = CompositeCoverageProvider::default();
    check_with_providers_and_reader(request, clock, reader, &diff_provider, &coverage_provider)
}
