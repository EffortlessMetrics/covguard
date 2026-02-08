# covguard-domain

Pure domain logic for diff coverage policy evaluation.

## Purpose

This crate is the pure, side-effect-free domain core. It evaluates changed lines against coverage data under a given policy and produces findings, verdicts, and metrics.

## Key Types

- **`Policy`** - Configuration for coverage evaluation
  - `scope` - Added or Touched lines
  - `threshold_pct` - Minimum coverage percentage
  - `fail_on` - When to fail (Never, Error, WarnOrError)
  - `ignore_directives` - Whether to honor `covguard: ignore` comments
- **`EvalInput`** - Inputs to evaluation
  - `changed_ranges` - File paths to line ranges
  - `coverage` - File paths to line hit counts
  - `policy` - Evaluation rules
  - `ignored_lines` - Lines with ignore directives
- **`EvalOutput`** - Results of evaluation
  - `findings` - List of findings
  - `verdict` - Pass/Warn/Fail/Skip
  - `metrics` - Coverage statistics
- **`Metrics`** - Coverage statistics (covered, uncovered, missing, ignored)

## Key Functions

- **`evaluate(input: EvalInput) -> EvalOutput`** - Main evaluation entry point
- **`sort_findings(findings: &mut [Finding])`** - Deterministic sorting: severity > path > line > check_id > code > message
- **`calc_coverage_pct(covered, total) -> Option<f64>`** - Safe percentage calculation
- **`determine_verdict(findings, fail_on) -> VerdictStatus`** - Map findings to verdict
- **`has_ignore_directive(line: &str) -> bool`** - Detect `covguard: ignore` in source

## Key Invariants

1. **Deterministic output** - Findings are always sorted in the same order
2. **Pure functions** - No I/O, no side effects, fully testable
3. **Policy-driven** - All behavior controlled by Policy configuration

## Testing

- Unit tests for edge cases
- Property tests (proptest) for:
  - Coverage percentage math
  - Findings ordering stability
  - Range handling

## Dependencies

- `covguard-types` - Shared DTOs
- `serde_json` - Used in tests
