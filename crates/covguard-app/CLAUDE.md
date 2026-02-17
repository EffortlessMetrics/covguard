# covguard-app

High-level orchestration layer for diff coverage analysis.

## Purpose

This crate orchestrates the entire diff coverage pipeline, connecting adapters (diff parsing, coverage parsing) to the domain core and renderers. It is the main entry point for programmatic use.

## Key Types

- **`CheckRequest`** - Input configuration
  - `diff` - Diff text (patch format)
  - `lcov` - LCOV coverage text
  - `threshold_pct` - Coverage threshold
  - `scope` - Added or Touched
  - `fail_on` - Failure policy
  - `source_paths` - Optional paths for ignore directive detection
- **`CheckResult`** - Output
  - `report` - Full Report object
  - `markdown` - Rendered markdown (if requested)
  - `annotations` - GitHub annotations (if requested)
  - `sarif` - SARIF JSON (if requested)
  - `exit_code` - 0, 1, or 2
- **`Clock` / `SystemClock`** - Time provider abstraction + system implementation
- **`RepoReader`** - Re-exported port trait used for ignore directives

## Key Functions

- **`check(request: CheckRequest) -> Result<CheckResult>`** - Main entry point
- **`check_with_clock(request, clock)`** - Testable with custom clock
- **`check_with_clock_and_reader(request, clock, reader)`** - Full control
- **`build_report(output, tool, clock)`** - Construct Report from EvalOutput
- **`detect_ignored_lines(ranges, reader)`** - Scan for `covguard: ignore` directives

## Pipeline Flow

```
CheckRequest
    ↓
parse_patch(diff)        → ChangedRanges
parse_lcov(lcov)         → CoverageMap
detect_ignored_lines()   → IgnoredLines (optional)
    ↓
evaluate(EvalInput)      → EvalOutput
    ↓
build_report()           → Report
render_*()               → Markdown/Annotations/SARIF
    ↓
CheckResult
```

## Exit Codes

- `0` - Pass or Warn
- `1` - Tool/runtime error (I/O, parse failure)
- `2` - Policy fail (blocking findings)

## Ignore Directives

When `ignore_directives` is enabled and source paths are provided:
1. Reads source files for changed lines
2. Detects `covguard: ignore` pattern in comments
3. Excludes those lines from coverage requirements

## Testing

- End-to-end tests (uncovered, covered, partial scenarios)
- Error handling tests
- Clock/reader trait tests for determinism
- Snapshot tests for output stability

## Dependencies

- `covguard-types` - DTOs
- `covguard-ports` - Shared port traits
- `covguard-domain` - Evaluation logic
- `covguard-adapters-diff` - Diff parsing
- `covguard-adapters-coverage` - LCOV parsing
- `covguard-render` - Output formatting
- `chrono` - Timestamps
- `thiserror` - Error types
