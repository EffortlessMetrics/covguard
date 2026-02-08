# covguard-types

Data transfer objects and schema definitions for covguard.

## Purpose

This crate defines the report schema and core types used throughout the system. It is the foundational layer that all other crates depend on for shared type definitions.

## Key Types

- **`Report`** - Top-level report structure containing schema, tool, run, verdict, findings, and data
- **`Finding`** - Individual finding with severity, code, message, and location
- **`Verdict`** - Overall verdict with status and counts
- **`VerdictStatus`** - Pass, Warn, Fail, Skip
- **`Severity`** - Info, Warn, Error
- **`Scope`** - Line evaluation scope (Added, Touched)
- **`Location`** - File path and optional line/end_line

## Error Codes

Constants for all covguard error codes:
- `CODE_UNCOVERED_LINE` - Changed line has no test coverage
- `CODE_COVERAGE_BELOW_THRESHOLD` - Diff coverage % below threshold
- `CODE_MISSING_COVERAGE_FOR_FILE` - File has changes but no coverage data
- `CODE_INVALID_LCOV` / `CODE_INVALID_DIFF` - Parse failures

## Design Notes

- All types implement `Serialize`/`Deserialize` for JSON compatibility
- Report must validate against `contracts/schemas/covguard.report.v1.json`
- VerdictStatus uses `#[serde(rename_all = "lowercase")]` for schema compliance
- Chrono used for timestamps with RFC3339 formatting

## Testing

Unit tests cover serialization roundtrips and report structure validation.

## Dependencies

- `serde` / `serde_json` - Serialization
- `chrono` - Timestamps
