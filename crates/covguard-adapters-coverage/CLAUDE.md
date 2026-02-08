# covguard-adapters-coverage

LCOV coverage file parsing adapter.

## Purpose

This crate parses LCOV format coverage files and merges coverage data from multiple sources. It is a port/adapter in the hexagonal architecture.

## Key Types

- **`CoverageMap`** - `BTreeMap<String, BTreeMap<u32, u32>>` of file paths to line coverage (line number → hit count)
- **`LcovError`** - Parse error types

## Key Functions

- **`parse_lcov(content: &str) -> Result<CoverageMap>`** - Parse LCOV format
- **`normalize_path(path: &str) -> String`** - Normalize file paths
- **`merge_coverage(a: CoverageMap, b: CoverageMap) -> CoverageMap`** - Merge coverage maps
- **`get_hits(map: &CoverageMap, file: &str, line: u32) -> Option<u32>`** - Query helper

## LCOV Format

Parses these LCOV records:
- `TN:` - Test name (ignored)
- `SF:path` - Source file path
- `DA:line,hits` - Line data
- `end_of_record` - End of file section

Ignores function coverage (`FN:`, `FNDA:`) and branch coverage (`BRDA:`, `BRF:`, `BRH:`).

## Path Normalization

- Strips `./` prefix
- Handles absolute paths (Unix `/path`, Windows `C:/path`)
- Converts backslashes to forward slashes
- Produces repo-relative paths

## Coverage Merging

When merging multiple LCOV files:
- Union of all files
- For same line in same file: takes **maximum** hit count
- Commutative: `merge(a, b) == merge(b, a)`
- Idempotent: `merge(a, a) == a`

## Error Handling

- Gracefully handles missing `end_of_record`
- Reports line numbers for parse errors
- Invalid `DA:` lines are skipped with warning

## Testing

- Unit tests for parsing
- Unit tests for merging
- Property tests for commutativity and idempotence
- Fixture-based tests with real LCOV files

## Dependencies

- `thiserror` - Error types
