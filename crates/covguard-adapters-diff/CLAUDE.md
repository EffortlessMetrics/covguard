# covguard-adapters-diff

Unified diff parsing adapter.

## Purpose

This crate parses unified diff format (patch files or git diff output) to extract changed line ranges per file. It is a port/adapter in the hexagonal architecture.

## Key Types

- **`ChangedRanges`** - `BTreeMap<String, Vec<(u32, u32)>>` of file paths to sorted, non-overlapping line ranges
- **`DiffError`** - Parse error types

## Key Functions

- **`parse_patch(diff: &str) -> Result<ChangedRanges>`** - Parse unified diff
- **`normalize_path(path: &str) -> String`** - Normalize file paths
- **`merge_ranges(ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)>`** - Merge overlapping ranges
- **`parse_hunk_header(line: &str) -> Option<u32>`** - Extract new-side start line

## Path Normalization

- Strips `b/`, `a/`, `./` prefixes
- Converts backslashes to forward slashes
- Produces repo-relative paths

## Parsing Details

Handles:
- Multiple files in one diff
- File renames (`rename from`/`rename to`)
- File deletions (no added lines)
- CRLF line endings
- Hunk headers: `@@ -old,count +new,count @@`

Only counts lines starting with `+` (added lines), excluding the `+++ b/file` header.

## Range Merging

Adjacent and overlapping ranges are merged into minimal non-overlapping set:
- `[(1,3), (4,6)]` → `[(1,6)]` (adjacent)
- `[(1,5), (3,7)]` → `[(1,7)]` (overlapping)

## Testing

- Unit tests for path normalization
- Unit tests for range merging
- Property tests for merge invariants
- Fixture-based tests with real diff files

## Dependencies

- `thiserror` - Error types
