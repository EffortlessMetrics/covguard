//! Diff parsing adapters for covguard.
//!
//! This crate provides a unified diff parser that extracts changed line ranges
//! from patch files or git diff output.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use thiserror::Error;

// ============================================================================
// Types
// ============================================================================

/// Map of file paths to their changed line ranges.
///
/// Keys are normalized repo-relative paths with forward slashes.
/// Values are sorted, non-overlapping, inclusive line ranges (1-indexed).
pub type ChangedRanges = BTreeMap<String, Vec<RangeInclusive<u32>>>;

/// Result of parsing a diff with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffParseResult {
    /// Parsed changed line ranges.
    pub changed_ranges: ChangedRanges,
    /// Detected binary files (normalized paths).
    pub binary_files: Vec<String>,
}

/// Errors that can occur during diff parsing.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DiffError {
    /// The diff format is invalid or malformed.
    #[error("invalid diff format: {0}")]
    InvalidFormat(String),

    /// An I/O error occurred while reading the diff.
    #[error("I/O error: {0}")]
    IoError(String),
}

// ============================================================================
// Path Normalization
// ============================================================================

/// Normalize a path from a diff header to repo-relative format.
///
/// - Strips `b/` prefix (git diff convention)
/// - Strips `a/` prefix
/// - Converts backslashes to forward slashes
/// - Removes leading `./`
///
/// # Examples
///
/// ```
/// use covguard_adapters_diff::normalize_path;
///
/// assert_eq!(normalize_path("b/src/lib.rs"), "src/lib.rs");
/// assert_eq!(normalize_path("a/src/lib.rs"), "src/lib.rs");
/// assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
/// assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
/// ```
pub fn normalize_path(path: &str) -> String {
    let path = path.trim();

    // Convert backslashes to forward slashes
    let path = path.replace('\\', "/");

    // Strip a/ or b/ prefix (git diff convention)
    let path = path
        .strip_prefix("b/")
        .or_else(|| path.strip_prefix("a/"))
        .unwrap_or(&path);

    // Remove leading ./
    let path = path.strip_prefix("./").unwrap_or(path);

    path.to_string()
}

// ============================================================================
// Range Merging
// ============================================================================

/// Merge overlapping or adjacent ranges into a minimal set.
///
/// Input ranges do not need to be sorted; output will be sorted and
/// contain no overlapping or adjacent ranges.
///
/// # Examples
///
/// ```
/// use covguard_adapters_diff::merge_ranges;
///
/// // These ranges are all adjacent/overlapping: 1..=4 (from 1..=3, 2..=4),
/// // then 5..=7 is adjacent to 1..=4, and 8..=10 is adjacent to 5..=7,
/// // so everything merges into one range.
/// let ranges = vec![1..=3, 5..=7, 2..=4, 8..=10];
/// let merged = merge_ranges(ranges);
/// assert_eq!(merged, vec![1..=10]);
///
/// // Non-adjacent ranges stay separate
/// let ranges = vec![1..=3, 10..=15];
/// let merged = merge_ranges(ranges);
/// assert_eq!(merged, vec![1..=3, 10..=15]);
/// ```
pub fn merge_ranges(mut ranges: Vec<RangeInclusive<u32>>) -> Vec<RangeInclusive<u32>> {
    if ranges.is_empty() {
        return Vec::new();
    }

    // Sort by start, then by end
    ranges.sort_by(|a, b| a.start().cmp(b.start()).then(a.end().cmp(b.end())));

    let mut merged: Vec<RangeInclusive<u32>> = Vec::with_capacity(ranges.len());

    for range in ranges {
        if let Some(last) = merged.last_mut() {
            // Check if ranges overlap or are adjacent
            // Adjacent: last.end + 1 == range.start
            // Overlapping: range.start <= last.end
            if *range.start() <= last.end().saturating_add(1) {
                // Extend the last range if needed
                if *range.end() > *last.end() {
                    *last = *last.start()..=*range.end();
                }
            } else {
                merged.push(range);
            }
        } else {
            merged.push(range);
        }
    }

    merged
}

// ============================================================================
// Diff Parsing
// ============================================================================

/// Parse a unified diff/patch and extract changed (added) line ranges.
///
/// This function parses the standard unified diff format as produced by
/// `git diff` or patch files. It extracts only added lines (lines starting
/// with `+` that aren't header lines).
///
/// # Arguments
///
/// * `text` - The unified diff text to parse
///
/// # Returns
///
/// A `ChangedRanges` map where keys are normalized file paths and values
/// are sorted, non-overlapping line ranges of added lines.
///
/// # Errors
///
/// Returns `DiffError::InvalidFormat` if the diff is malformed.
///
/// # Examples
///
/// ```
/// use covguard_adapters_diff::parse_patch;
///
/// let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
/// new file mode 100644
/// index 0000000..1111111
/// --- /dev/null
/// +++ b/src/lib.rs
/// @@ -0,0 +1,3 @@
/// +pub fn add(a: i32, b: i32) -> i32 {
/// +    a + b
/// +}
/// "#;
///
/// let ranges = parse_patch(diff).unwrap();
/// assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=3]));
/// ```
pub fn parse_patch(text: &str) -> Result<ChangedRanges, DiffError> {
    Ok(parse_patch_with_meta(text)?.changed_ranges)
}

/// Parse a unified diff/patch and extract changed (added) line ranges with metadata.
///
/// In addition to changed ranges, this records binary files detected via:
/// - "Binary files ... and ... differ" lines
/// - "GIT binary patch" markers
pub fn parse_patch_with_meta(text: &str) -> Result<DiffParseResult, DiffError> {
    // Normalize line endings (handle CRLF)
    let text = text.replace("\r\n", "\n");
    let lines: Vec<&str> = text.lines().collect();

    let mut result: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut current_diff_file: Option<String> = None;
    let mut current_new_line: u32 = 0;
    let mut in_hunk = false;

    // Track rename information
    let mut rename_to: Option<String> = None;
    // Track binary files
    let mut binary_files: BTreeSet<String> = BTreeSet::new();

    for line in lines {
        // Track diff header for fallback file identity
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let mut parts = rest.split_whitespace();
            let _a = parts.next();
            let b = parts.next();
            current_diff_file = b.map(normalize_path);
            continue;
        }

        // Check for rename to header
        if line.starts_with("rename to ") {
            rename_to = Some(normalize_path(line.strip_prefix("rename to ").unwrap()));
            continue;
        }

        // Detect binary file marker line
        if let Some(rest) = line.strip_prefix("Binary files ") {
            if let Some(and_pos) = rest.find(" and ") {
                let after_and = &rest[and_pos + 5..];
                let path_part = after_and.strip_suffix(" differ").unwrap_or(after_and);
                let path = path_part.trim();
                if path != "/dev/null" {
                    binary_files.insert(normalize_path(path));
                }
            }
            continue;
        }

        // Detect git binary patch marker
        if line.starts_with("GIT binary patch") {
            if let Some(path) = current_file.clone().or_else(|| current_diff_file.clone()) {
                binary_files.insert(path);
            }
            continue;
        }

        // Check for new file header (+++ line)
        if let Some(path) = line.strip_prefix("+++ ") {
            let path = path.trim();

            // Handle /dev/null (deleted files)
            if path == "/dev/null" {
                current_file = None;
                continue;
            }

            // Use rename target if available, otherwise normalize the path
            let normalized = if let Some(ref rename) = rename_to {
                rename.clone()
            } else {
                normalize_path(path)
            };

            current_file = Some(normalized);
            rename_to = None;
            in_hunk = false;
            continue;
        }

        // Check for hunk header
        if line.starts_with("@@ ") {
            if let Some(ref _file) = current_file {
                // Parse @@ -old_start,old_count +new_start,new_count @@
                if let Some(new_start) = parse_hunk_header(line) {
                    current_new_line = new_start;
                    in_hunk = true;
                } else {
                    return Err(DiffError::InvalidFormat(format!(
                        "malformed hunk header: '{}'",
                        line
                    )));
                }
            }
            continue;
        }

        // Process lines within a hunk
        if in_hunk && let Some(ref file) = current_file {
            if let Some(first_char) = line.chars().next() {
                match first_char {
                    '+' => {
                        // Added line (but not +++ header)
                        result
                            .entry(file.clone())
                            .or_default()
                            .push(current_new_line);
                        current_new_line += 1;
                    }
                    '-' => {
                        // Deleted line - doesn't affect new-side line numbers
                    }
                    ' ' => {
                        // Context line
                        current_new_line += 1;
                    }
                    '\\' => {
                        // "\ No newline at end of file" - ignore
                    }
                    _ => {
                        // Some diffs may have other content, treat as context
                        current_new_line += 1;
                    }
                }
            } else {
                // Empty line in the hunk, could be context
                current_new_line += 1;
            }
        }
    }

    // Convert line lists to merged ranges
    let mut ranges: ChangedRanges = BTreeMap::new();
    for (file, lines) in result {
        let line_ranges: Vec<RangeInclusive<u32>> = lines.into_iter().map(|l| l..=l).collect();
        ranges.insert(file, merge_ranges(line_ranges));
    }
    // Remove any binary files from the ranges
    for binary in &binary_files {
        ranges.remove(binary);
    }

    Ok(DiffParseResult {
        changed_ranges: ranges,
        binary_files: binary_files.into_iter().collect(),
    })
}

/// Parse a hunk header and return the new-side starting line number.
///
/// Hunk headers have the format: `@@ -old_start,old_count +new_start,new_count @@ optional context`
/// or: `@@ -old_start +new_start @@ optional context` (count defaults to 1)
fn parse_hunk_header(line: &str) -> Option<u32> {
    // Find the +new_start part
    let parts: Vec<&str> = line.split_whitespace().collect();

    for part in parts {
        if let Some(new_part) = part.strip_prefix('+') {
            // new_part is either "start,count" or just "start"
            let start_str = new_part.split(',').next()?;
            return start_str.parse().ok();
        }
    }

    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_b_prefix() {
        assert_eq!(normalize_path("b/src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_a_prefix() {
        assert_eq!(normalize_path("a/src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_dot_slash() {
        assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_backslash() {
        assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
        // After converting backslashes to forward slashes, b/ prefix is stripped
        assert_eq!(normalize_path("b\\src\\lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_normalize_path_combined() {
        // b/ is stripped first, then ./ is stripped
        assert_eq!(normalize_path("b/./src/lib.rs"), "src/lib.rs");
        // ./ is stripped, leaving b/src/lib.rs, then b/ is not at start so stays
        assert_eq!(normalize_path("./b/src/lib.rs"), "b/src/lib.rs");
    }

    #[test]
    fn test_normalize_path_no_change() {
        assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn test_merge_ranges_empty() {
        let result = merge_ranges(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_ranges_single() {
        let result = merge_ranges(vec![1..=5]);
        assert_eq!(result, vec![1..=5]);
    }

    #[test]
    fn test_merge_ranges_non_overlapping() {
        let result = merge_ranges(vec![1..=3, 7..=10]);
        assert_eq!(result, vec![1..=3, 7..=10]);
    }

    #[test]
    fn test_merge_ranges_overlapping() {
        let result = merge_ranges(vec![1..=5, 3..=8]);
        assert_eq!(result, vec![1..=8]);
    }

    #[test]
    fn test_merge_ranges_adjacent() {
        let result = merge_ranges(vec![1..=3, 4..=6]);
        assert_eq!(result, vec![1..=6]);
    }

    #[test]
    fn test_merge_ranges_unsorted() {
        // After sorting and merging: 1..=3, 2..=4 -> 1..=4
        // 5..=7, 8..=10 are adjacent (7+1=8), so merge to 5..=10
        // 1..=4 and 5..=10 are adjacent (4+1=5), so merge to 1..=10
        let result = merge_ranges(vec![5..=7, 1..=3, 2..=4, 8..=10]);
        assert_eq!(result, vec![1..=10]);
    }

    #[test]
    fn test_merge_ranges_contained() {
        let result = merge_ranges(vec![1..=10, 3..=5]);
        assert_eq!(result, vec![1..=10]);
    }

    #[test]
    fn test_parse_patch_simple_added() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=3]));
    }

    #[test]
    fn test_parse_patch_modified_file_multiple_hunks() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 pub fn add(a: i32, b: i32) -> i32 {
+    // Adding numbers
     a + b
 }
+
@@ -10,2 +12,4 @@
 fn other() {
+    // New comment
+    println!("hello");
 }
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        let file_ranges = ranges.get("src/lib.rs").unwrap();
        // Line 2 from first hunk, line 5 (empty line), lines 13-14 from second hunk
        assert_eq!(file_ranges, &vec![2..=2, 5..=5, 13..=14]);
    }

    #[test]
    fn test_parse_patch_deletion_only_hunk() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,5 +1,3 @@
 pub fn add(a: i32, b: i32) -> i32 {
-    // Old comment
-    // Another old comment
     a + b
 }
"#;

        let ranges = parse_patch(diff).unwrap();
        // No added lines, so file should not be in the map (or have empty ranges)
        assert!(!ranges.contains_key("src/lib.rs"));
    }

    #[test]
    fn test_parse_patch_rename() {
        let diff = r#"diff --git a/old_name.rs b/new_name.rs
similarity index 95%
rename from old_name.rs
rename to new_name.rs
index 1111111..2222222 100644
--- a/old_name.rs
+++ b/new_name.rs
@@ -1,3 +1,4 @@
 fn main() {
+    println!("added line");
     println!("Hello");
 }
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        // Should use the new name
        assert!(ranges.contains_key("new_name.rs"));
        assert_eq!(ranges.get("new_name.rs"), Some(&vec![2..=2]));
    }

    #[test]
    fn test_parse_patch_deleted_file() {
        let diff = r#"diff --git a/deleted.rs b/deleted.rs
deleted file mode 100644
index 1111111..0000000
--- a/deleted.rs
+++ /dev/null
@@ -1,3 +0,0 @@
-fn main() {
-    println!("goodbye");
-}
"#;

        let ranges = parse_patch(diff).unwrap();
        // Deleted file should not contribute any ranges
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_parse_patch_crlf() {
        let diff = "diff --git a/src/lib.rs b/src/lib.rs\r\n\
            new file mode 100644\r\n\
            index 0000000..1111111\r\n\
            --- /dev/null\r\n\
            +++ b/src/lib.rs\r\n\
            @@ -0,0 +1,2 @@\r\n\
            +line one\r\n\
            +line two\r\n";

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=2]));
    }

    #[test]
    fn test_parse_patch_multiple_files() {
        let diff = r#"diff --git a/src/a.rs b/src/a.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/a.rs
@@ -0,0 +1,2 @@
+fn a() {}
+fn b() {}
diff --git a/src/c.rs b/src/c.rs
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/src/c.rs
@@ -0,0 +1,1 @@
+fn c() {}
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges.get("src/a.rs"), Some(&vec![1..=2]));
        assert_eq!(ranges.get("src/c.rs"), Some(&vec![1..=1]));
    }

    #[test]
    fn test_parse_patch_no_newline_marker() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,2 @@
+fn main() {}
+fn other() {}
\ No newline at end of file
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=2]));
    }

    #[test]
    fn test_parse_patch_empty() {
        let ranges = parse_patch("").unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_parse_patch_binary_files_marker() {
        let diff = r#"diff --git a/assets/logo.png b/assets/logo.png
index 1111111..2222222
Binary files a/assets/logo.png and b/assets/logo.png differ
"#;

        let result = parse_patch_with_meta(diff).unwrap();
        assert!(result.changed_ranges.is_empty());
        assert_eq!(result.binary_files, vec!["assets/logo.png".to_string()]);
    }

    #[test]
    fn test_parse_patch_binary_files_marker_dev_null() {
        let diff = r#"diff --git a/assets/logo.png b/assets/logo.png
index 1111111..2222222
Binary files a/assets/logo.png and /dev/null differ
"#;

        let result = parse_patch_with_meta(diff).unwrap();
        assert!(result.changed_ranges.is_empty());
        assert!(result.binary_files.is_empty());
    }

    #[test]
    fn test_parse_patch_binary_files_marker_without_and() {
        let diff = r#"diff --git a/assets/logo.png b/assets/logo.png
index 1111111..2222222
Binary files a/assets/logo.png differ
"#;

        let result = parse_patch_with_meta(diff).unwrap();
        assert!(result.changed_ranges.is_empty());
        assert!(result.binary_files.is_empty());
    }

    #[test]
    fn test_parse_patch_git_binary_patch_marker() {
        let diff = r#"diff --git a/assets/data.bin b/assets/data.bin
index 1111111..2222222
GIT binary patch
literal 0
HcmV?d00001
"#;

        let result = parse_patch_with_meta(diff).unwrap();
        assert!(result.changed_ranges.is_empty());
        assert_eq!(result.binary_files, vec!["assets/data.bin".to_string()]);
    }

    #[test]
    fn test_parse_patch_malformed_hunk_header_returns_error() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,1 @@
+line
"#;

        let result = parse_patch(diff);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_patch_empty_line_in_hunk() {
        let diff = "diff --git a/src/lib.rs b/src/lib.rs\n\
index 1111111..2222222 100644\n\
--- a/src/lib.rs\n\
+++ b/src/lib.rs\n\
@@ -1,1 +1,3 @@\n\
+line1\n\
\n\
+line2\n";

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=1, 3..=3]));
    }

    #[test]
    fn test_parse_hunk_header_with_counts() {
        let line = "@@ -10,5 +20,8 @@ fn context()";
        assert_eq!(parse_hunk_header(line), Some(20));
    }

    #[test]
    fn test_parse_hunk_header_without_counts() {
        let line = "@@ -1 +1 @@";
        assert_eq!(parse_hunk_header(line), Some(1));
    }

    #[test]
    fn test_parse_hunk_header_missing_plus_returns_none() {
        let line = "@@ -10,5 @@ fn context()";
        assert_eq!(parse_hunk_header(line), None);
    }

    #[test]
    fn test_parse_hunk_header_new_file() {
        let line = "@@ -0,0 +1,3 @@";
        assert_eq!(parse_hunk_header(line), Some(1));
    }

    #[test]
    fn test_parse_patch_mixed_additions_deletions() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,5 +1,6 @@
 fn main() {
-    old_code();
+    new_code();
+    extra_code();
     common();
 }
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        // Lines 2 and 3 are the added lines (new_code and extra_code)
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![2..=3]));
    }

    #[test]
    fn test_parse_fixture_simple_added_patch() {
        // This matches the content of fixtures/diff/simple_added.patch
        let fixture_content = r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}
"#;

        let ranges = parse_patch(fixture_content).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![1..=3]));
    }

    #[test]
    fn test_parse_patch_context_without_leading_space() {
        // Some tools may generate diffs where context lines don't have a leading space
        // This tests that we handle that gracefully
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
fn main() {
+    println!("added");
}
"#;

        let ranges = parse_patch(diff).unwrap();
        assert_eq!(ranges.len(), 1);
        // Line 2 is the added line
        assert_eq!(ranges.get("src/lib.rs"), Some(&vec![2..=2]));
    }
}

// ============================================================================
// Property Tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn merge_ranges_produces_sorted_output(ranges in prop::collection::vec(1u32..1000, 0..50)) {
            let input: Vec<RangeInclusive<u32>> = ranges.iter().map(|&x| x..=x).collect();
            let merged = merge_ranges(input);

            // Check sorted
            for window in merged.windows(2) {
                prop_assert!(window[0].end() < window[1].start());
            }
        }

        #[test]
        fn merge_ranges_produces_non_overlapping_output(ranges in prop::collection::vec((1u32..500, 1u32..500), 0..30)) {
            let input: Vec<RangeInclusive<u32>> = ranges
                .into_iter()
                .map(|(start, len)| start..=(start + len))
                .collect();
            let merged = merge_ranges(input);

            // Check non-overlapping and non-adjacent
            for window in merged.windows(2) {
                let gap = *window[1].start() as i64 - *window[0].end() as i64;
                prop_assert!(gap >= 2, "Ranges should not be adjacent or overlapping: gap={}", gap);
            }
        }

        #[test]
        fn merge_ranges_is_idempotent(ranges in prop::collection::vec((1u32..500, 1u32..100), 0..20)) {
            let input: Vec<RangeInclusive<u32>> = ranges
                .into_iter()
                .map(|(start, len)| start..=(start + len))
                .collect();

            let merged_once = merge_ranges(input.clone());
            let merged_twice = merge_ranges(merged_once.clone());

            prop_assert_eq!(merged_once, merged_twice, "merge_ranges should be idempotent");
        }

        #[test]
        fn merge_ranges_preserves_all_values(values in prop::collection::vec(1u32..1000, 1..50)) {
            let input: Vec<RangeInclusive<u32>> = values.iter().map(|&x| x..=x).collect();
            let merged = merge_ranges(input);

            // Every input value should be contained in some output range
            for val in &values {
                let contained = merged.iter().any(|r| r.contains(val));
                prop_assert!(contained, "Value {} should be in merged ranges", val);
            }
        }

        #[test]
        fn normalize_path_never_panics(path in ".*") {
            let _ = normalize_path(&path);
        }

        #[test]
        fn normalize_path_removes_leading_b_prefix(suffix in "[a-z]+") {
            // Only test with suffixes that don't start with b/ to avoid "b/b/..." edge case
            prop_assume!(!suffix.starts_with("b"));
            let path = format!("b/{}", suffix);
            let normalized = normalize_path(&path);
            prop_assert!(!normalized.starts_with("b/"), "Should remove b/ prefix from {}", path);
        }
    }
}
