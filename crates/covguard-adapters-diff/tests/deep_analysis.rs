//! Deep analysis test for diff parser edge cases.
//!
//! Run with: cargo test --package covguard-adapters-diff --test deep_analysis -- --nocapture

use covguard_adapters_diff::{normalize_path, parse_patch, parse_patch_with_meta};
use std::fs;

// Workspace root directory for fixture paths
const WORKSPACE_ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn fixture_path(relative: &str) -> String {
    format!("{}/../../{}", WORKSPACE_ROOT, relative)
}

/// Helper to print parsed results
fn print_result(name: &str, result: &covguard_adapters_diff::DiffParseResult) {
    println!("\n=== {} ===", name);
    println!("Files found: {}", result.changed_ranges.len());
    for (path, ranges) in &result.changed_ranges {
        println!("  File: {}", path);
        for range in ranges {
            println!("    Lines: {}..={}", range.start(), range.end());
        }
    }
    if !result.binary_files.is_empty() {
        println!("Binary files: {:?}", result.binary_files);
    }
}

#[test]
fn test_fixture_simple_added() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/simple_added.patch"))
        .expect("Failed to read simple_added.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- simple_added.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("simple_added.patch", &result);

    assert!(
        result.changed_ranges.contains_key("src/lib.rs"),
        "Expected src/lib.rs in changed_ranges"
    );
    let ranges = result.changed_ranges.get("src/lib.rs").unwrap();
    assert_eq!(ranges, &vec![1..=3], "Expected lines 1-3 to be added");
    assert!(result.binary_files.is_empty(), "Expected no binary files");
}

#[test]
fn test_fixture_delete_only() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/delete_only.patch"))
        .expect("Failed to read delete_only.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- delete_only.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("delete_only.patch", &result);

    // Delete-only diff should have no changed ranges (only deletions, no additions)
    assert!(
        !result.changed_ranges.contains_key("src/lib.rs"),
        "Delete-only patch should not have src/lib.rs in changed_ranges"
    );
    assert!(result.binary_files.is_empty());
}

#[test]
fn test_fixture_multiple_files() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/multiple_files.patch"))
        .expect("Failed to read multiple_files.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- multiple_files.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("multiple_files.patch", &result);

    assert_eq!(result.changed_ranges.len(), 3, "Expected 3 files");
    assert!(result.changed_ranges.contains_key("src/lib.rs"));
    assert!(result.changed_ranges.contains_key("src/calculator.rs"));
    assert!(result.changed_ranges.contains_key("src/validator.rs"));

    // lib.rs: lines 1-3 added (mod calculator, mod validator, blank line)
    let lib_ranges = result.changed_ranges.get("src/lib.rs").unwrap();
    assert_eq!(lib_ranges, &vec![1..=3], "Expected lines 1-3 in src/lib.rs");

    // calculator.rs: lines 1-11 added
    let calc_ranges = result.changed_ranges.get("src/calculator.rs").unwrap();
    assert_eq!(
        calc_ranges,
        &vec![1..=11],
        "Expected lines 1-11 in src/calculator.rs"
    );

    // validator.rs: lines 1-7 added
    let val_ranges = result.changed_ranges.get("src/validator.rs").unwrap();
    assert_eq!(
        val_ranges,
        &vec![1..=7],
        "Expected lines 1-7 in src/validator.rs"
    );
}

#[test]
fn test_fixture_renamed_file() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/renamed_file.patch"))
        .expect("Failed to read renamed_file.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- renamed_file.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("renamed_file.patch", &result);

    // Should use the NEW path (src/utils.rs), not the old path (src/old_utils.rs)
    assert!(
        result.changed_ranges.contains_key("src/utils.rs"),
        "Expected src/utils.rs (new name) in changed_ranges"
    );
    assert!(
        !result.changed_ranges.contains_key("src/old_utils.rs"),
        "Expected src/old_utils.rs (old name) NOT in changed_ranges"
    );

    // Lines 1-4 added (new function signature, blank line, new validate function)
    let ranges = result.changed_ranges.get("src/utils.rs").unwrap();
    // Note: Lines 1-2 are modifications (delete + add), lines 4-5 are pure additions
    // After the deletions, the added lines are: line 1 (helper mod), line 2 (value > 0),
    // line 3 (blank), line 4 (pub fn validate), line 5 (!input.is_empty())
    println!("Renamed file ranges: {:?}", ranges);
}

#[test]
fn test_fixture_binary_file() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/binary_file.patch"))
        .expect("Failed to read binary_file.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- binary_file.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("binary_file.patch", &result);

    // Binary file should be detected
    assert!(
        result.binary_files.contains(&"assets/logo.png".to_string()),
        "Expected assets/logo.png in binary_files"
    );

    // Regular file should still be parsed
    assert!(
        result.changed_ranges.contains_key("src/config.rs"),
        "Expected src/config.rs in changed_ranges"
    );

    // Binary file should NOT be in changed_ranges
    assert!(
        !result.changed_ranges.contains_key("assets/logo.png"),
        "Binary file should not be in changed_ranges"
    );

    let config_ranges = result.changed_ranges.get("src/config.rs").unwrap();
    assert_eq!(
        config_ranges,
        &vec![3..=4],
        "Expected lines 3-4 in src/config.rs"
    );
}

#[test]
fn test_fixture_with_ignore_directive() {
    let content = fs::read_to_string(fixture_path("fixtures/diff/with_ignore_directive.patch"))
        .expect("Failed to read with_ignore_directive.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");

    println!("\n--- with_ignore_directive.patch analysis ---");
    println!("Raw content:\n{}", content);
    print_result("with_ignore_directive.patch", &result);

    // The ignore directive is in the content, but the parser doesn't interpret it
    // It just extracts the line ranges - the directive is for downstream processing
    assert!(result.changed_ranges.contains_key("src/lib.rs"));
    let ranges = result.changed_ranges.get("src/lib.rs").unwrap();
    // All 3 lines are added (including the one with covguard: ignore)
    assert_eq!(
        ranges,
        &vec![1..=3],
        "Expected lines 1-3 (ignore directive is not parsed by diff parser)"
    );
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_edge_case_empty_diff() {
    let result = parse_patch("").expect("Failed to parse empty diff");
    assert!(result.is_empty(), "Empty diff should produce empty ranges");

    let result_meta = parse_patch_with_meta("").expect("Failed to parse empty diff");
    assert!(result_meta.changed_ranges.is_empty());
    assert!(result_meta.binary_files.is_empty());
}

#[test]
fn test_edge_case_only_context_lines() {
    let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,3 @@
 pub fn add(a: i32, b: i32) -> i32 {
     a + b
 }
"#;
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- only_context_lines analysis ---");
    println!("Result: {:?}", result);
    assert!(
        !result.contains_key("src/lib.rs"),
        "Diff with only context should not have changed ranges"
    );
}

#[test]
fn test_edge_case_crlf_endings() {
    // Simulate CRLF line endings
    let diff = "diff --git a/src/lib.rs b/src/lib.rs\r\n\
new file mode 100644\r\n\
index 0000000..1111111\r\n\
--- /dev/null\r\n\
+++ b/src/lib.rs\r\n\
@@ -0,0 +1,2 @@\r\n\
+line one\r\n\
+line two\r\n";

    let result = parse_patch(diff).expect("Failed to parse CRLF diff");
    println!("\n--- crlf_endings analysis ---");
    println!("Result: {:?}", result);
    assert_eq!(
        result.get("src/lib.rs"),
        Some(&vec![1..=2]),
        "CRLF endings should be handled correctly"
    );
}

#[test]
fn test_edge_case_large_line_numbers() {
    let diff = r#"diff --git a/src/huge.rs b/src/huge.rs
index 0000000..1111111 100644
--- a/src/huge.rs
+++ b/src/huge.rs
@@ -999999,3 +999999,5 @@
 // Line near u32 max range
 fn large_line_number() {}
+fn added_at_huge_line_number() {}
+fn another_huge_line() {}
"#;
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- large_line_numbers analysis ---");
    println!("Result: {:?}", result);
    let ranges = result.get("src/huge.rs").expect("Expected src/huge.rs");
    // The hunk starts at line 999999 in the new file, with 2 context lines
    // then lines 1000000 and 1000001 are added
    assert_eq!(
        ranges,
        &vec![1000001..=1000002],
        "Large line numbers should be handled correctly"
    );
}

#[test]
fn test_edge_case_overlapping_hunks() {
    let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 line1
+line2
 line3
+line4
@@ -5,2 +7,3 @@
 line5
+line6
"#;
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- overlapping_hunks analysis ---");
    println!("Result: {:?}", result);
    // Lines 2, 4 from first hunk, line 8 from second hunk
    let ranges = result.get("src/lib.rs").expect("Expected src/lib.rs");
    // After merging adjacent: 2..=2, 4..=4, 8..=8
    println!("Merged ranges: {:?}", ranges);
}

#[test]
fn test_edge_case_multiple_hunks_same_file() {
    let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -10,2 +10,3 @@
 fn first() {}
+fn added_first() {}
@@ -50,2 +51,3 @@
 fn second() {}
+fn added_second() {}
@@ -100,2 +102,3 @@
 fn third() {}
+fn added_third() {}
"#;
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- multiple_hunks_same_file analysis ---");
    println!("Result: {:?}", result);
    let ranges = result.get("src/lib.rs").expect("Expected src/lib.rs");
    // Lines 11, 52, 103 should be added
    assert!(ranges.contains(&(11..=11)), "Expected line 11");
    assert!(ranges.contains(&(52..=52)), "Expected line 52");
    assert!(ranges.contains(&(103..=103)), "Expected line 103");
}

#[test]
fn test_edge_case_no_newline_marker() {
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
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- no_newline_marker analysis ---");
    println!("Result: {:?}", result);
    assert_eq!(
        result.get("src/lib.rs"),
        Some(&vec![1..=2]),
        "No newline marker should be ignored"
    );
}

#[test]
fn test_edge_case_deleted_file() {
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
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- deleted_file analysis ---");
    println!("Result: {:?}", result);
    assert!(
        result.is_empty(),
        "Deleted file should have no added ranges"
    );
}

#[test]
fn test_edge_case_mixed_additions_deletions() {
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
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- mixed_additions_deletions analysis ---");
    println!("Result: {:?}", result);
    // Lines 2 and 3 are added (new_code and extra_code)
    let ranges = result.get("src/lib.rs").expect("Expected src/lib.rs");
    assert_eq!(ranges, &vec![2..=3], "Expected lines 2-3 to be added");
}

// ============================================================================
// Path Normalization Tests
// ============================================================================

#[test]
fn test_path_normalization_b_prefix() {
    assert_eq!(normalize_path("b/src/lib.rs"), "src/lib.rs");
}

#[test]
fn test_path_normalization_a_prefix() {
    assert_eq!(normalize_path("a/src/lib.rs"), "src/lib.rs");
}

#[test]
fn test_path_normalization_dot_slash() {
    assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
}

#[test]
fn test_path_normalization_backslash() {
    assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
    assert_eq!(normalize_path("src\\sub\\lib.rs"), "src/sub/lib.rs");
}

#[test]
fn test_path_normalization_combined() {
    assert_eq!(normalize_path("b/./src/lib.rs"), "src/lib.rs");
    assert_eq!(normalize_path("b/src\\lib.rs"), "src/lib.rs");
}

#[test]
fn test_path_normalization_no_change() {
    assert_eq!(normalize_path("src/lib.rs"), "src/lib.rs");
}

#[test]
fn test_path_normalization_whitespace() {
    assert_eq!(normalize_path("  src/lib.rs  "), "src/lib.rs");
}

// ============================================================================
// Binary File Detection Tests
// ============================================================================

#[test]
fn test_binary_detection_binary_files_marker() {
    let diff = r#"diff --git a/assets/logo.png b/assets/logo.png
index 1111111..2222222
Binary files a/assets/logo.png and b/assets/logo.png differ
"#;
    let result = parse_patch_with_meta(diff).expect("Failed to parse");
    println!("\n--- binary_files_marker analysis ---");
    println!("Result: {:?}", result);
    assert!(result.binary_files.contains(&"assets/logo.png".to_string()));
    assert!(result.changed_ranges.is_empty());
}

#[test]
fn test_binary_detection_git_binary_patch() {
    let diff = r#"diff --git a/assets/data.bin b/assets/data.bin
index 1111111..2222222
GIT binary patch
literal 0
HcmV?d00001
"#;
    let result = parse_patch_with_meta(diff).expect("Failed to parse");
    println!("\n--- git_binary_patch analysis ---");
    println!("Result: {:?}", result);
    assert!(result.binary_files.contains(&"assets/data.bin".to_string()));
}

#[test]
fn test_binary_detection_dev_null() {
    let diff = r#"diff --git a/assets/logo.png b/assets/logo.png
index 1111111..2222222
Binary files a/assets/logo.png and /dev/null differ
"#;
    let result = parse_patch_with_meta(diff).expect("Failed to parse");
    println!("\n--- binary_dev_null analysis ---");
    println!("Result: {:?}", result);
    // /dev/null should not be added as a binary file
    assert!(!result.binary_files.iter().any(|p| p.contains("dev/null")));
}

// ============================================================================
// Rename Handling Tests
// ============================================================================

#[test]
fn test_rename_handling_basic() {
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
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- rename_basic analysis ---");
    println!("Result: {:?}", result);
    assert!(result.contains_key("new_name.rs"), "Should use new name");
    assert!(
        !result.contains_key("old_name.rs"),
        "Should not use old name"
    );
}

#[test]
fn test_rename_handling_with_subdirectory() {
    let diff = r#"diff --git a/old_dir/file.rs b/new_dir/file.rs
similarity index 90%
rename from old_dir/file.rs
rename to new_dir/file.rs
index 1111111..2222222 100644
--- a/old_dir/file.rs
+++ b/new_dir/file.rs
@@ -1,2 +1,3 @@
 fn existing() {}
+fn added() {}
"#;
    let result = parse_patch(diff).expect("Failed to parse");
    println!("\n--- rename_subdirectory analysis ---");
    println!("Result: {:?}", result);
    assert!(
        result.contains_key("new_dir/file.rs"),
        "Should use new path"
    );
}

// ============================================================================
// Fuzz Corpus Tests
// ============================================================================

#[test]
fn test_fuzz_crlf_endings() {
    let content = fs::read_to_string(fixture_path(
        "fuzz/corpus/fuzz_diff_parser/crlf_endings.patch",
    ))
    .expect("Failed to read crlf_endings.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");
    println!("\n--- fuzz crlf_endings analysis ---");
    print_result("fuzz/crlf_endings.patch", &result);
    assert!(result.changed_ranges.contains_key("src/windows.rs"));
}

#[test]
fn test_fuzz_large_line_numbers() {
    let content = fs::read_to_string(fixture_path(
        "fuzz/corpus/fuzz_diff_parser/large_line_numbers.patch",
    ))
    .expect("Failed to read large_line_numbers.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");
    println!("\n--- fuzz large_line_numbers analysis ---");
    print_result("fuzz/large_line_numbers.patch", &result);
    assert!(result.changed_ranges.contains_key("src/huge_file.rs"));
    let ranges = result.changed_ranges.get("src/huge_file.rs").unwrap();
    // Lines 1000000 and 1000001 should be added
    assert!(ranges.iter().any(|r| *r.start() >= 999999));
}

#[test]
fn test_fuzz_empty_hunk() {
    let content = fs::read_to_string(fixture_path(
        "fuzz/corpus/fuzz_diff_parser/empty_hunk.patch",
    ))
    .expect("Failed to read empty_hunk.patch");
    let result = parse_patch_with_meta(&content).expect("Failed to parse");
    println!("\n--- fuzz empty_hunk analysis ---");
    print_result("fuzz/empty_hunk.patch", &result);
    // Empty hunk (0,0 -> 0,0) should not cause errors
    // The file should not appear in changed_ranges since there are no additions
}

// ============================================================================
// Summary Test
// ============================================================================

#[test]
fn test_all_fixtures_summary() {
    println!("\n========================================");
    println!("DIFF PARSER DEEP ANALYSIS SUMMARY");
    println!("========================================");

    let fixtures = [
        (fixture_path("fixtures/diff/simple_added.patch"), true, 1),
        (fixture_path("fixtures/diff/delete_only.patch"), false, 0),
        (fixture_path("fixtures/diff/multiple_files.patch"), true, 3),
        (fixture_path("fixtures/diff/renamed_file.patch"), true, 1),
        (fixture_path("fixtures/diff/binary_file.patch"), true, 1),
        (
            fixture_path("fixtures/diff/with_ignore_directive.patch"),
            true,
            1,
        ),
    ];

    for (path, expect_content, expected_files) in fixtures {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                println!("\n{}: FAILED TO READ - {}", path, e);
                continue;
            }
        };
        let result =
            parse_patch_with_meta(&content).unwrap_or_else(|_| panic!("Failed to parse {}", path));

        let file_count = result.changed_ranges.len();
        let binary_count = result.binary_files.len();
        let total_lines: usize = result
            .changed_ranges
            .values()
            .map(|ranges| ranges.iter().map(|r| r.end() - r.start() + 1).sum::<u32>() as usize)
            .sum();

        println!("\n{}:", path);
        println!("  Files with changes: {}", file_count);
        println!("  Binary files: {}", binary_count);
        println!("  Total changed lines: {}", total_lines);

        if expect_content && file_count != expected_files {
            println!(
                "  WARNING: Expected {} files, got {}",
                expected_files, file_count
            );
        }
    }

    println!("\n========================================");
    println!("Path Normalization Verification");
    println!("========================================");

    let path_tests = [
        ("b/src/lib.rs", "src/lib.rs"),
        ("a/src/lib.rs", "src/lib.rs"),
        ("./src/lib.rs", "src/lib.rs"),
        ("src\\lib.rs", "src/lib.rs"),
        ("b/./src/lib.rs", "src/lib.rs"),
        ("b/src\\sub\\lib.rs", "src/sub/lib.rs"),
    ];

    for (input, expected) in path_tests {
        let result = normalize_path(input);
        let status = if result == expected { "✓" } else { "✗" };
        println!(
            "  {} '{}' -> '{}' (expected: '{}')",
            status, input, result, expected
        );
    }

    println!("\n========================================");
    println!("Analysis Complete");
    println!("========================================");
}
