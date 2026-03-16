//! Deep analysis tests for LCOV parser to verify real coverage file handling.
//!
//! This test file validates:
//! - All fixture LCOV files
//! - Edge cases (empty, no DA, high hit counts, large line numbers)
//! - Path stripping with various prefixes
//! - Coverage merging behavior
//! - Error handling for malformed input

use covguard_adapters_coverage::{
    CoverageMap, LcovError, get_hits, merge_coverage, parse_lcov, parse_lcov_with_strip,
};
use std::collections::BTreeMap;

// ============================================================================
// Fixture File Tests
// ============================================================================

#[test]
fn test_fixture_covered_info() {
    let lcov = include_str!("../../../fixtures/lcov/covered.info");
    let coverage = parse_lcov(lcov).unwrap();

    // Should have exactly one file
    assert_eq!(coverage.len(), 1);
    assert!(coverage.contains_key("src/lib.rs"));

    // All lines should have hits = 1
    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(file.get(&1), Some(&1));
    assert_eq!(file.get(&2), Some(&1));
    assert_eq!(file.get(&3), Some(&1));
}

#[test]
fn test_fixture_uncovered_info() {
    let lcov = include_str!("../../../fixtures/lcov/uncovered.info");
    let coverage = parse_lcov(lcov).unwrap();

    // Should have exactly one file
    assert_eq!(coverage.len(), 1);
    assert!(coverage.contains_key("src/lib.rs"));

    // All lines should have hits = 0
    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(file.get(&1), Some(&0));
    assert_eq!(file.get(&2), Some(&0));
    assert_eq!(file.get(&3), Some(&0));
}

#[test]
fn test_fixture_partial_coverage_info() {
    let lcov = include_str!("../../../fixtures/lcov/partial_coverage.info");
    let coverage = parse_lcov(lcov).unwrap();

    // Should have exactly one file
    assert_eq!(coverage.len(), 1);
    assert!(coverage.contains_key("src/lib.rs"));

    // Mixed coverage: lines 1 and 3 covered, line 2 not
    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(file.get(&1), Some(&1)); // covered
    assert_eq!(file.get(&2), Some(&0)); // not covered
    assert_eq!(file.get(&3), Some(&1)); // covered
}

#[test]
fn test_fixture_multiple_files_info() {
    let lcov = include_str!("../../../fixtures/lcov/multiple_files.info");
    let coverage = parse_lcov(lcov).unwrap();

    // Should have three files
    assert_eq!(coverage.len(), 3);
    assert!(coverage.contains_key("src/lib.rs"));
    assert!(coverage.contains_key("src/calculator.rs"));
    assert!(coverage.contains_key("src/validator.rs"));

    // src/lib.rs - all 6 lines covered
    let lib = coverage.get("src/lib.rs").unwrap();
    assert_eq!(lib.len(), 6);
    for line in 1..=6 {
        assert_eq!(
            lib.get(&line),
            Some(&1),
            "src/lib.rs line {} should be covered",
            line
        );
    }

    // src/calculator.rs - 11 lines, some uncovered
    let calc = coverage.get("src/calculator.rs").unwrap();
    assert_eq!(calc.len(), 11);
    assert_eq!(
        calc.get(&4),
        Some(&0),
        "calculator line 4 should be uncovered"
    );
    assert_eq!(
        calc.get(&7),
        Some(&0),
        "calculator line 7 should be uncovered"
    );
    assert_eq!(
        calc.get(&8),
        Some(&0),
        "calculator line 8 should be uncovered"
    );

    // src/validator.rs - 7 lines, one uncovered
    let validator = coverage.get("src/validator.rs").unwrap();
    assert_eq!(validator.len(), 7);
    assert_eq!(
        validator.get(&4),
        Some(&0),
        "validator line 4 should be uncovered"
    );
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_lcov_file() {
    let coverage = parse_lcov("").unwrap();
    assert!(coverage.is_empty());
}

#[test]
fn test_lcov_with_only_whitespace() {
    let coverage = parse_lcov("   \n\t\n  ").unwrap();
    assert!(coverage.is_empty());
}

#[test]
fn test_lcov_with_only_comments_or_tn() {
    // TN: without any SF should result in empty coverage
    let coverage = parse_lcov("TN:test_name\n").unwrap();
    assert!(coverage.is_empty());
}

#[test]
fn test_sf_without_da_records() {
    // SF with end_of_record but no DA lines
    let lcov = r#"TN:
SF:src/empty.rs
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    // File should exist but have no line entries
    assert_eq!(coverage.len(), 1);
    let file = coverage.get("src/empty.rs").unwrap();
    assert!(file.is_empty());
}

#[test]
fn test_sf_without_da_or_end_of_record() {
    // SF at EOF without DA or end_of_record
    let lcov = "SF:src/empty.rs\n";
    let coverage = parse_lcov(lcov).unwrap();

    // File should exist but have no line entries
    assert_eq!(coverage.len(), 1);
    let file = coverage.get("src/empty.rs").unwrap();
    assert!(file.is_empty());
}

#[test]
fn test_high_hit_counts() {
    let lcov = r#"TN:
SF:src/hot_path.rs
DA:1,10000
DA:2,999999
DA:3,4294967295
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/hot_path.rs").unwrap();
    assert_eq!(file.get(&1), Some(&10000));
    assert_eq!(file.get(&2), Some(&999999));
    assert_eq!(file.get(&3), Some(&4294967295)); // max u32
}

#[test]
fn test_large_line_numbers() {
    let lcov = r#"TN:
SF:src/huge_file.rs
DA:1,1
DA:100000,1
DA:500000,0
DA:999999,1
DA:1000000,0
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/huge_file.rs").unwrap();
    assert_eq!(file.len(), 5);
    assert_eq!(file.get(&1), Some(&1));
    assert_eq!(file.get(&100000), Some(&1));
    assert_eq!(file.get(&500000), Some(&0));
    assert_eq!(file.get(&999999), Some(&1));
    assert_eq!(file.get(&1000000), Some(&0));
}

#[test]
fn test_sparse_line_coverage() {
    // Non-contiguous line numbers
    let lcov = r#"TN:
SF:src/sparse.rs
DA:5,1
DA:100,0
DA:500,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/sparse.rs").unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(file.get(&5), Some(&1));
    assert_eq!(file.get(&100), Some(&0));
    assert_eq!(file.get(&500), Some(&1));
    // Lines not in DA should not exist in map
    assert_eq!(file.get(&1), None);
    assert_eq!(file.get(&50), None);
}

// ============================================================================
// Path Normalization Tests
// ============================================================================

#[test]
fn test_path_normalization_relative() {
    let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_path_normalization_with_dot_slash() {
    let lcov = r#"TN:
SF:./src/lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_path_normalization_with_multiple_dot_slash() {
    let lcov = r#"TN:
SF:./././src/lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_path_normalization_absolute_unix() {
    let lcov = r#"TN:
SF:/home/user/project/src/lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    // Should strip to src/ marker
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_path_normalization_absolute_windows() {
    let lcov = r#"TN:
SF:C:\Users\dev\project\src\lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    // Should strip to src/ marker
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_path_normalization_lib_marker() {
    let lcov = r#"TN:
SF:/home/user/project/lib/module.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    // Should strip to lib/ marker
    assert!(coverage.contains_key("lib/module.rs"));
}

#[test]
fn test_path_normalization_test_marker() {
    let lcov = r#"TN:
SF:/home/user/project/test/integration.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    // Should strip to test/ marker
    assert!(coverage.contains_key("test/integration.rs"));
}

#[test]
fn test_path_normalization_backslashes() {
    let lcov = r#"TN:
SF:src\sub\lib.rs
DA:1,1
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();
    assert!(coverage.contains_key("src/sub/lib.rs"));
}

// ============================================================================
// Path Stripping with Custom Prefixes
// ============================================================================

#[test]
fn test_parse_with_strip_prefix() {
    let lcov = r#"TN:
SF:/home/runner/work/myproject/src/lib.rs
DA:1,1
end_of_record
"#;
    let strip_prefixes = vec!["/home/runner/work/myproject/".to_string()];
    let coverage = parse_lcov_with_strip(lcov, &strip_prefixes).unwrap();
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_parse_with_strip_prefix_windows() {
    let lcov = r#"TN:
SF:C:\build\workspace\src\main.rs
DA:1,1
end_of_record
"#;
    let strip_prefixes = vec!["C:\\build\\workspace\\".to_string()];
    let coverage = parse_lcov_with_strip(lcov, &strip_prefixes).unwrap();
    assert!(coverage.contains_key("src/main.rs"));
}

#[test]
fn test_parse_with_multiple_strip_prefixes() {
    // First matching prefix wins
    let lcov = r#"TN:
SF:/opt/build/src/lib.rs
DA:1,1
end_of_record
"#;
    let strip_prefixes = vec!["/home/runner/".to_string(), "/opt/build/".to_string()];
    let coverage = parse_lcov_with_strip(lcov, &strip_prefixes).unwrap();
    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_parse_strip_prefix_no_match_falls_back_to_marker() {
    let lcov = r#"TN:
SF:/unknown/path/src/lib.rs
DA:1,1
end_of_record
"#;
    let strip_prefixes = vec!["/different/prefix/".to_string()];
    let coverage = parse_lcov_with_strip(lcov, &strip_prefixes).unwrap();
    // Falls back to stripping at /src/ marker
    assert!(coverage.contains_key("src/lib.rs"));
}

// ============================================================================
// Merging Tests
// ============================================================================

#[test]
fn test_merge_empty_maps() {
    let merged = merge_coverage(vec![]);
    assert!(merged.is_empty());
}

#[test]
fn test_merge_single_map() {
    let mut map: CoverageMap = BTreeMap::new();
    let mut lines = BTreeMap::new();
    lines.insert(1, 5);
    map.insert("src/lib.rs".to_string(), lines);

    let merged = merge_coverage(vec![map]);
    assert_eq!(merged.len(), 1);
    assert_eq!(get_hits(&merged, "src/lib.rs", 1), Some(5));
}

#[test]
fn test_merge_disjoint_files() {
    let map1 = parse_lcov("SF:a.rs\nDA:1,1\nend_of_record\n").unwrap();
    let map2 = parse_lcov("SF:b.rs\nDA:1,1\nend_of_record\n").unwrap();

    let merged = merge_coverage(vec![map1, map2]);
    assert_eq!(merged.len(), 2);
    assert!(merged.contains_key("a.rs"));
    assert!(merged.contains_key("b.rs"));
}

#[test]
fn test_merge_same_file_different_lines() {
    let map1 = parse_lcov("SF:src/lib.rs\nDA:1,1\nDA:2,2\nend_of_record\n").unwrap();
    let map2 = parse_lcov("SF:src/lib.rs\nDA:3,3\nDA:4,4\nend_of_record\n").unwrap();

    let merged = merge_coverage(vec![map1, map2]);
    assert_eq!(merged.len(), 1);
    let file = merged.get("src/lib.rs").unwrap();
    assert_eq!(file.len(), 4);
    assert_eq!(file.get(&1), Some(&1));
    assert_eq!(file.get(&2), Some(&2));
    assert_eq!(file.get(&3), Some(&3));
    assert_eq!(file.get(&4), Some(&4));
}

#[test]
fn test_merge_same_line_takes_max() {
    let map1 = parse_lcov("SF:src/lib.rs\nDA:1,0\nDA:2,10\nend_of_record\n").unwrap();
    let map2 = parse_lcov("SF:src/lib.rs\nDA:1,5\nDA:2,3\nend_of_record\n").unwrap();

    let merged = merge_coverage(vec![map1, map2]);
    let file = merged.get("src/lib.rs").unwrap();
    assert_eq!(file.get(&1), Some(&5)); // max(0, 5)
    assert_eq!(file.get(&2), Some(&10)); // max(10, 3)
}

#[test]
fn test_merge_covered_with_uncovered() {
    // Merging covered with uncovered should result in covered
    let covered = include_str!("../../../fixtures/lcov/covered.info");
    let uncovered = include_str!("../../../fixtures/lcov/uncovered.info");

    let map1 = parse_lcov(covered).unwrap();
    let map2 = parse_lcov(uncovered).unwrap();

    let merged = merge_coverage(vec![map1, map2]);
    let file = merged.get("src/lib.rs").unwrap();

    // All lines should be covered (max of 1 and 0)
    assert_eq!(file.get(&1), Some(&1));
    assert_eq!(file.get(&2), Some(&1));
    assert_eq!(file.get(&3), Some(&1));
}

#[test]
fn test_merge_three_maps() {
    let map1 = parse_lcov("SF:x.rs\nDA:1,1\nend_of_record\n").unwrap();
    let map2 = parse_lcov("SF:x.rs\nDA:1,5\nend_of_record\n").unwrap();
    let map3 = parse_lcov("SF:x.rs\nDA:1,3\nend_of_record\n").unwrap();

    let merged = merge_coverage(vec![map1, map2, map3]);
    assert_eq!(get_hits(&merged, "x.rs", 1), Some(5)); // max(1, 5, 3)
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[test]
fn test_error_da_without_sf() {
    let lcov = "DA:1,5\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
    match result {
        Err(LcovError::MissingSourceFile { .. }) => {}
        _ => panic!("Expected MissingSourceFile error"),
    }
}

#[test]
fn test_error_invalid_da_missing_comma() {
    let lcov = "SF:src/lib.rs\nDA:123\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
    match result {
        Err(LcovError::InvalidDaRecord { .. }) => {}
        _ => panic!("Expected InvalidDaRecord error"),
    }
}

#[test]
fn test_error_invalid_da_missing_hits() {
    let lcov = "SF:src/lib.rs\nDA:123,\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
    match result {
        Err(LcovError::InvalidFormat { message, .. }) => {
            assert!(message.contains("Invalid hit count"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_error_invalid_line_number() {
    let lcov = "SF:src/lib.rs\nDA:abc,5\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
    match result {
        Err(LcovError::InvalidFormat { message, .. }) => {
            assert!(message.contains("Invalid line number"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_error_invalid_hit_count() {
    let lcov = "SF:src/lib.rs\nDA:5,xyz\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
    match result {
        Err(LcovError::InvalidFormat { message, .. }) => {
            assert!(message.contains("Invalid hit count"));
        }
        _ => panic!("Expected InvalidFormat error"),
    }
}

#[test]
fn test_error_negative_line_number_not_allowed() {
    // Negative numbers can't be parsed as u32
    let lcov = "SF:src/lib.rs\nDA:-1,5\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
}

#[test]
fn test_error_line_number_overflow() {
    // Number larger than u32::MAX
    let lcov = "SF:src/lib.rs\nDA:4294967296,1\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
}

// ============================================================================
// Fuzz Corpus Tests
// ============================================================================

#[test]
fn test_fuzz_corpus_empty_file_record() {
    let lcov = include_str!("../../../fuzz/corpus/fuzz_lcov_parser/empty_file_record.info");
    let coverage = parse_lcov(lcov).unwrap();

    // First file has no DA records
    let empty = coverage.get("src/empty.rs").unwrap();
    assert!(empty.is_empty());

    // Second file has DA records
    let nonempty = coverage.get("src/nonempty.rs").unwrap();
    assert_eq!(nonempty.len(), 2);
}

#[test]
fn test_fuzz_corpus_high_hit_count() {
    let lcov = include_str!("../../../fuzz/corpus/fuzz_lcov_parser/high_hit_count.info");
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/hot_path.rs").unwrap();
    assert_eq!(file.get(&1), Some(&10000));
    assert_eq!(file.get(&2), Some(&999999));
    assert_eq!(file.get(&3), Some(&4294967295)); // u32::MAX
}

#[test]
fn test_fuzz_corpus_large_line_numbers() {
    let lcov = include_str!("../../../fuzz/corpus/fuzz_lcov_parser/large_line_numbers.info");
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/huge_file.rs").unwrap();
    assert_eq!(file.get(&1000000), Some(&0));
}

#[test]
fn test_fuzz_corpus_minimal_valid() {
    let lcov = include_str!("../../../fuzz/corpus/fuzz_lcov_parser/minimal_valid.info");
    let coverage = parse_lcov(lcov).unwrap();

    // Minimal file named "a"
    assert!(coverage.contains_key("a"));
    let file = coverage.get("a").unwrap();
    assert_eq!(file.get(&1), Some(&0));
}

#[test]
fn test_fuzz_corpus_sparse_coverage() {
    let lcov = include_str!("../../../fuzz/corpus/fuzz_lcov_parser/sparse_coverage.info");
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/sparse.rs").unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(file.get(&5), Some(&1));
    assert_eq!(file.get(&100), Some(&0));
    assert_eq!(file.get(&500), Some(&1));
}

// ============================================================================
// Additional Edge Cases
// ============================================================================

#[test]
fn test_duplicate_sf_records_same_file() {
    // Same file appears twice - should merge with max hits
    let lcov = r#"TN:
SF:src/lib.rs
DA:1,1
DA:2,0
end_of_record
SF:src/lib.rs
DA:2,5
DA:3,3
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.get(&1), Some(&1));
    assert_eq!(file.get(&2), Some(&5)); // max(0, 5)
    assert_eq!(file.get(&3), Some(&3));
}

#[test]
fn test_da_before_end_of_record_without_sf() {
    // DA after end_of_record but before next SF is an error
    let lcov = "end_of_record\nDA:1,1\nSF:src/lib.rs\nDA:1,1\nend_of_record\n";
    let result = parse_lcov(lcov);
    assert!(result.is_err());
}

#[test]
fn test_trailing_whitespace_in_records() {
    let lcov = "TN:test  \nSF:src/lib.rs  \nDA:1,5  \nend_of_record  \n";
    let coverage = parse_lcov(lcov).unwrap();

    assert!(coverage.contains_key("src/lib.rs"));
    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.get(&1), Some(&5));
}

#[test]
fn test_crlf_line_endings() {
    let lcov = "TN:\r\nSF:src/lib.rs\r\nDA:1,1\r\nend_of_record\r\n";
    let coverage = parse_lcov(lcov).unwrap();

    assert!(coverage.contains_key("src/lib.rs"));
}

#[test]
fn test_zero_hit_count_is_valid() {
    let lcov = "SF:src/lib.rs\nDA:1,0\nend_of_record\n";
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.get(&1), Some(&0));
}

#[test]
fn test_line_number_one_is_valid() {
    let lcov = "SF:src/lib.rs\nDA:1,100\nend_of_record\n";
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/lib.rs").unwrap();
    assert_eq!(file.get(&1), Some(&100));
}

#[test]
fn test_multiple_da_same_line_takes_last_within_record() {
    // Within a single record, last DA for same line wins
    // (This is implementation-defined behavior - testing current impl)
    let lcov = r#"TN:
SF:src/lib.rs
DA:1,5
DA:1,10
DA:1,3
end_of_record
"#;
    let coverage = parse_lcov(lcov).unwrap();

    let file = coverage.get("src/lib.rs").unwrap();
    // Current implementation takes max during merge_file_coverage
    // But within a single record, it inserts sequentially, so last wins
    assert_eq!(file.get(&1), Some(&3)); // Last value inserted
}
