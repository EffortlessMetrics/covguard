//! Integration tests for the covguard CLI.
//!
//! These tests exercise the CLI as a subprocess with real fixtures,
//! verifying exit codes, output files, and error handling.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Get a Command for the covguard binary.
fn covguard() -> Command {
    Command::new(env!("CARGO_BIN_EXE_covguard"))
}

/// Get the project root directory (for accessing fixtures).
fn project_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Get the path to a fixture file.
fn fixture(path: &str) -> String {
    project_root().join(path).display().to_string()
}

// ============================================================================
// Help and Version Tests
// ============================================================================

#[test]
fn test_help_displays_usage() {
    covguard()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("covguard"))
        .stdout(predicate::str::contains("check"));
}

#[test]
fn test_version_displays_version() {
    covguard()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("covguard"))
        .stdout(predicate::str::contains("0.2.0"));
}

#[test]
fn test_check_help_displays_options() {
    covguard()
        .args(["check", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--diff-file"))
        .stdout(predicate::str::contains("--lcov"))
        .stdout(predicate::str::contains("--out"))
        .stdout(predicate::str::contains("--md"))
        .stdout(predicate::str::contains("--raw"))
        .stdout(predicate::str::contains("--threshold"))
        .stdout(predicate::str::contains("--path-strip"))
        .stdout(predicate::str::contains("--root"));
}

#[test]
fn test_explain_outputs_code_info() {
    covguard()
        .args(["explain", "covguard.diff.uncovered_line"])
        .assert()
        .success()
        .stdout(predicate::str::contains("covguard.diff.uncovered_line"))
        .stdout(predicate::str::contains("Uncovered"));
}

// ============================================================================
// Basic Check Command Tests
// ============================================================================

#[test]
fn test_check_with_covered_lines_passes() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0); // Exit code 0 = pass

    // Verify report was written
    assert!(out.exists());

    // Verify report structure
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["schema"], "covguard.report.v1");
    assert_eq!(report["verdict"]["status"], "pass");
}

#[test]
fn test_check_with_uncovered_lines_fails() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2); // Exit code 2 = policy fail

    // Verify report was written
    assert!(out.exists());

    // Verify report structure
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["schema"], "covguard.report.v1");
    assert_eq!(report["verdict"]["status"], "fail");
    assert!(!report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn test_check_reads_diff_from_stdin() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let diff = fs::read_to_string(fixture("fixtures/diff/simple_added.patch")).unwrap();

    covguard()
        .args([
            "check",
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .write_stdin(diff)
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["data"]["inputs"]["diff_source"], "stdin");
    assert_eq!(report["verdict"]["status"], "pass");
}

// ============================================================================
// Advanced CLI Features
// ============================================================================

#[test]
fn test_check_with_multiple_lcov_merges_hits() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let lcov_a = temp.path().join("a.info");
    let lcov_b = temp.path().join("b.info");

    fs::write(
        &lcov_a,
        "TN:\nSF:src/lib.rs\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n",
    )
    .unwrap();
    fs::write(
        &lcov_b,
        "TN:\nSF:src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,1\nend_of_record\n",
    )
    .unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &lcov_a.display().to_string(),
            "--lcov",
            &lcov_b.display().to_string(),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "pass");
    assert_eq!(report["data"]["covered_lines"], 3);
    assert_eq!(report["data"]["uncovered_lines"], 0);
    assert_eq!(
        report["data"]["inputs"]["lcov_paths"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn test_check_with_path_strip_matches_absolute_paths() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let lcov_path = temp.path().join("coverage.info");

    fs::write(
        &lcov_path,
        "TN:\nSF:/tmp/repo/src/lib.rs\nDA:1,1\nDA:2,1\nDA:3,1\nend_of_record\n",
    )
    .unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &lcov_path.display().to_string(),
            "--path-strip",
            "/tmp/repo/",
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "pass");
    assert_eq!(report["data"]["covered_lines"], 3);
}

#[test]
fn test_check_honors_ignore_directives_from_filesystem() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();
    let out = root.join("report.json");
    let diff_path = root.join("diff.patch");
    let lcov_path = root.join("coverage.info");
    let src_dir = root.join("src");
    let src_file = src_dir.join("lib.rs");

    fs::create_dir_all(&src_dir).unwrap();
    fs::write(&src_file, "fn main() {}\n// covguard: ignore\n").unwrap();

    fs::write(
        &diff_path,
        "diff --git a/src/lib.rs b/src/lib.rs\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/src/lib.rs\n@@ -0,0 +1,2 @@\n+fn main() {}\n+// covguard: ignore\n",
    )
    .unwrap();

    fs::write(
        &lcov_path,
        "TN:\nSF:src/lib.rs\nDA:1,1\nDA:2,0\nend_of_record\n",
    )
    .unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &diff_path.display().to_string(),
            "--lcov",
            &lcov_path.display().to_string(),
            "--root",
            &root.display().to_string(),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "pass");
    assert_eq!(report["data"]["ignored_lines_count"], 1);
}

#[test]
fn test_check_writes_error_report_on_invalid_diff() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let diff_path = temp.path().join("invalid.patch");
    fs::write(&diff_path, "not a diff").unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &diff_path.display().to_string(),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "fail");
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect();
    assert!(codes.contains(&"covguard.input.invalid_diff"));
    assert!(codes.contains(&"tool.runtime_error"));
}

#[test]
fn test_check_writes_error_report_on_invalid_lcov() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let lcov_path = temp.path().join("invalid.info");
    fs::write(&lcov_path, "DA:1,1\nend_of_record\n").unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &lcov_path.display().to_string(),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "fail");
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["code"].as_str())
        .collect();
    assert!(codes.contains(&"covguard.input.invalid_lcov"));
    assert!(codes.contains(&"tool.runtime_error"));
}

// ============================================================================
// Output File Tests
// ============================================================================

#[test]
fn test_check_creates_output_directory() {
    let temp = TempDir::new().unwrap();
    let nested_out = temp.path().join("deep/nested/path/report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &nested_out.display().to_string(),
        ])
        .assert()
        .code(0);

    // Verify nested directories were created and report exists
    assert!(nested_out.exists());
}

#[test]
fn test_check_writes_markdown_output() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let md = temp.path().join("comment.md");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--md",
            &md.display().to_string(),
        ])
        .assert()
        .code(2);

    // Verify markdown was written
    assert!(md.exists());
    let md_content = fs::read_to_string(&md).unwrap();
    assert!(md_content.contains("covguard: Diff Coverage Report"));
    assert!(md_content.contains("fail"));
}

#[test]
fn test_check_writes_sarif_output() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let sarif = temp.path().join("results.sarif");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--sarif",
            &sarif.display().to_string(),
        ])
        .assert()
        .code(2);

    // Verify SARIF was written
    assert!(sarif.exists());
    let sarif_content: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&sarif).unwrap()).unwrap();
    assert_eq!(sarif_content["version"], "2.1.0");
    assert!(!sarif_content["runs"].as_array().unwrap().is_empty());
}

#[test]
fn test_check_writes_raw_artifacts() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let raw_dir = temp.path().join("artifacts/covguard/raw");

    covguard()
        .current_dir(temp.path())
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
            "--raw",
        ])
        .assert()
        .code(0);

    assert!(raw_dir.join("diff.patch").exists());
    assert!(raw_dir.join("lcov.info").exists());
}

#[test]
fn test_check_writes_annotations_to_stdout() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("::error file=src/lib.rs"));
}

// ============================================================================
// Argument Validation Tests
// ============================================================================

#[test]
fn test_check_requires_diff_source() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1) // Exit code 1 = runtime error
        .stderr(predicate::str::contains(
            "Must provide either --diff-file or both --base and --head",
        ));
}

#[test]
fn test_check_rejects_conflicting_diff_sources() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--base",
            "main",
            "--head",
            "HEAD",
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Cannot use --diff-file together with --base/--head",
        ));
}

#[test]
fn test_check_requires_both_base_and_head() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--base",
            "main",
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Must provide either --diff-file or both --base and --head",
        ));
}

#[test]
fn test_check_errors_on_missing_diff_file() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            "/nonexistent/file.patch",
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Failed to read file"));
}

#[test]
fn test_check_errors_on_missing_lcov_file() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            "/nonexistent/coverage.info",
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Failed to read file"));
}

// ============================================================================
// Scope Tests
// ============================================================================

#[test]
fn test_check_with_scope_added() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
            "--scope",
            "added",
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["data"]["scope"], "added");
}

#[test]
fn test_check_with_scope_touched() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
            "--scope",
            "touched",
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["data"]["scope"], "touched");
}

// ============================================================================
// Threshold Tests
// ============================================================================

#[test]
fn test_check_with_threshold_override() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // With 0% threshold, even uncovered lines should pass
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--threshold",
            "0",
        ])
        .assert()
        .code(2); // Still fails because of uncovered_lines findings

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["data"]["threshold_pct"], 0.0);
}

#[test]
fn test_check_with_high_threshold() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
            "--threshold",
            "100",
        ])
        .assert()
        .code(0); // Should still pass with 100% coverage

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["data"]["threshold_pct"], 100.0);
}

// ============================================================================
// Profile Tests
// ============================================================================

#[test]
fn test_check_with_profile_oss() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // OSS profile uses fail_on=never, so even uncovered lines should warn, not fail
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--profile",
            "oss",
        ])
        .assert()
        .code(0); // OSS profile uses fail_on=never

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    // Findings should be warnings, not errors
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
}

#[test]
fn test_check_with_profile_strict() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // Strict profile should fail on uncovered lines
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--profile",
            "strict",
        ])
        .assert()
        .code(2); // Policy fail
}

// ============================================================================
// No-Ignore Tests
// ============================================================================

#[test]
fn test_check_with_no_ignore_flag() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--no-ignore",
        ])
        .assert()
        .code(2);

    // The --no-ignore flag should be accepted
    assert!(out.exists());
}

// ============================================================================
// Multiple Files Tests
// ============================================================================

#[test]
fn test_check_with_multiple_files_diff() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // This fixture has some uncovered lines, so it will fail with code 2
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/multiple_files.patch"),
            "--lcov",
            &fixture("fixtures/lcov/multiple_files.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2); // Has uncovered lines

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    // Should have data about multiple files
    assert!(report["data"]["changed_lines_total"].as_u64().unwrap() > 0);
    // Should have uncovered lines
    assert!(report["data"]["uncovered_lines"].as_u64().unwrap() > 0);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_check_with_empty_diff() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let empty_diff = temp.path().join("empty.patch");
    fs::write(&empty_diff, "").unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &empty_diff.display().to_string(),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0); // Empty diff = pass

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["verdict"]["status"], "pass");
    assert_eq!(report["data"]["changed_lines_total"], 0);
}

#[test]
fn test_check_with_delete_only_diff() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/delete_only.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0); // Delete-only diff = pass (no added lines to check)
}

#[test]
fn test_check_with_binary_file_diff() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // Note: binary_file.patch also contains changes to src/config.rs
    // which has no coverage data, so this test verifies that binary
    // parts are ignored but text changes are still evaluated
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/binary_file.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2); // The text file changes have no coverage

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    // Binary files should be excluded from the changed lines count
    // Only src/config.rs changes should be counted
    let findings = report["findings"].as_array().unwrap();
    // All findings should be for the text file, not the binary
    for finding in findings {
        if let Some(loc) = finding.get("location") {
            let path = loc["path"].as_str().unwrap();
            assert!(!path.ends_with(".png"), "Binary file should be ignored");
        }
    }
}

// ============================================================================
// Report Content Verification Tests
// ============================================================================

#[test]
fn test_report_json_has_required_fields() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();

    // Check all required top-level fields
    assert!(report.get("schema").is_some());
    assert!(report.get("tool").is_some());
    assert!(report.get("run").is_some());
    assert!(report.get("verdict").is_some());
    assert!(report.get("findings").is_some());
    assert!(report.get("data").is_some());

    // Check tool fields
    assert!(report["tool"].get("name").is_some());
    assert!(report["tool"].get("version").is_some());

    // Check verdict fields
    assert!(report["verdict"].get("status").is_some());
    assert!(report["verdict"].get("counts").is_some());

    // Check data fields
    assert!(report["data"].get("scope").is_some());
    assert!(report["data"].get("threshold_pct").is_some());
    assert!(report["data"].get("diff_coverage_pct").is_some());
    assert!(report["data"].get("inputs").is_some());
}

#[test]
fn test_report_metrics_calculation() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    // All 3 lines are covered
    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();

    assert_eq!(report["data"]["changed_lines_total"], 3);
    assert_eq!(report["data"]["covered_lines"], 3);
    assert_eq!(report["data"]["uncovered_lines"], 0);
    assert_eq!(report["data"]["diff_coverage_pct"], 100.0);
}

#[test]
fn test_report_inputs_with_diff_file() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();

    assert_eq!(report["data"]["inputs"]["diff_source"], "diff-file");
    assert!(report["data"]["inputs"]["diff_file"].as_str().is_some());
    assert!(report["data"]["inputs"]["lcov_paths"].as_array().is_some());
}

// ============================================================================
// Finding Structure Tests
// ============================================================================

#[test]
fn test_findings_have_required_fields() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty());

    for finding in findings {
        assert!(finding.get("severity").is_some());
        assert!(finding.get("check_id").is_some());
        assert!(finding.get("code").is_some());
        assert!(finding.get("message").is_some());
    }
}

#[test]
fn test_findings_location_format() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(2);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    let findings = report["findings"].as_array().unwrap();

    for finding in findings {
        if let Some(location) = finding.get("location") {
            // Path should be repo-relative with forward slashes
            let path = location["path"].as_str().unwrap();
            assert!(!path.starts_with("./"), "Path should not start with ./");
            assert!(!path.starts_with("b/"), "Path should not have b/ prefix");
            assert!(
                !path.contains('\\'),
                "Path should use forward slashes: {}",
                path
            );

            // Line should be present and positive
            if let Some(line) = location.get("line") {
                assert!(line.as_u64().unwrap() > 0);
            }
        }
    }
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_output_is_deterministic() {
    let temp = TempDir::new().unwrap();
    let out1 = temp.path().join("report1.json");
    let out2 = temp.path().join("report2.json");

    for out in [&out1, &out2] {
        covguard()
            .args([
                "check",
                "--diff-file",
                &fixture("fixtures/diff/simple_added.patch"),
                "--lcov",
                &fixture("fixtures/lcov/uncovered.info"),
                "--out",
                &out.display().to_string(),
            ])
            .assert()
            .code(2);
    }

    let report1: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out1).unwrap()).unwrap();
    let report2: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out2).unwrap()).unwrap();

    // Compare everything except timestamps
    assert_eq!(report1["schema"], report2["schema"]);
    assert_eq!(report1["verdict"], report2["verdict"]);
    assert_eq!(report1["findings"], report2["findings"]);
    assert_eq!(report1["data"]["scope"], report2["data"]["scope"]);
    assert_eq!(
        report1["data"]["threshold_pct"],
        report2["data"]["threshold_pct"]
    );
    assert_eq!(
        report1["data"]["diff_coverage_pct"],
        report2["data"]["diff_coverage_pct"]
    );
}

// ============================================================================
// Cockpit Fallback Receipt Capability Reason Tests
// ============================================================================

#[test]
fn test_cockpit_no_diff_source_writes_missing_diff_reason() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0); // Cockpit mode writes fallback receipt and exits 0

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["diff"]["reason"],
        "missing_diff"
    );
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["coverage"]["reason"],
        "tool_error"
    );
}

#[test]
fn test_cockpit_conflicting_diff_writes_missing_diff_reason() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--base",
            "main",
            "--head",
            "HEAD",
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["diff"]["reason"],
        "missing_diff"
    );
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["coverage"]["reason"],
        "tool_error"
    );
}

#[test]
fn test_cockpit_nonexistent_file_writes_tool_error_reasons() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            "Z:\\nonexistent_drive_9999\\x.patch",
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["diff"]["reason"],
        "tool_error"
    );
    assert_eq!(
        report["run"]["capabilities"]["inputs"]["coverage"]["reason"],
        "tool_error"
    );
}

// ============================================================================
// Core Split: Cockpit Receipt vs Domain Payload Tests
// ============================================================================

#[test]
fn test_cockpit_mode_writes_receipt_to_out_and_payload_to_extras() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let extras_payload = temp.path().join("extras").join("payload.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    // --out should have cockpit receipt (sensor.report.v1)
    let receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(receipt["schema"], "sensor.report.v1");
    assert!(receipt["run"]["capabilities"].is_object());

    // extras/payload.json should have domain report (covguard.report.v1)
    assert!(
        extras_payload.exists(),
        "payload file should be created at default extras path"
    );
    let domain: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&extras_payload).unwrap()).unwrap();
    assert_eq!(domain["schema"], "covguard.report.v1");
    assert!(domain["run"]["capabilities"].is_null());
}

#[test]
fn test_cockpit_mode_writes_payload_to_custom_path() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let payload = temp.path().join("custom").join("payload.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
            "--payload",
            &payload.display().to_string(),
        ])
        .assert()
        .code(0);

    // --out should have cockpit receipt
    let receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(receipt["schema"], "sensor.report.v1");

    // --payload should have domain report
    assert!(payload.exists());
    let domain: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&payload).unwrap()).unwrap();
    assert_eq!(domain["schema"], "covguard.report.v1");
    assert!(domain["run"]["capabilities"].is_null());
}

#[test]
fn test_standard_mode_writes_domain_report_to_out() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");

    covguard()
        .args([
            "check",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/covered.info"),
            "--out",
            &out.display().to_string(),
        ])
        .assert()
        .code(0);

    // Standard mode --out should have domain report (covguard.report.v1)
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(report["schema"], "covguard.report.v1");
    assert!(report["run"]["capabilities"].is_null());
}

#[test]
fn test_cockpit_mode_receipt_truncated_payload_full() {
    let temp = TempDir::new().unwrap();
    let out = temp.path().join("report.json");
    let payload = temp.path().join("payload.json");

    covguard()
        .args([
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            &fixture("fixtures/diff/simple_added.patch"),
            "--lcov",
            &fixture("fixtures/lcov/uncovered.info"),
            "--out",
            &out.display().to_string(),
            "--payload",
            &payload.display().to_string(),
            "--max-findings",
            "1",
        ])
        .assert()
        .code(0);

    // Cockpit receipt should have truncated findings
    let receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(receipt["schema"], "sensor.report.v1");
    assert_eq!(receipt["findings"].as_array().unwrap().len(), 1);
    assert!(
        receipt["data"]["truncation"]["findings_truncated"]
            .as_bool()
            .unwrap()
    );

    // Domain payload should have ALL findings (no truncation)
    let domain: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&payload).unwrap()).unwrap();
    assert_eq!(domain["schema"], "covguard.report.v1");
    assert!(domain["findings"].as_array().unwrap().len() > 1);
    assert!(domain["data"]["truncation"].is_null());
}
