//! BDD/Cucumber test harness for covguard.
//!
//! This module implements step definitions for the Gherkin feature files
//! located in `bdd/features/`. It uses the cucumber-rs crate to parse
//! feature files and execute step definitions.
//!
//! Run with: `cargo test --test bdd`

use std::collections::{BTreeMap, BTreeSet};

use covguard_app::{CheckRequest, FailOn, MissingBehavior, check};
use covguard_types::{CODE_UNCOVERED_LINE, Scope, Severity, VerdictStatus};
use cucumber::{World, given, then, when};

/// The world state for BDD tests.
///
/// This struct holds the state between steps in a scenario.
#[derive(Debug, Default, World)]
pub struct CovguardWorld {
    /// The diff text (patch format).
    diff_text: String,
    /// The LCOV coverage text inputs.
    lcov_texts: Vec<String>,
    /// The scope of lines to evaluate.
    scope: Scope,
    /// The coverage threshold percentage.
    threshold_pct: f64,
    /// Optional uncovered line buffer.
    max_uncovered_lines: Option<u32>,
    /// Determines when the evaluation should fail.
    fail_on: FailOn,
    /// Whether to honor ignore directives.
    ignore_directives: bool,
    /// Pre-computed ignored lines for testing.
    ignored_lines: BTreeMap<String, BTreeSet<u32>>,
    /// The result of running check().
    result: Option<covguard_app::CheckResult>,
    /// Whether an error occurred during check.
    check_error: Option<String>,
    /// The file path used in the current scenario.
    current_file: String,
    /// The line number used for ignore directive scenarios.
    ignore_line: u32,
    /// Additional files used in multi-file scenarios.
    additional_files: Vec<String>,
    /// Include glob patterns.
    include_patterns: Vec<String>,
    /// Exclude glob patterns.
    exclude_patterns: Vec<String>,
    /// LCOV path-strip prefixes.
    path_strip: Vec<String>,
    /// Missing-line coverage behavior.
    missing_coverage: MissingBehavior,
    /// Missing-file coverage behavior.
    missing_file: MissingBehavior,
    /// Optional max findings cap.
    max_findings: Option<usize>,
    /// Whether to expect an error from the check.
    expect_error: bool,
}

fn set_single_lcov(world: &mut CovguardWorld, text: String) {
    world.lcov_texts = vec![text];
}

// ============================================================================
// Background Steps
// ============================================================================

/// Background step: ignore directives are disabled by default.
#[given("ignore directives are disabled")]
fn given_ignore_directives_disabled(world: &mut CovguardWorld) {
    world.ignore_directives = false;
    world.ignored_lines.clear();
    world.scope = Scope::Added;
    world.threshold_pct = 80.0;
    world.max_uncovered_lines = None;
    world.fail_on = FailOn::Error;
    world.include_patterns.clear();
    world.exclude_patterns.clear();
    world.path_strip.clear();
    world.missing_coverage = MissingBehavior::Warn;
    world.missing_file = MissingBehavior::Warn;
    world.max_findings = None;
    world.expect_error = false;
}

/// Background step: enable ignore directives.
#[given("ignore directives are enabled")]
fn given_ignore_directives_enabled(world: &mut CovguardWorld) {
    world.ignore_directives = true;
}

// ============================================================================
// Given Steps - Diff Setup
// ============================================================================

/// Given a diff with added lines in a specific file.
#[given(expr = "a diff with added lines in {string}")]
fn given_diff_with_added_lines(world: &mut CovguardWorld, file_path: String) {
    // Normalize path by removing leading ./
    let normalized = file_path.trim_start_matches("./").to_string();
    world.current_file = normalized.clone();
    // Create a diff that adds 3 lines to the specified file
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{file}
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {{
+    a + b
+}}
"#,
        file = normalized
    );
}

/// Given a diff adding N lines to a specific file.
#[given(expr = "a diff adding {int} lines to {string}")]
fn given_diff_adding_n_lines(world: &mut CovguardWorld, num_lines: i32, file_path: String) {
    world.current_file = file_path.clone();

    // Build the diff content with the specified number of lines
    let mut lines = String::new();
    for i in 1..=num_lines {
        lines.push_str(&format!("+    line_{}\n", i));
    }

    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{file}
@@ -0,0 +1,{num} @@
{lines}"#,
        file = file_path,
        num = num_lines,
        lines = lines
    );
}

/// Given a diff that only deletes lines from a specific file.
#[given(expr = "a diff that only deletes lines from {string}")]
fn given_diff_with_only_deletions(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
    // Create a diff that only removes lines (no additions)
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
index 1111111..2222222
--- a/{file}
+++ b/{file}
@@ -1,5 +1,2 @@
 pub fn add(a: i32, b: i32) -> i32 {{
-    // This comment will be removed
-    // And this one too
-    // And this third one
     a + b
 }}
"#,
        file = file_path
    );
}

/// Given a diff that modifies existing lines in a specific file.
#[given(expr = "a diff that modifies existing lines in {string}")]
fn given_diff_with_modifications(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
    // Create a diff that modifies existing lines (delete + add on same position)
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
index 1111111..2222222
--- a/{file}
+++ b/{file}
@@ -1,3 +1,3 @@
 pub fn add(a: i32, b: i32) -> i32 {{
-    a + b
+    a + b + 1
 }}
"#,
        file = file_path
    );
}

/// Given an empty diff.
#[given("an empty diff")]
fn given_empty_diff(world: &mut CovguardWorld) {
    world.diff_text = String::new();
}

/// Given a diff with only context changes (no additions or deletions).
#[given(expr = "a diff with only context changes in {string}")]
fn given_diff_with_only_context(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
    // A diff with only context lines (no + or - lines that matter)
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
index 1111111..2222222
--- a/{file}
+++ b/{file}
@@ -1,3 +1,3 @@
 pub fn add(a: i32, b: i32) -> i32 {{
     a + b
 }}
"#,
        file = file_path
    );
}

/// Given a diff that modifies a binary file.
#[given("a diff that modifies a binary file")]
fn given_diff_with_binary(world: &mut CovguardWorld) {
    world.diff_text = r#"diff --git a/image.png b/image.png
new file mode 100644
index 0000000..1234567
Binary files /dev/null and b/image.png differ
"#
    .to_string();
}

/// Given a diff adding line at a specific number.
#[given(expr = "a diff adding line {int} to {string}")]
fn given_diff_adding_specific_line(world: &mut CovguardWorld, line_num: i32, file_path: String) {
    world.current_file = file_path.clone();
    // Create a diff that adds at a specific line number
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
index 1111111..2222222
--- a/{file}
+++ b/{file}
@@ -{start},0 +{line},1 @@
+    new_line_content
"#,
        file = file_path,
        start = line_num - 1,
        line = line_num
    );
}

/// Given a diff adding uncovered lines to multiple files (in specified order).
#[given(expr = "a diff adding uncovered lines to {string}, {string}, and {string}")]
fn given_diff_adding_to_three_files(
    world: &mut CovguardWorld,
    file1: String,
    file2: String,
    file3: String,
) {
    world.current_file = file1.clone();
    world.additional_files = vec![file2.clone(), file3.clone()];

    // Create a diff with multiple files in the specified order
    world.diff_text = format!(
        r#"diff --git a/{f1} b/{f1}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{f1}
@@ -0,0 +1,2 @@
+fn f1() {{}}
+fn f1b() {{}}
diff --git a/{f2} b/{f2}
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/{f2}
@@ -0,0 +1,2 @@
+fn f2() {{}}
+fn f2b() {{}}
diff --git a/{f3} b/{f3}
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/{f3}
@@ -0,0 +1,2 @@
+fn f3() {{}}
+fn f3b() {{}}
"#,
        f1 = file1,
        f2 = file2,
        f3 = file3
    );
}

/// Given a diff adding lines to multiple files (two files).
#[given(expr = "a diff adding lines to {string} and {string}")]
fn given_diff_adding_to_two_files(world: &mut CovguardWorld, file1: String, file2: String) {
    world.current_file = file1.clone();
    world.additional_files = vec![file2.clone()];

    world.diff_text = format!(
        r#"diff --git a/{f1} b/{f1}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{f1}
@@ -0,0 +1,2 @@
+fn main() {{}}
+fn helper() {{}}
diff --git a/{f2} b/{f2}
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/{f2}
@@ -0,0 +1,2 @@
+fn other() {{}}
+fn utility() {{}}
"#,
        f1 = file1,
        f2 = file2
    );
}

/// Given a diff adding lines to multiple files (generic).
#[given("a diff adding lines to multiple files")]
fn given_diff_adding_to_multiple_files(world: &mut CovguardWorld) {
    world.current_file = "src/a.rs".to_string();
    world.additional_files = vec!["src/b.rs".to_string()];

    world.diff_text = r#"diff --git a/src/a.rs b/src/a.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/a.rs
@@ -0,0 +1,2 @@
+fn a1() {}
+fn a2() {}
diff --git a/src/b.rs b/src/b.rs
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/src/b.rs
@@ -0,0 +1,2 @@
+fn b1() {}
+fn b2() {}
"#
    .to_string();
}

/// Given a diff with added lines containing ignore directive in a file.
#[given(expr = "a diff with added lines containing {string} in {string}")]
fn given_diff_with_ignore_directive_in_file(
    world: &mut CovguardWorld,
    directive: String,
    file_path: String,
) {
    world.current_file = file_path.clone();
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{file}
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {{
+    a + b // {directive}
+}}
"#,
        file = file_path,
        directive = directive
    );
}

/// Given an invalid diff text.
#[given(expr = "an invalid diff text {string}")]
fn given_invalid_diff(world: &mut CovguardWorld, text: String) {
    world.diff_text = text;
}

/// Given a diff that renames a file with changes.
#[given(expr = "a diff that renames {string} to {string} with changes")]
fn given_diff_rename_with_changes(world: &mut CovguardWorld, old_path: String, new_path: String) {
    world.current_file = new_path.clone();
    world.diff_text = format!(
        r#"diff --git a/{old} b/{new}
similarity index 80%
rename from {old}
rename to {new}
index 1111111..2222222 100644
--- a/{old}
+++ b/{new}
@@ -1,2 +1,4 @@
 pub fn existing() {{}}
+pub fn new_func() {{}}
+pub fn another() {{}}
+pub fn third() {{}}
"#,
        old = old_path,
        new = new_path
    );
}

/// Given a diff that renames a file without changes.
#[given(expr = "a diff that renames {string} to {string} without changes")]
fn given_diff_rename_without_changes(
    world: &mut CovguardWorld,
    old_path: String,
    new_path: String,
) {
    world.current_file = new_path.clone();
    world.diff_text = format!(
        r#"diff --git a/{old} b/{new}
similarity index 100%
rename from {old}
rename to {new}
"#,
        old = old_path,
        new = new_path
    );
}

/// Given a file where an added line contains a specific directive.
#[given(expr = "a file where an added line contains {string}")]
fn given_file_with_ignore_directive(world: &mut CovguardWorld, directive: String) {
    world.current_file = "src/lib.rs".to_string();
    world.ignore_line = 2; // The line with the ignore directive

    // Create a diff that adds lines, one of which contains the directive
    world.diff_text = format!(
        r#"diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {{
+    a + b // {directive}
+}}
"#,
        directive = directive
    );

    // Pre-compute the ignored lines since we can't read from the filesystem
    let mut ignored = BTreeSet::new();
    ignored.insert(world.ignore_line);
    world
        .ignored_lines
        .insert(world.current_file.clone(), ignored);
}

// ============================================================================
// Given Steps - LCOV Setup
// ============================================================================

/// And an LCOV report where those lines have 0 hits.
#[given("an LCOV report where those lines have 0 hits")]
fn given_lcov_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report where all lines are covered.
#[given("an LCOV report where all lines are covered")]
fn given_lcov_all_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,5
DA:2,5
DA:3,5
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report with any values.
#[given("an LCOV report with any values")]
fn given_lcov_any_values(world: &mut CovguardWorld) {
    let file = if world.current_file.is_empty() {
        "src/lib.rs"
    } else {
        &world.current_file
    };
    // Provide some coverage data
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,1
DA:2,1
end_of_record
"#,
            file = file
        ),
    );
}

/// And LCOV reports that line has 0 hits.
#[given("LCOV reports that line has 0 hits")]
fn given_lcov_ignore_line_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    // All lines including the ignored one have 0 hits
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report where modified lines have 0 hits.
#[given("an LCOV report where modified lines have 0 hits")]
fn given_lcov_modified_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,1
DA:2,0
DA:3,1
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report where line 2 is covered but lines 1 and 3 are not.
#[given("an LCOV report where line 2 is covered but lines 1 and 3 are not")]
fn given_lcov_partial_middle_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,5
DA:3,0
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report with N% line coverage.
#[given(expr = "an LCOV report with {int}% line coverage")]
fn given_lcov_with_percent_coverage(world: &mut CovguardWorld, percent: i32) {
    let file = &world.current_file;
    // For 10 lines, calculate how many should be covered
    let covered_count = percent / 10;

    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=10 {
        let hits = if i <= covered_count { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report with {int} uncovered lines")]
fn given_lcov_with_n_uncovered_lines(world: &mut CovguardWorld, num_lines: i32) {
    let file = &world.current_file;
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=num_lines {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

/// And an LCOV report where 3 lines are covered and 2 are not.
#[given("an LCOV report where 3 lines are covered and 2 are not")]
fn given_lcov_3_covered_2_not(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,1
DA:2,1
DA:3,1
DA:4,0
DA:5,0
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report where line N has 0 hits.
#[given(expr = "an LCOV report where line {int} has 0 hits")]
fn given_lcov_specific_line_uncovered(world: &mut CovguardWorld, line_num: i32) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:{line},0
end_of_record
"#,
            file = file,
            line = line_num
        ),
    );
}

/// And an LCOV report where all added lines have 0 hits.
#[given("an LCOV report where all added lines have 0 hits")]
fn given_lcov_all_added_uncovered(world: &mut CovguardWorld) {
    let mut lcov = String::from("TN:\n");

    // Add LCOV data for main file
    lcov.push_str(&format!("SF:{}\n", world.current_file));
    lcov.push_str("DA:1,0\n");
    lcov.push_str("DA:2,0\n");
    lcov.push_str("end_of_record\n");

    // Add LCOV data for additional files
    for file in &world.additional_files {
        lcov.push_str(&format!("SF:{}\n", file));
        lcov.push_str("DA:1,0\n");
        lcov.push_str("DA:2,0\n");
        lcov.push_str("end_of_record\n");
    }

    set_single_lcov(world, lcov);
}

/// And an LCOV report where "src/a.rs" is covered and "src/b.rs" is not.
#[given(expr = "an LCOV report where {string} is covered and {string} is not")]
fn given_lcov_mixed_coverage(
    world: &mut CovguardWorld,
    covered_file: String,
    uncovered_file: String,
) {
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{covered}
DA:1,5
DA:2,5
end_of_record
SF:{uncovered}
DA:1,0
DA:2,0
end_of_record
"#,
            covered = covered_file,
            uncovered = uncovered_file
        ),
    );
}

/// And an LCOV report that only covers a specific file.
#[given(expr = "an LCOV report that only covers {string}")]
fn given_lcov_only_covers_one_file(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,5
DA:2,5
end_of_record
"#,
            file = file_path
        ),
    );
}

/// And an empty LCOV report.
#[given("an empty LCOV report")]
fn given_empty_lcov(world: &mut CovguardWorld) {
    world.lcov_texts = vec![String::new()];
}

/// And an invalid LCOV text.
#[given(expr = "an invalid LCOV text {string}")]
fn given_invalid_lcov(world: &mut CovguardWorld, text: String) {
    set_single_lcov(world, text);
}

/// And an LCOV report with explicit zero hits.
#[given("an LCOV report with explicit zero hits")]
fn given_lcov_explicit_zero(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,0
DA:3,0
LH:0
LF:3
end_of_record
"#,
            file = file
        ),
    );
}

/// And an LCOV report for a specific file with 0 hits.
#[given(expr = "an LCOV report for {string} with 0 hits")]
fn given_lcov_for_file_uncovered(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,0
DA:3,0
DA:4,0
end_of_record
"#,
            file = file_path
        ),
    );
}

/// And an LCOV report for normalized path.
#[given(expr = "an LCOV report for normalized path {string} with 0 hits")]
fn given_lcov_for_normalized_path(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,0
DA:2,0
DA:3,0
end_of_record
"#,
            file = file_path
        ),
    );
}

/// And an LCOV report with separate entries for both files fully covered.
#[given("an LCOV report with separate entries for both files fully covered")]
fn given_lcov_both_files_covered(world: &mut CovguardWorld) {
    let file1 = &world.current_file;
    let file2 = world
        .additional_files
        .first()
        .map(|s| s.as_str())
        .unwrap_or("src/other.rs");
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{f1}
DA:1,5
DA:2,5
end_of_record
SF:{f2}
DA:1,5
DA:2,5
end_of_record
"#,
            f1 = file1,
            f2 = file2
        ),
    );
}

/// And an LCOV report where all lines have a specific hit count.
#[given(expr = "an LCOV report where all lines have {int} hits")]
fn given_lcov_all_lines_hits(world: &mut CovguardWorld, hits: i32) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,{hits}
DA:2,{hits}
DA:3,{hits}
end_of_record
"#,
            file = file,
            hits = hits
        ),
    );
}

/// And an LCOV report where 1 line is covered and 2 are not.
#[given("an LCOV report where 1 line is covered and 2 are not")]
fn given_lcov_one_of_three_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            r#"TN:
SF:{file}
DA:1,1
DA:2,0
DA:3,0
end_of_record
"#,
            file = file
        ),
    );
}

#[given("multiple LCOV inputs are merged by max hits")]
fn given_multiple_lcov_inputs(world: &mut CovguardWorld) {
    let file = &world.current_file;
    world.lcov_texts = vec![
        format!(
            "TN:\nSF:{file}\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n",
            file = file
        ),
        format!(
            "TN:\nSF:{file}\nDA:1,5\nDA:2,0\nDA:3,0\nend_of_record\n",
            file = file
        ),
    ];
}

#[given(
    expr = "an LCOV report with absolute SF paths under {string} where those lines have 0 hits"
)]
fn given_lcov_absolute_paths(world: &mut CovguardWorld, prefix: String) {
    let file = &world.current_file;
    let absolute = format!(
        "{}{}",
        prefix.trim_end_matches('/'),
        format!("/{}", file).replace('\\', "/")
    );
    set_single_lcov(
        world,
        format!(
            "TN:\nSF:{absolute}\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n",
            absolute = absolute
        ),
    );
}

// ============================================================================
// Given Steps - Configuration
// ============================================================================

/// And a coverage threshold of N%.
#[given(expr = "a coverage threshold of {int}%")]
fn given_threshold(world: &mut CovguardWorld, threshold: i32) {
    world.threshold_pct = threshold as f64;
}

#[given(expr = "a path strip prefix {string}")]
fn given_path_strip_prefix(world: &mut CovguardWorld, prefix: String) {
    world.path_strip = vec![prefix];
}

#[given(expr = "exclude patterns are {string}")]
fn given_exclude_patterns(world: &mut CovguardWorld, patterns: String) {
    world.exclude_patterns = patterns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
}

#[given(expr = "include patterns are {string}")]
fn given_include_patterns(world: &mut CovguardWorld, patterns: String) {
    world.include_patterns = patterns
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
}

#[given(expr = "max findings is {int}")]
fn given_max_findings(world: &mut CovguardWorld, max: i32) {
    world.max_findings = Some(max as usize);
}

// ============================================================================
// When Steps
// ============================================================================

/// When covguard checks coverage with a specific profile.
#[when(expr = "covguard checks coverage with profile {string}")]
fn when_check_with_profile(world: &mut CovguardWorld, profile: String) {
    match profile.as_str() {
        "strict" => {
            world.fail_on = FailOn::Error;
            world.threshold_pct = 90.0;
            world.scope = Scope::Touched;
            world.max_uncovered_lines = Some(5);
            world.missing_coverage = MissingBehavior::Fail;
            world.missing_file = MissingBehavior::Fail;
        }
        "oss" => {
            world.fail_on = FailOn::Never;
            world.threshold_pct = 70.0;
            world.scope = Scope::Added;
            world.max_uncovered_lines = None;
            world.missing_coverage = MissingBehavior::Skip;
            world.missing_file = MissingBehavior::Skip;
        }
        "moderate" => {
            world.fail_on = FailOn::Error;
            world.threshold_pct = 75.0;
            world.scope = Scope::Added;
            world.max_uncovered_lines = None;
            world.missing_coverage = MissingBehavior::Warn;
            world.missing_file = MissingBehavior::Skip;
        }
        "team" => {
            world.fail_on = FailOn::Error;
            world.threshold_pct = 80.0;
            world.scope = Scope::Added;
            world.max_uncovered_lines = None;
            world.missing_coverage = MissingBehavior::Warn;
            world.missing_file = MissingBehavior::Warn;
        }
        "lenient" => {
            world.fail_on = FailOn::Never;
            world.threshold_pct = 0.0;
            world.scope = Scope::Added;
            world.max_uncovered_lines = None;
            world.missing_coverage = MissingBehavior::Warn;
            world.missing_file = MissingBehavior::Warn;
        }
        _ => {
            world.fail_on = FailOn::Error;
            world.threshold_pct = 80.0;
            world.scope = Scope::Added;
            world.max_uncovered_lines = None;
            world.missing_coverage = MissingBehavior::Warn;
            world.missing_file = MissingBehavior::Warn;
        }
    }

    run_check(world);
}

/// When covguard checks coverage with a specific scope.
#[when(expr = "covguard checks coverage with scope {string}")]
fn when_check_with_scope(world: &mut CovguardWorld, scope: String) {
    world.scope = match scope.as_str() {
        "added" => Scope::Added,
        "touched" => Scope::Touched,
        _ => Scope::Added,
    };
    world.max_uncovered_lines = None;
    world.missing_coverage = MissingBehavior::Warn;
    world.missing_file = MissingBehavior::Warn;
    if world.threshold_pct == 0.0 {
        world.threshold_pct = 80.0;
    }
    if world.fail_on == FailOn::Never {
        world.fail_on = FailOn::Error;
    }

    run_check(world);
}

/// When covguard checks with a specific fail_on mode.
#[when(expr = "covguard checks with fail_on {string}")]
fn when_check_with_fail_on(world: &mut CovguardWorld, fail_on: String) {
    world.fail_on = match fail_on.as_str() {
        "error" => FailOn::Error,
        "warn" => FailOn::Warn,
        "never" => FailOn::Never,
        _ => FailOn::Error,
    };
    world.max_uncovered_lines = None;
    world.missing_coverage = MissingBehavior::Warn;
    world.missing_file = MissingBehavior::Warn;
    if world.threshold_pct == 0.0 {
        world.threshold_pct = 100.0;
    }
    world.scope = Scope::Added;

    run_check(world);
}

/// When covguard checks coverage (with defaults).
#[when("covguard checks coverage")]
fn when_check_default(world: &mut CovguardWorld) {
    world.max_uncovered_lines = None;
    if world.fail_on == FailOn::Never && world.threshold_pct == 0.0 {
        // Reset to defaults if not set
        world.fail_on = FailOn::Error;
        world.threshold_pct = 80.0;
    }
    if world.threshold_pct == 0.0 {
        world.threshold_pct = 80.0;
    }
    world.scope = Scope::Added;
    world.missing_coverage = MissingBehavior::Warn;
    world.missing_file = MissingBehavior::Warn;

    run_check(world);
}

/// When covguard checks coverage expecting an error.
#[when("covguard checks coverage expecting an error")]
fn when_check_expecting_error(world: &mut CovguardWorld) {
    world.expect_error = true;
    world.fail_on = FailOn::Error;
    world.threshold_pct = 80.0;
    world.scope = Scope::Added;
    world.max_uncovered_lines = None;
    world.missing_coverage = MissingBehavior::Warn;
    world.missing_file = MissingBehavior::Warn;

    run_check_with_error_handling(world);
}

/// Helper function to run the check.
fn run_check(world: &mut CovguardWorld) {
    run_check_with_error_handling(world);
}

/// Helper function to run the check with error handling.
fn run_check_with_error_handling(world: &mut CovguardWorld) {
    let request = CheckRequest {
        diff_text: world.diff_text.clone(),
        diff_file_path: Some("test.patch".to_string()),
        base_ref: None,
        head_ref: None,
        lcov_texts: world.lcov_texts.clone(),
        lcov_paths: (0..world.lcov_texts.len())
            .map(|idx| format!("coverage-{}.info", idx + 1))
            .collect(),
        max_uncovered_lines: world.max_uncovered_lines,
        missing_coverage: world.missing_coverage,
        missing_file: world.missing_file,
        include_patterns: world.include_patterns.clone(),
        exclude_patterns: world.exclude_patterns.clone(),
        path_strip: world.path_strip.clone(),
        threshold_pct: world.threshold_pct,
        scope: world.scope,
        fail_on: world.fail_on,
        ignore_directives: world.ignore_directives,
        max_findings: world.max_findings,
        ignored_lines: if world.ignored_lines.is_empty() {
            None
        } else {
            Some(world.ignored_lines.clone())
        },
        ..Default::default()
    };

    match check(request) {
        Ok(result) => {
            world.result = Some(result);
            world.check_error = None;
        }
        Err(e) => {
            world.check_error = Some(e.to_string());
            world.result = None;
        }
    }
}

// ============================================================================
// Then Steps - Verdict Assertions
// ============================================================================

/// Then the verdict is a specific status.
#[then(expr = "the verdict is {string}")]
fn then_verdict_is(world: &mut CovguardWorld, expected_status: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual_status = match result.report.verdict.status {
        VerdictStatus::Pass => "pass",
        VerdictStatus::Warn => "warn",
        VerdictStatus::Fail => "fail",
        VerdictStatus::Skip => "skip",
    };

    assert_eq!(
        actual_status, expected_status,
        "Expected verdict '{}' but got '{}'",
        expected_status, actual_status
    );
}

#[then(expr = "the verdict reasons include {string}")]
fn then_verdict_reasons_include(world: &mut CovguardWorld, expected_reason: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result
            .report
            .verdict
            .reasons
            .iter()
            .any(|reason| reason == &expected_reason),
        "Expected verdict reasons to include '{}', but got {:?}",
        expected_reason,
        result.report.verdict.reasons
    );
}

/// And the exit code is a specific value.
#[then(expr = "the exit code is {int}")]
fn then_exit_code_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(
        result.exit_code, expected,
        "Expected exit code {} but got {}",
        expected, result.exit_code
    );
}

// ============================================================================
// Then Steps - Findings Assertions
// ============================================================================

/// And findings include a specific code.
#[then(expr = "findings include code {string}")]
fn then_findings_include_code(world: &mut CovguardWorld, expected_code: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let has_code = result
        .report
        .findings
        .iter()
        .any(|f| f.code == expected_code);

    assert!(
        has_code,
        "Expected findings to include code '{}', but found: {:?}",
        expected_code,
        result
            .report
            .findings
            .iter()
            .map(|f| &f.code)
            .collect::<Vec<_>>()
    );
}

/// And findings count is a specific value.
#[then(expr = "findings count is {int}")]
fn then_findings_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.findings.len() as i32;

    assert_eq!(
        actual, expected,
        "Expected {} findings but got {}",
        expected, actual
    );
}

/// Then all findings have a specific severity.
#[then(expr = "all findings have severity {string}")]
fn then_all_findings_have_severity(world: &mut CovguardWorld, expected_severity: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let expected = match expected_severity.as_str() {
        "error" => Severity::Error,
        "warn" | "warning" => Severity::Warn,
        "info" => Severity::Info,
        _ => panic!("Unknown severity: {}", expected_severity),
    };

    for finding in &result.report.findings {
        assert_eq!(
            finding.severity, expected,
            "Expected all findings to have severity {:?} but found {:?}",
            expected, finding.severity
        );
    }
}

/// Then findings exist for a specific file.
#[then(expr = "findings exist for file {string}")]
fn then_findings_exist_for_file(world: &mut CovguardWorld, file_path: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let has_finding = result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path)
            .unwrap_or(false)
    });

    assert!(
        has_finding,
        "Expected findings for file '{}' but found none",
        file_path
    );
}

/// And no findings exist for a specific file.
#[then(expr = "no findings exist for file {string}")]
fn then_no_findings_for_file(world: &mut CovguardWorld, file_path: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let has_finding = result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path)
            .unwrap_or(false)
    });

    assert!(
        !has_finding,
        "Expected no findings for file '{}' but found some",
        file_path
    );
}

/// Then a finding exists for a specific file at a specific line.
#[then(expr = "a finding exists for file {string} at line {int}")]
fn then_finding_exists_at_location(world: &mut CovguardWorld, file_path: String, line_num: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let has_finding = result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path && loc.line == Some(line_num as u32))
            .unwrap_or(false)
    });

    assert!(
        has_finding,
        "Expected finding for file '{}' at line {} but found none. Findings: {:?}",
        file_path, line_num, result.report.findings
    );
}

/// Then findings are sorted by path then line number.
#[then("findings are sorted by path then line number")]
fn then_findings_are_sorted(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let findings = &result.report.findings;

    for i in 1..findings.len() {
        let prev = &findings[i - 1];
        let curr = &findings[i];

        let prev_loc = prev.location.as_ref();
        let curr_loc = curr.location.as_ref();

        if let (Some(prev_loc), Some(curr_loc)) = (prev_loc, curr_loc) {
            let path_cmp = prev_loc.path.cmp(&curr_loc.path);
            let is_sorted = match path_cmp {
                std::cmp::Ordering::Less => true,
                std::cmp::Ordering::Equal => prev_loc.line <= curr_loc.line,
                std::cmp::Ordering::Greater => false,
            };

            assert!(
                is_sorted,
                "Findings are not sorted: {:?} should come before {:?}",
                prev_loc, curr_loc
            );
        }
    }
}

// ============================================================================
// Then Steps - Metrics Assertions
// ============================================================================

/// And changed_lines_total is a specific value.
#[then(expr = "changed_lines_total is {int}")]
fn then_changed_lines_total_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.changed_lines_total as i32;

    assert_eq!(
        actual, expected,
        "Expected changed_lines_total to be {} but got {}",
        expected, actual
    );
}

/// And covered_lines is a specific value.
#[then(expr = "covered_lines is {int}")]
fn then_covered_lines_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.covered_lines as i32;

    assert_eq!(
        actual, expected,
        "Expected covered_lines to be {} but got {}",
        expected, actual
    );
}

/// And uncovered_lines is a specific value.
#[then(expr = "uncovered_lines is {int}")]
fn then_uncovered_lines_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.uncovered_lines as i32;

    assert_eq!(
        actual, expected,
        "Expected uncovered_lines to be {} but got {}",
        expected, actual
    );
}

/// And missing_lines is greater than 0.
#[then("missing_lines is greater than 0")]
fn then_missing_lines_greater_than_zero(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.missing_lines;

    assert!(
        actual > 0,
        "Expected missing_lines to be greater than 0 but got {}",
        actual
    );
}

/// And coverage_pct is a specific value.
#[then(expr = "coverage_pct is {float}")]
fn then_coverage_pct_is(world: &mut CovguardWorld, expected: f64) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.diff_coverage_pct;

    assert!(
        (actual - expected).abs() < 0.01,
        "Expected diff_coverage_pct to be {} but got {}",
        expected,
        actual
    );
}

/// And coverage_pct is approximately a value (with tolerance).
#[then(expr = "coverage_pct is approximately {float}")]
fn then_coverage_pct_approximately(world: &mut CovguardWorld, expected: f64) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.diff_coverage_pct;

    assert!(
        (actual - expected).abs() < 1.0,
        "Expected diff_coverage_pct to be approximately {} but got {}",
        expected,
        actual
    );
}

/// Then the ignored line is excluded from evaluation.
#[then("the ignored line is excluded from evaluation")]
fn then_ignored_line_excluded(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");

    // Check that there's no finding for the ignored line
    let ignored_line = world.ignore_line;
    let has_finding_for_ignored = result.report.findings.iter().any(|f| {
        f.code == CODE_UNCOVERED_LINE
            && f.location
                .as_ref()
                .map(|loc| loc.line == Some(ignored_line))
                .unwrap_or(false)
    });

    assert!(
        !has_finding_for_ignored,
        "Expected ignored line {} to be excluded from findings, but found a finding for it",
        ignored_line
    );
}

/// And ignored_lines_count is a specific value.
#[then(expr = "ignored_lines_count is {int}")]
fn then_ignored_lines_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.ignored_lines_count as i32;

    assert_eq!(
        actual, expected,
        "Expected ignored_lines_count to be {} but got {}",
        expected, actual
    );
}

#[then(expr = "excluded_files_count is {int}")]
fn then_excluded_files_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = result.report.data.excluded_files_count as i32;
    assert_eq!(
        actual, expected,
        "Expected excluded_files_count {} but got {}",
        expected, actual
    );
}

#[then(expr = "truncation is present with shown {int}")]
fn then_truncation_shown(world: &mut CovguardWorld, shown: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let trunc = result
        .report
        .data
        .truncation
        .as_ref()
        .expect("expected truncation metadata");
    assert_eq!(trunc.shown as i32, shown);
    assert!(trunc.findings_truncated);
}

#[then("truncation total is greater than shown")]
fn then_truncation_total_gt_shown(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let trunc = result
        .report
        .data
        .truncation
        .as_ref()
        .expect("expected truncation metadata");
    assert!(
        trunc.total > trunc.shown,
        "Expected truncation.total ({}) > truncation.shown ({})",
        trunc.total,
        trunc.shown
    );
}

#[then(expr = "debug binary_files_count is {int}")]
fn then_debug_binary_files_count(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let debug = result
        .report
        .data
        .debug
        .as_ref()
        .expect("expected debug metadata");
    let actual = debug["binary_files_count"]
        .as_u64()
        .expect("binary_files_count should be a number") as i32;
    assert_eq!(
        actual, expected,
        "Expected debug.binary_files_count {} but got {}",
        expected, actual
    );
}

#[then(expr = "debug includes binary file {string}")]
fn then_debug_includes_binary_file(world: &mut CovguardWorld, expected_file: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let debug = result
        .report
        .data
        .debug
        .as_ref()
        .expect("expected debug metadata");
    let files = debug["binary_files"]
        .as_array()
        .expect("binary_files should be an array");
    let has_file = files
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|path| path == expected_file);
    assert!(
        has_file,
        "Expected debug.binary_files to include '{}', got {:?}",
        expected_file, files
    );
}

// ============================================================================
// Then Steps - Error Handling
// ============================================================================

/// Then the check fails with an error.
#[then("the check fails with an error")]
fn then_check_fails_with_error(world: &mut CovguardWorld) {
    assert!(
        world.check_error.is_some(),
        "Expected check to fail with an error, but it succeeded"
    );
}

/// Then the check succeeds without error.
#[then("the check succeeds without error")]
fn then_check_succeeds(world: &mut CovguardWorld) {
    assert!(
        world.check_error.is_none(),
        "Expected check to succeed, but got error: {:?}",
        world.check_error
    );
}

// ============================================================================
// Then Steps - Output Format Assertions
// ============================================================================

/// Then the markdown output contains a specific string.
#[then(expr = "the markdown output contains {string}")]
fn then_markdown_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let markdown = covguard_app::render_markdown(&result.report);

    assert!(
        markdown.to_lowercase().contains(&expected.to_lowercase()),
        "Expected markdown to contain '{}', but got: {}",
        expected,
        markdown
    );
}

/// Then the SARIF output is valid JSON.
#[then("the SARIF output is valid JSON")]
fn then_sarif_is_valid_json(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let sarif = covguard_app::render_sarif(&result.report);

    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&sarif);
    assert!(
        parsed.is_ok(),
        "Expected SARIF to be valid JSON, but got parse error: {:?}",
        parsed.err()
    );
}

/// Then the SARIF output contains a specific string.
#[then(expr = "the SARIF output contains {string}")]
fn then_sarif_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let sarif = covguard_app::render_sarif(&result.report);

    assert!(
        sarif.contains(&expected),
        "Expected SARIF to contain '{}', but got: {}",
        expected,
        sarif
    );
}

/// Then the annotations output contains a specific string.
#[then(expr = "the annotations output contains {string}")]
fn then_annotations_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let annotations = covguard_app::render_annotations(&result.report);

    assert!(
        annotations.contains(&expected),
        "Expected annotations to contain '{}', but got: {}",
        expected,
        annotations
    );
}

#[then(expr = "annotations rendered with limit {int} contain at most {int} entries")]
fn then_annotations_with_limit_count(world: &mut CovguardWorld, limit: i32, max_count: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let annotations = covguard_app::render_annotations_with_limit(&result.report, limit as usize);
    let actual = annotations
        .lines()
        .filter(|line| line.starts_with("::"))
        .count() as i32;
    assert!(
        actual <= max_count,
        "Expected at most {} annotations with limit {}, got {}",
        max_count,
        limit,
        actual
    );
    assert!(actual > 0, "Expected at least one annotation");
}

/// Then the report scope is a specific value.
#[then(expr = "the report scope is {string}")]
fn then_report_scope_is(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");

    assert_eq!(
        result.report.data.scope, expected,
        "Expected report scope to be '{}' but got '{}'",
        expected, result.report.data.scope
    );
}

/// Then the report has valid tool info.
#[then("the report has valid tool info")]
fn then_report_has_tool_info(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");

    assert_eq!(result.report.tool.name, "covguard");
    assert!(!result.report.tool.version.is_empty());
    assert!(!result.report.run.started_at.is_empty());
}

#[then("re-running the same check yields identical report JSON")]
fn then_rerun_is_deterministic(world: &mut CovguardWorld) {
    let first = world.result.as_ref().expect("check should have been run");
    let first_value =
        serde_json::to_value(&first.report).expect("first report should serialize to JSON");

    run_check(world);

    let second = world.result.as_ref().expect("second check should have run");
    let second_value =
        serde_json::to_value(&second.report).expect("second report should serialize to JSON");

    assert_eq!(first_value["schema"], second_value["schema"]);
    assert_eq!(first_value["tool"], second_value["tool"]);
    assert_eq!(first_value["verdict"], second_value["verdict"]);
    assert_eq!(first_value["data"], second_value["data"]);
    assert_eq!(first_value["findings"], second_value["findings"]);
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    // Run cucumber tests from the bdd/features directory
    futures::executor::block_on(CovguardWorld::cucumber().run("../../bdd/features"));
}
