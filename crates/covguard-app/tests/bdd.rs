//! BDD/Cucumber test harness for covguard.
//!
//! This module implements step definitions for the Gherkin feature files
//! located in `bdd/features/`. It uses the cucumber-rs crate to parse
//! feature files and execute step definitions.
//!
//! Run with: `cargo test --test bdd`

use std::collections::{BTreeMap, BTreeSet};

use covguard_app::{CheckRequest, FailOn, MissingBehavior, check};
use covguard_output_features::OutputFeatureFlags;
use covguard_policy::{Scope as PolicyScope, profile_defaults, profile_from_name};
use covguard_types::{Scope, Severity, VerdictStatus};
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
    /// The coverage inputs (content, path, format).
    coverage_inputs: Vec<(String, String, covguard_types::CoverageFormat)>,
    /// The coverage format to use for checks.
    coverage_format: covguard_types::CoverageFormat,
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
    /// Renderer output budgets for markdown/annotations/SARIF.
    output_flags: OutputFeatureFlags,
    /// Whether to expect an error from the check.
    expect_error: bool,
    /// Whether to use sensor schema mode (enables skip verdicts).
    sensor_schema: bool,
}

fn set_single_lcov(world: &mut CovguardWorld, text: String) {
    world.lcov_texts = vec![text];
}

// ============================================================================
// Background Steps
// ============================================================================

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
    world.output_flags = OutputFeatureFlags::default();
    world.expect_error = false;
    world.sensor_schema = false;
    world.coverage_inputs.clear();
    world.lcov_texts.clear();
}

#[given("ignore directives are enabled")]
fn given_ignore_directives_enabled(world: &mut CovguardWorld) {
    world.ignore_directives = true;
}

// ============================================================================
// Given Steps - Diff Setup
// ============================================================================

#[given(expr = "a diff with added lines in {string}")]
fn given_diff_with_added_lines(world: &mut CovguardWorld, file_path: String) {
    let normalized = file_path.trim_start_matches("./").to_string();
    world.current_file = normalized.clone();
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

#[given(expr = "a diff adding lines to {string}")]
fn given_diff_adding_lines(world: &mut CovguardWorld, file_path: String) {
    given_diff_with_added_lines(world, file_path);
}

#[given(expr = "a diff adding {int} lines to {string}")]
fn given_diff_adding_n_lines(world: &mut CovguardWorld, num_lines: i32, file_path: String) {
    let mut lines = String::new();
    for i in 1..=num_lines {
        lines.push_str(&format!("+    line_{}\n", i));
    }
    let new_diff = format!(
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
    if world.diff_text.is_empty() {
        world.current_file = file_path;
        world.diff_text = new_diff;
    } else {
        world.additional_files.push(file_path);
        world.diff_text.push_str(&new_diff);
    }
}

#[given(expr = "a diff adding {int} line to {string}")]
fn given_diff_adding_one_line(world: &mut CovguardWorld, num_lines: i32, file_path: String) {
    given_diff_adding_n_lines(world, num_lines, file_path);
}

#[given(expr = "a diff with overlapping hunks in {string}")]
fn given_diff_with_overlapping_hunks(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
    world.diff_text = format!(
        r#"diff --git a/{file} b/{file}
index 1111111..2222222 100644
--- a/{file}
+++ b/{file}
@@ -0,0 +1,2 @@
+line1
+line2
@@ -0,0 +2,2 @@
+line2_again
+line3
"#,
        file = file_path
    );
}

#[given(expr = "a diff that only deletes lines from {string}")]
fn given_diff_with_only_deletions(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
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

#[given(expr = "a diff that modifies existing lines in {string}")]
fn given_diff_with_modifications(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
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

#[given("an empty diff")]
fn given_empty_diff(world: &mut CovguardWorld) {
    world.diff_text = String::new();
}

#[given(expr = "a diff with only context changes in {string}")]
fn given_diff_with_only_context(world: &mut CovguardWorld, file_path: String) {
    world.current_file = file_path.clone();
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

#[given("a diff that modifies a binary file")]
fn given_diff_with_binary(world: &mut CovguardWorld) {
    world.diff_text = r#"diff --git a/image.png b/image.png
new file mode 100644
index 0000000..1234567
Binary files /dev/null and b/image.png differ
"#
    .to_string();
}

#[given(expr = "a diff adding line {int} to {string}")]
fn given_diff_adding_specific_line(world: &mut CovguardWorld, line_num: i32, file_path: String) {
    world.current_file = file_path.clone();
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

#[given(expr = "a diff adding uncovered lines to {string}, {string}, and {string}")]
fn given_diff_adding_to_three_files(
    world: &mut CovguardWorld,
    file1: String,
    file2: String,
    file3: String,
) {
    world.current_file = file1.clone();
    world.additional_files = vec![file2.clone(), file3.clone()];
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

#[given("a diff adding lines to multiple files")]
fn given_diff_adding_to_multiple_files(world: &mut CovguardWorld) {
    given_diff_adding_to_two_files(world, "src/a.rs".to_string(), "src/b.rs".to_string());
}

#[given(expr = "a diff adding {int} lines to {string} and {int} lines to {string}")]
fn given_diff_adding_to_two_files_with_counts(
    world: &mut CovguardWorld,
    num1: i32,
    file1: String,
    num2: i32,
    file2: String,
) {
    world.current_file = file1.clone();
    world.additional_files = vec![file2.clone()];
    let mut lines1 = String::new();
    for i in 1..=num1 {
        lines1.push_str(&format!("+    line_{}\n", i));
    }
    let mut lines2 = String::new();
    for i in 1..=num2 {
        lines2.push_str(&format!("+    line_{}\n", i));
    }
    world.diff_text = format!(
        r#"diff --git a/{f1} b/{f1}
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/{f1}
@@ -0,0 +1,{n1} @@
{l1}diff --git a/{f2} b/{f2}
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/{f2}
@@ -0,0 +1,{n2} @@
{l2}"#,
        f1 = file1,
        n1 = num1,
        l1 = lines1,
        f2 = file2,
        n2 = num2,
        l2 = lines2
    );
}

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

#[given(expr = "an invalid diff text {string}")]
fn given_invalid_diff(world: &mut CovguardWorld, text: String) {
    world.diff_text = text;
}

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

#[given(expr = "a file where an added line contains {string}")]
fn given_file_with_ignore_directive(world: &mut CovguardWorld, directive: String) {
    world.current_file = "src/lib.rs".to_string();
    world.ignore_line = 2;
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
    let mut ignored = BTreeSet::new();
    ignored.insert(world.ignore_line);
    world
        .ignored_lines
        .insert(world.current_file.clone(), ignored);
}

// ============================================================================
// Given Steps - LCOV Setup
// ============================================================================

#[given("an LCOV report where those lines have 0 hits")]
fn given_lcov_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n"),
    );
}

#[given("an LCOV report where all lines are covered")]
fn given_lcov_all_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,5\nDA:2,5\nDA:3,5\nend_of_record\n"),
    );
}

#[given("an LCOV report with any values")]
fn given_lcov_any_values(world: &mut CovguardWorld) {
    let file = if world.current_file.is_empty() {
        "src/lib.rs"
    } else {
        &world.current_file
    };
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,1\nDA:2,1\nend_of_record\n"),
    );
}

#[given("LCOV reports that line has 0 hits")]
fn given_lcov_ignore_line_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n"),
    );
}

#[given("an LCOV report where modified lines have 0 hits")]
fn given_lcov_modified_uncovered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,1\nDA:2,0\nDA:3,1\nend_of_record\n"),
    );
}

#[given("an LCOV report where line 2 is covered but lines 1 and 3 are not")]
fn given_lcov_partial_middle_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,0\nDA:2,5\nDA:3,0\nend_of_record\n"),
    );
}

#[given(expr = "an LCOV report with {int}% line coverage")]
fn given_lcov_with_percent_coverage(world: &mut CovguardWorld, percent: i32) {
    let file = &world.current_file;
    let covered_count = percent / 10;
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=10 {
        let hits = if i <= covered_count { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report where {int}% line coverage")]
fn given_lcov_where_percent_coverage(world: &mut CovguardWorld, percent: i32) {
    given_lcov_with_percent_coverage(world, percent);
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

#[given("an LCOV report where 3 lines are covered and 2 are not")]
fn given_lcov_3_covered_2_not(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,0\nDA:5,0\nend_of_record\n"),
    );
}

#[given(expr = "an LCOV report where line {int} has 0 hits")]
fn given_lcov_specific_line_uncovered(world: &mut CovguardWorld, line_num: i32) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:{line_num},0\nend_of_record\n"),
    );
}

#[given("an LCOV report where all added lines have 0 hits")]
fn given_lcov_all_added_uncovered(world: &mut CovguardWorld) {
    let mut lcov = String::from("TN:\n");
    lcov.push_str(&format!(
        "SF:{}\nDA:1,0\nDA:2,0\nend_of_record\n",
        world.current_file
    ));
    for file in &world.additional_files {
        lcov.push_str(&format!("SF:{}\nDA:1,0\nDA:2,0\nend_of_record\n", file));
    }
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report where {string} is covered and {string} is not")]
fn given_lcov_mixed_coverage(
    world: &mut CovguardWorld,
    covered_file: String,
    uncovered_file: String,
) {
    set_single_lcov(
        world,
        format!(
            "TN:\nSF:{covered}\nDA:1,5\nDA:2,5\nend_of_record\nSF:{uncovered}\nDA:1,0\nDA:2,0\nend_of_record\n",
            covered = covered_file,
            uncovered = uncovered_file
        ),
    );
}

#[given(expr = "an LCOV report where {string} is covered")]
fn given_lcov_file_covered(world: &mut CovguardWorld, file: String) {
    let lcov = format!("TN:\nSF:{file}\nDA:1,1\nDA:2,1\nDA:3,1\nDA:4,1\nDA:5,1\nend_of_record\n");
    world.coverage_inputs.push((
        lcov,
        format!("{}.info", file.replace('/', "_")),
        covguard_types::CoverageFormat::Lcov,
    ));
}

#[given(expr = "an LCOV report that only covers {string}")]
fn given_lcov_only_covers_one_file(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!("TN:\nSF:{file_path}\nDA:1,5\nDA:2,5\nend_of_record\n"),
    );
}

#[given("an empty LCOV report")]
fn given_empty_lcov(world: &mut CovguardWorld) {
    world.lcov_texts = vec![String::new()];
}

#[given(expr = "an invalid LCOV text {string}")]
fn given_invalid_lcov(world: &mut CovguardWorld, text: String) {
    set_single_lcov(world, text);
}

#[given("an LCOV report with explicit zero hits")]
fn given_lcov_explicit_zero(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!("TN:\nSF:{file}\nDA:1,0\nDA:2,0\nDA:3,0\nLH:0\nLF:3\nend_of_record\n"),
    );
}

#[given(expr = "an LCOV report for {string} with 0 hits")]
fn given_lcov_for_file_uncovered(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!("TN:\nSF:{file_path}\nDA:1,0\nDA:2,0\nDA:3,0\nDA:4,0\nend_of_record\n"),
    );
}

#[given(expr = "an LCOV report for normalized path {string} with 0 hits")]
fn given_lcov_for_normalized_path(world: &mut CovguardWorld, file_path: String) {
    set_single_lcov(
        world,
        format!("TN:\nSF:{file_path}\nDA:1,0\nDA:2,0\nDA:3,0\nend_of_record\n"),
    );
}

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
            "TN:\nSF:{f1}\nDA:1,5\nDA:2,5\nend_of_record\nSF:{f2}\nDA:1,5\nDA:2,5\nend_of_record\n",
            f1 = file1,
            f2 = file2
        ),
    );
}

#[given(expr = "an LCOV report where all lines have {int} hits")]
fn given_lcov_all_lines_hits(world: &mut CovguardWorld, hits: i32) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            "TN:\nSF:{file}\nDA:1,{hits}\nDA:2,{hits}\nDA:3,{hits}\nend_of_record\n",
            file = file,
            hits = hits
        ),
    );
}

#[given("an LCOV report where 1 line is covered and 2 are not")]
fn given_lcov_one_of_three_covered(world: &mut CovguardWorld) {
    let file = &world.current_file;
    set_single_lcov(
        world,
        format!(
            "TN:\nSF:{file}\nDA:1,1\nDA:2,0\nDA:3,0\nend_of_record\n",
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
// Given Steps - LCOV (additional patterns for new features)
// ============================================================================

#[given(expr = "an LCOV report with {int}% coverage")]
fn given_lcov_pct_coverage(world: &mut CovguardWorld, percent: i32) {
    let file = world.current_file.clone();
    let num_lines = 100;
    let covered_count = (num_lines * percent as i64) / 100;
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=num_lines {
        let hits = if i <= covered_count { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given("an LCOV report with 0% coverage for that file")]
fn given_lcov_zero_for_that_file(world: &mut CovguardWorld) {
    let file = world.current_file.clone();
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=10 {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given("an LCOV report with 0% coverage for that line")]
fn given_lcov_zero_for_that_line(world: &mut CovguardWorld) {
    let file = world.current_file.clone();
    set_single_lcov(world, format!("TN:\nSF:{}\nDA:1,0\nend_of_record\n", file));
}

#[given(expr = "an LCOV report with 0% coverage for line {int}")]
fn given_lcov_zero_for_specific_line(world: &mut CovguardWorld, line: i32) {
    let file = world.current_file.clone();
    set_single_lcov(
        world,
        format!("TN:\nSF:{}\nDA:{},0\nend_of_record\n", file, line),
    );
}

#[given("an LCOV report with 0% coverage for both files")]
fn given_lcov_zero_for_both_files(world: &mut CovguardWorld) {
    let file1 = world.current_file.clone();
    let file2 = world.additional_files.first().cloned().unwrap_or_default();
    let mut lcov = String::from("TN:\n");
    for file in [&file1, &file2] {
        lcov.push_str(&format!("SF:{}\n", file));
        for i in 1..=10 {
            lcov.push_str(&format!("DA:{},0\n", i));
        }
        lcov.push_str("end_of_record\n");
    }
    set_single_lcov(world, lcov);
}

#[given("an LCOV report with 0% coverage for all lines")]
fn given_lcov_zero_all_lines(world: &mut CovguardWorld) {
    let file = world.current_file.clone();
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=100 {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report where {int} of {int} lines are covered")]
fn given_lcov_n_of_m_covered(world: &mut CovguardWorld, covered: i32, total: i32) {
    let file = world.current_file.clone();
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=total {
        let hits = if i <= covered { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report with line {int}-{int} covered")]
fn given_lcov_line_range_covered(world: &mut CovguardWorld, start: i32, end: i32) {
    let file = world.current_file.clone();
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=10 {
        let hits = if i >= start && i <= end { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "another LCOV report with line {int}-{int} covered")]
fn given_another_lcov_line_range_covered(world: &mut CovguardWorld, start: i32, end: i32) {
    let file = world.current_file.clone();
    let mut lcov = format!("TN:\nSF:{}\n", file);
    for i in 1..=10 {
        let hits = if i >= start && i <= end { 1 } else { 0 };
        lcov.push_str(&format!("DA:{},{}\n", i, hits));
    }
    lcov.push_str("end_of_record\n");
    world.lcov_texts.push(lcov);
}

#[given(expr = "an LCOV report with absolute path {string}")]
fn given_lcov_absolute_path(world: &mut CovguardWorld, abs_path: String) {
    let mut lcov = format!("TN:\nSF:{}\n", abs_path);
    for i in 1..=10 {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(expr = "an LCOV report with Windows absolute path {string}")]
fn given_lcov_windows_absolute_path(world: &mut CovguardWorld, abs_path: String) {
    let mut lcov = format!("TN:\nSF:{}\n", abs_path);
    for i in 1..=10 {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

#[given(regex = r#"^an LCOV report for "([^"]+)" \(different case\)$"#)]
fn given_lcov_different_case(world: &mut CovguardWorld, file_path: String) {
    let mut lcov = format!("TN:\nSF:{}\n", file_path);
    for i in 1..=10 {
        lcov.push_str(&format!("DA:{},0\n", i));
    }
    lcov.push_str("end_of_record\n");
    set_single_lcov(world, lcov);
}

// ============================================================================
// Given Steps - JaCoCo Setup
// ============================================================================

#[given(expr = "a JaCoCo report where those lines have {int} hits")]
fn given_jacoco_report_with_hits(world: &mut CovguardWorld, hits: i32) {
    let file_str = if world.current_file.is_empty() {
        "com/example/Foo.java"
    } else {
        world.current_file.as_str()
    };
    let (package, filename) = if let Some(pos) = file_str.rfind('/') {
        (&file_str[..pos], &file_str[pos + 1..])
    } else {
        ("", file_str)
    };
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><report name="Test"><package name="{package}"><sourcefile name="{filename}"><line nr="1" ci="{hits}" mi="0"/><line nr="2" ci="{hits}" mi="0"/><line nr="3" ci="{hits}" mi="0"/></sourcefile></package></report>"#,
        package = package,
        filename = filename,
        hits = hits
    );
    world.coverage_inputs.push((
        content,
        "jacoco.xml".to_string(),
        covguard_types::CoverageFormat::Jacoco,
    ));
}

#[given("a JaCoCo report where all lines are covered")]
fn given_jacoco_covered(world: &mut CovguardWorld) {
    given_jacoco_report_with_hits(world, 1);
}

#[given("a JaCoCo report where line 1 is covered and lines 2 and 3 are not")]
fn given_jacoco_partial(world: &mut CovguardWorld) {
    let file_str = if world.current_file.is_empty() {
        "com/example/Foo.java"
    } else {
        world.current_file.as_str()
    };
    let (package, filename) = if let Some(pos) = file_str.rfind('/') {
        (&file_str[..pos], &file_str[pos + 1..])
    } else {
        ("", file_str)
    };
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><report name="Test"><package name="{package}"><sourcefile name="{filename}"><line nr="1" ci="1" mi="0"/><line nr="2" ci="0" mi="1"/><line nr="3" ci="0" mi="1"/></sourcefile></package></report>"#,
        package = package,
        filename = filename
    );
    world.coverage_inputs.push((
        content,
        "jacoco.xml".to_string(),
        covguard_types::CoverageFormat::Jacoco,
    ));
}

#[given(expr = "a JaCoCo report where {string} is covered")]
fn given_jacoco_file_covered(world: &mut CovguardWorld, file: String) {
    let (package, filename) = if let Some(pos) = file.rfind('/') {
        (&file[..pos], &file[pos + 1..])
    } else {
        ("", file.as_str())
    };
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><report name="Test"><package name="{package}"><sourcefile name="{filename}"><line nr="1" ci="1" mi="0"/><line nr="2" ci="1" mi="0"/><line nr="3" ci="1" mi="0"/><line nr="4" ci="1" mi="0"/><line nr="5" ci="1" mi="0"/></sourcefile></package></report>"#,
        package = package,
        filename = filename
    );
    world.coverage_inputs.push((
        content,
        format!("{}.xml", filename),
        covguard_types::CoverageFormat::Jacoco,
    ));
}

#[given(expr = "a JaCoCo report with line {int}-{int} covered")]
fn given_jacoco_line_range(world: &mut CovguardWorld, start: i32, end: i32) {
    let file_str = if world.current_file.is_empty() {
        "src/Java.java"
    } else {
        world.current_file.as_str()
    };
    let (package, filename) = if let Some(pos) = file_str.rfind('/') {
        (&file_str[..pos], &file_str[pos + 1..])
    } else {
        ("", file_str)
    };
    let mut lines = String::new();
    for i in 1..=10 {
        let (ci, mi) = if i >= start && i <= end {
            (1, 0)
        } else {
            (0, 1)
        };
        lines.push_str(&format!(r#"<line nr="{}" ci="{}" mi="{}"/>"#, i, ci, mi));
    }
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><report name="Test"><package name="{package}"><sourcefile name="{filename}">{lines}</sourcefile></package></report>"#,
    );
    world.coverage_inputs.push((
        content,
        "jacoco.xml".to_string(),
        covguard_types::CoverageFormat::Jacoco,
    ));
}

// ============================================================================
// Given Steps - coverage.py Setup
// ============================================================================

#[given(expr = "a coverage.py report where those lines are {word}")]
fn given_coverage_py_report(world: &mut CovguardWorld, status: String) {
    let file = if world.current_file.is_empty() {
        "src/main.py"
    } else {
        &world.current_file
    };
    let (executed, missing) = if status == "executed" {
        ("[1, 2, 3]", "[]")
    } else {
        ("[]", "[1, 2, 3]")
    };
    let content = format!(
        r#"{{"files": {{"{file}": {{"executed_lines": {executed}, "missing_lines": {missing}}}}}}}"#,
        file = file,
        executed = executed,
        missing = missing
    );
    world.coverage_inputs.push((
        content,
        "coverage.json".to_string(),
        covguard_types::CoverageFormat::CoveragePy,
    ));
}

#[given("a coverage.py report where all lines are executed")]
fn given_coverage_py_executed(world: &mut CovguardWorld) {
    given_coverage_py_report(world, "executed".to_string());
}

// ============================================================================
// Given Steps - Configuration
// ============================================================================

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

#[given(expr = "output feature flags are markdown {int}, annotations {int}, and sarif {int}")]
fn given_output_feature_flags(
    world: &mut CovguardWorld,
    markdown: i32,
    annotations: i32,
    sarif: i32,
) {
    world.output_flags = OutputFeatureFlags {
        max_markdown_lines: markdown as usize,
        max_annotations: annotations as usize,
        max_sarif_results: sarif as usize,
    };
}

#[given(expr = "output feature flags are {int}, {int}, and {int}")]
fn given_output_feature_flags_compact(
    world: &mut CovguardWorld,
    markdown: i32,
    annotations: i32,
    sarif: i32,
) {
    given_output_feature_flags(world, markdown, annotations, sarif);
}

// ============================================================================
// Given Steps - Config/Misc (for configuration_edge_cases)
// ============================================================================

#[given("no config file exists")]
fn given_no_config_file(_world: &mut CovguardWorld) {
    // No-op: covguard doesn't use config files; absence is the default.
}

#[given("an empty config file exists")]
fn given_empty_config_file(_world: &mut CovguardWorld) {
    // No-op: covguard doesn't use config files.
}

#[given("a config file with unknown keys")]
fn given_config_file_unknown_keys(_world: &mut CovguardWorld) {
    // No-op: covguard doesn't use config files.
}

#[given("no LCOV report provided")]
fn given_no_lcov_report(world: &mut CovguardWorld) {
    world.lcov_texts.clear();
    world.coverage_inputs.clear();
}

#[given(expr = "exclude pattern {string}")]
fn given_exclude_pattern_single(world: &mut CovguardWorld, pattern: String) {
    world.exclude_patterns.push(pattern);
}

#[given(expr = "include pattern {string}")]
fn given_include_pattern_single(world: &mut CovguardWorld, pattern: String) {
    world.include_patterns.push(pattern);
}

#[given(expr = "path strip prefix {string}")]
fn given_path_strip_prefix_short(world: &mut CovguardWorld, prefix: String) {
    world.path_strip = vec![prefix];
}

#[given(expr = "max findings of {int}")]
fn given_max_findings_of(world: &mut CovguardWorld, max: i32) {
    world.max_findings = Some(max as usize);
}

#[given(expr = "max annotations of {int}")]
fn given_max_annotations_of(world: &mut CovguardWorld, max: i32) {
    world.output_flags.max_annotations = max as usize;
}

#[given(expr = "max markdown lines of {int}")]
fn given_max_markdown_lines(world: &mut CovguardWorld, max: i32) {
    world.output_flags.max_markdown_lines = max as usize;
}

#[given(expr = "max SARIF results of {int}")]
fn given_max_sarif_results(world: &mut CovguardWorld, max: i32) {
    world.output_flags.max_sarif_results = max as usize;
}

// ============================================================================
// When Steps
// ============================================================================

#[when(expr = "covguard checks coverage with profile {string}")]
fn when_check_with_profile(world: &mut CovguardWorld, profile: String) {
    let profile = profile_from_name(&profile).unwrap_or(covguard_policy::Profile::Team);
    let flags = profile_defaults(profile);
    world.fail_on = flags.fail_on;
    world.threshold_pct = flags.threshold_pct;
    world.scope = match flags.scope {
        PolicyScope::Added => Scope::Added,
        PolicyScope::Touched => Scope::Touched,
    };
    world.max_uncovered_lines = flags.max_uncovered_lines;
    world.missing_coverage = flags.missing_coverage;
    world.missing_file = flags.missing_file;
    run_check(world);
}

#[when(expr = "covguard checks coverage with scope {string}")]
fn when_check_with_scope(world: &mut CovguardWorld, scope: String) {
    world.scope = match scope.as_str() {
        "added" => Scope::Added,
        "touched" => Scope::Touched,
        _ => Scope::Added,
    };
    run_check(world);
}

#[when(expr = "covguard checks coverage with format {string}")]
fn when_check_with_format(world: &mut CovguardWorld, format_str: String) {
    let format = match format_str.as_str() {
        "lcov" => covguard_types::CoverageFormat::Lcov,
        "jacoco" => covguard_types::CoverageFormat::Jacoco,
        "coverage-py" => covguard_types::CoverageFormat::CoveragePy,
        "auto" => covguard_types::CoverageFormat::Auto,
        _ => panic!("Unknown format: {}", format_str),
    };
    world.coverage_format = format;
    run_check(world);
}

#[when("covguard checks coverage with auto-detected format")]
fn when_check_with_auto_format(world: &mut CovguardWorld) {
    world.coverage_format = covguard_types::CoverageFormat::Auto;
    run_check(world);
}

#[when(expr = "covguard checks with fail_on {string}")]
fn when_check_with_fail_on(world: &mut CovguardWorld, fail_on: String) {
    world.fail_on = match fail_on.as_str() {
        "error" => FailOn::Error,
        "warn" => FailOn::Warn,
        "never" => FailOn::Never,
        _ => FailOn::Error,
    };
    run_check(world);
}

#[when("covguard checks coverage")]
fn when_check_default(world: &mut CovguardWorld) {
    run_check(world);
}

#[when("covguard checks coverage expecting an error")]
fn when_check_expecting_error(world: &mut CovguardWorld) {
    world.expect_error = true;
    run_check(world);
}

#[when("covguard checks coverage with both reports")]
fn when_check_with_both_reports(world: &mut CovguardWorld) {
    run_check(world);
}

#[when("covguard checks coverage with SARIF output")]
fn when_check_with_sarif(world: &mut CovguardWorld) {
    run_check(world);
}

fn run_check(world: &mut CovguardWorld) {
    let mut coverage_inputs = world
        .coverage_inputs
        .iter()
        .map(|(content, path, format)| covguard_app::CoverageInput {
            content: content.clone(),
            path: path.clone(),
            format: *format,
        })
        .collect::<Vec<_>>();
    for (i, text) in world.lcov_texts.iter().enumerate() {
        coverage_inputs.push(covguard_app::CoverageInput {
            content: text.clone(),
            path: format!("coverage-{}.info", i + 1),
            format: covguard_types::CoverageFormat::Lcov,
        });
    }
    let request = CheckRequest {
        diff_text: world.diff_text.clone(),
        coverage_inputs,
        threshold_pct: if world.threshold_pct == 0.0 {
            80.0
        } else {
            world.threshold_pct
        },
        scope: world.scope,
        fail_on: world.fail_on,
        ignore_directives: world.ignore_directives,
        include_patterns: world.include_patterns.clone(),
        exclude_patterns: world.exclude_patterns.clone(),
        path_strip: world.path_strip.clone(),
        max_uncovered_lines: world.max_uncovered_lines,
        missing_coverage: world.missing_coverage,
        missing_file: world.missing_file,
        max_findings: world.max_findings,
        output: world.output_flags,
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
// Then Steps - Assertions
// ============================================================================

#[then(expr = "the verdict is {string}")]
fn then_verdict_is(world: &mut CovguardWorld, expected_status: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let actual = match result.report.verdict.status {
        VerdictStatus::Pass => "pass",
        VerdictStatus::Warn => "warn",
        VerdictStatus::Fail => "fail",
        VerdictStatus::Skip => "skip",
    };
    assert_eq!(actual, expected_status);
}

#[then(regex = r"^the exit code is (\d+)$")]
fn then_exit_code_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.exit_code, expected);
}

#[then(regex = r#"^findings include code "([^"]+)"$"#)]
fn then_findings_include_code(world: &mut CovguardWorld, expected_code: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result
            .report
            .findings
            .iter()
            .any(|f| f.code == expected_code)
    );
}

#[then(expr = "findings count is {int}")]
fn then_findings_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.findings.len() as i32, expected);
}

#[then(expr = "all findings have severity {string}")]
fn then_all_findings_have_severity(world: &mut CovguardWorld, expected_severity: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let expected = match expected_severity.as_str() {
        "error" => Severity::Error,
        "warn" | "warning" => Severity::Warn,
        "info" => Severity::Info,
        _ => panic!("Unknown severity"),
    };
    for finding in &result.report.findings {
        assert_eq!(finding.severity, expected);
    }
}

#[then(expr = "findings exist for file {string}")]
fn then_findings_exist_for_file(world: &mut CovguardWorld, file_path: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path)
            .unwrap_or(false)
    }));
}

#[then(expr = "no findings exist for file {string}")]
fn then_no_findings_for_file(world: &mut CovguardWorld, file_path: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(!result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path)
            .unwrap_or(false)
    }));
}

#[then(expr = "a finding exists for file {string} at line {int}")]
fn then_finding_exists_at_location(world: &mut CovguardWorld, file_path: String, line_num: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.path == file_path && loc.line == Some(line_num as u32))
            .unwrap_or(false)
    }));
}

#[then(expr = "changed_lines_total is {int}")]
fn then_changed_lines_total_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.changed_lines_total as i32, expected);
}

#[then(expr = "covered_lines is {int}")]
fn then_covered_lines_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.covered_lines as i32, expected);
}

#[then(expr = "uncovered_lines is {int}")]
fn then_uncovered_lines_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.uncovered_lines as i32, expected);
}

#[then("missing_lines is greater than 0")]
fn then_missing_lines_greater_than_zero(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(result.report.data.missing_lines > 0);
}

#[then(expr = "coverage_pct is {float}")]
fn then_coverage_pct_is(world: &mut CovguardWorld, expected: f64) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!((result.report.data.diff_coverage_pct - expected).abs() < 0.01);
}

#[then(expr = "coverage_pct is approximately {float}")]
fn then_coverage_pct_approximately(world: &mut CovguardWorld, expected: f64) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!((result.report.data.diff_coverage_pct - expected).abs() < 1.0);
}

#[then("the check fails with an error")]
fn then_check_fails_with_error(world: &mut CovguardWorld) {
    assert!(world.check_error.is_some());
}

#[then("the check succeeds without error")]
fn then_check_succeeds(world: &mut CovguardWorld) {
    assert!(world.check_error.is_none());
}

#[then(expr = "the markdown output contains {string}")]
fn then_markdown_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result
            .markdown
            .to_lowercase()
            .contains(&expected.to_lowercase())
    );
}

#[then("the SARIF output is valid JSON")]
fn then_sarif_is_valid_json(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let _: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
}

#[then(expr = "the SARIF output contains {string}")]
fn then_sarif_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(result.sarif.contains(&expected));
}

#[then(expr = "the annotations output contains {string}")]
fn then_annotations_contains(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(result.annotations.contains(&expected));
}

#[then("the ignored line is excluded from evaluation")]
fn then_ignored_line_excluded(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let ignored_line = world.ignore_line;
    let has_finding_for_ignored = result.report.findings.iter().any(|f| {
        f.location
            .as_ref()
            .map(|loc| loc.line == Some(ignored_line))
            .unwrap_or(false)
    });
    assert!(!has_finding_for_ignored);
}

#[then(expr = "ignored_lines_count is {int}")]
fn then_ignored_lines_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.ignored_lines_count as i32, expected);
}

#[then("findings are sorted by path then line number")]
fn then_findings_are_sorted(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let findings = &result.report.findings;
    for i in 1..findings.len() {
        let prev = &findings[i - 1];
        let curr = &findings[i];
        if let (Some(prev_loc), Some(curr_loc)) = (prev.location.as_ref(), curr.location.as_ref()) {
            let path_cmp = prev_loc.path.cmp(&curr_loc.path);
            assert!(path_cmp != std::cmp::Ordering::Greater);
            if path_cmp == std::cmp::Ordering::Equal {
                assert!(prev_loc.line <= curr_loc.line);
            }
        }
    }
}

#[then(expr = "the report scope is {string}")]
fn then_report_scope_is(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.scope, expected);
}

#[then("the report has valid tool info")]
fn then_report_has_tool_info(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.tool.name, "covguard");
    assert!(!result.report.tool.version.is_empty());
}

#[then(expr = "excluded_files_count is {int}")]
fn then_excluded_files_count_is(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    assert_eq!(result.report.data.excluded_files_count as i32, expected);
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
    assert!(trunc.total > trunc.shown);
}

#[then(expr = "annotations rendered with limit {int} contain at most {int} entries")]
fn then_annotations_with_limit_count(world: &mut CovguardWorld, limit: i32, max_count: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let annotations =
        covguard_output::render_annotations_with_limit(&result.report, limit as usize);
    let actual = annotations
        .lines()
        .filter(|line| line.starts_with("::"))
        .count() as i32;
    assert!(actual <= max_count);
}

#[then("the shared output feature flags are used for rendering")]
fn then_shared_output_flags_used_for_rendering(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let flags = world.output_flags;

    let markdown =
        covguard_output::render_markdown_with_limit(&result.report, flags.max_markdown_lines);
    let annotations =
        covguard_output::render_annotations_with_limit(&result.report, flags.max_annotations);
    let sarif = covguard_output::render_sarif_with_limit(&result.report, flags.max_sarif_results);

    assert_eq!(result.output, flags);
    assert_eq!(result.markdown, markdown);
    assert_eq!(result.annotations, annotations);
    assert_eq!(result.sarif, sarif);
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
            .any(|r| r == &expected_reason)
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
    assert_eq!(actual, expected);
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
        .filter_map(|v| v.as_str())
        .any(|path| path == expected_file);
    assert!(has_file);
}

#[then("re-running the same check yields identical report JSON")]
fn then_rerun_is_deterministic(world: &mut CovguardWorld) {
    let first = world.result.as_ref().unwrap().report.clone();
    run_check(world);
    let second = world.result.as_ref().unwrap().report.clone();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap()
    );
}

// ============================================================================
// Then Steps - Output Format Assertions
// ============================================================================

#[then(expr = "findings do not exist for file {string}")]
fn then_findings_do_not_exist_for_file(world: &mut CovguardWorld, file_path: String) {
    then_no_findings_for_file(world, file_path);
}

#[then("markdown output exists")]
fn then_markdown_output_exists(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(!result.markdown.is_empty(), "markdown output should exist");
}

#[then(expr = "markdown contains {string}")]
fn then_markdown_contains_text(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result
            .markdown
            .to_lowercase()
            .contains(&expected.to_lowercase()),
        "markdown should contain '{}', got:\n{}",
        expected,
        result.markdown
    );
}

#[then(regex = r#"^markdown contains "([^"]+)" or "([^"]+)"$"#)]
fn then_markdown_contains_either(world: &mut CovguardWorld, a: String, b: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let md = result.markdown.to_lowercase();
    assert!(
        md.contains(&a.to_lowercase()) || md.contains(&b.to_lowercase()),
        "markdown should contain '{}' or '{}', got:\n{}",
        a,
        b,
        result.markdown
    );
}

#[then("markdown contains truncation indicator")]
fn then_markdown_truncation_indicator(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let md = result.markdown.to_lowercase();
    assert!(
        md.contains("showing")
            || md.contains("truncat")
            || md.contains("…")
            || md.contains("...")
            || md.contains("more"),
        "markdown should contain truncation indicator, got:\n{}",
        result.markdown
    );
}

#[then(expr = "markdown line count is approximately {int}")]
fn then_markdown_line_count_approx(world: &mut CovguardWorld, expected: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let count = result.markdown.lines().count() as i32;
    assert!(
        (count - expected).abs() <= expected,
        "Expected approximately {} markdown lines, got {}",
        expected,
        count
    );
}

#[then("SARIF output is valid JSON")]
fn then_sarif_output_valid_json(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let _: serde_json::Value =
        serde_json::from_str(&result.sarif).expect("SARIF should be valid JSON");
}

#[then(expr = "SARIF contains {string} field")]
fn then_sarif_contains_field(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let v: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
    assert!(
        !v[&field].is_null(),
        "SARIF should contain '{}' field",
        field
    );
}

#[then(expr = "SARIF contains {string} array")]
fn then_sarif_contains_array(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result.sarif.contains(&format!("\"{}\"", field)),
        "SARIF should contain '{}' array",
        field
    );
}

#[then("SARIF results array is empty")]
fn then_sarif_results_empty(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let v: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("SARIF should have results array");
    assert!(results.is_empty(), "SARIF results should be empty");
}

#[then(expr = "SARIF results count is at most {int}")]
fn then_sarif_results_at_most(world: &mut CovguardWorld, max: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let v: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("SARIF should have results array");
    assert!(
        results.len() as i32 <= max,
        "Expected at most {} SARIF results, got {}",
        max,
        results.len()
    );
}

#[then("SARIF contains rules section")]
fn then_sarif_contains_rules(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let v: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
    assert!(
        v["runs"][0]["tool"]["driver"]["rules"].is_array(),
        "SARIF should contain rules section"
    );
}

#[then(expr = "SARIF rules include {string}")]
fn then_sarif_rules_include(world: &mut CovguardWorld, rule_id: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let v: serde_json::Value = serde_json::from_str(&result.sarif).unwrap();
    let rules = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF should have rules");
    assert!(
        rules.iter().any(|r| r["id"].as_str() == Some(&rule_id)),
        "SARIF rules should include '{}'",
        rule_id
    );
}

#[then(expr = "annotation output contains {string}")]
fn then_annotation_output_contains_text(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result.annotations.contains(&expected),
        "annotations should contain '{}'",
        expected
    );
}

#[then(expr = "annotation contains {string}")]
fn then_annotation_contains_text(world: &mut CovguardWorld, expected: String) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result.annotations.contains(&expected),
        "annotations should contain '{}'",
        expected
    );
}

#[then(expr = "annotation error count is at most {int}")]
fn then_annotation_error_count_at_most(world: &mut CovguardWorld, max: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let count = result
        .annotations
        .lines()
        .filter(|l| l.starts_with("::error"))
        .count() as i32;
    assert!(
        count <= max,
        "Expected at most {} annotation errors, got {}",
        max,
        count
    );
}

#[then("report JSON is valid")]
fn then_report_json_valid(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    let _: serde_json::Value =
        serde_json::to_value(&result.report).expect("report should serialize to valid JSON");
}

#[then(expr = "report contains {string} field")]
fn then_report_contains_field(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let json = serde_json::to_value(&result.report).unwrap();
    assert!(
        !json[&field].is_null(),
        "report should contain '{}' field",
        field
    );
}

#[then(expr = "report contains {string} array")]
fn then_report_contains_array(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let json = serde_json::to_value(&result.report).unwrap();
    assert!(
        json[&field].is_array(),
        "report should contain '{}' array",
        field
    );
}

#[then(expr = "report contains {string} section")]
fn then_report_contains_section(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let json = serde_json::to_value(&result.report).unwrap();
    assert!(
        !json[&field].is_null(),
        "report should contain '{}' section",
        field
    );
}

#[then(expr = "data contains {string}")]
fn then_data_contains_field(world: &mut CovguardWorld, field: String) {
    let result = world.result.as_ref().expect("check should have been run");
    let json = serde_json::to_value(&result.report.data).unwrap();
    let json_str = serde_json::to_string(&json).unwrap();
    assert!(
        json_str.contains(&format!("\"{}\"", field)),
        "data should contain '{}', got: {}",
        field,
        json_str
    );
}

#[then("findings array is empty")]
fn then_findings_array_empty(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result.report.findings.is_empty(),
        "findings should be empty"
    );
}

#[then("the report includes truncation indicator")]
fn then_report_includes_truncation(world: &mut CovguardWorld) {
    let result = world.result.as_ref().expect("check should have been run");
    assert!(
        result.report.data.truncation.is_some(),
        "report should include truncation indicator"
    );
}

#[then(expr = "the annotation output contains at most {int} errors")]
fn then_annotation_output_max_errors(world: &mut CovguardWorld, max: i32) {
    let result = world.result.as_ref().expect("check should have been run");
    let count = result
        .annotations
        .lines()
        .filter(|l| l.starts_with("::error"))
        .count() as i32;
    assert!(
        count <= max,
        "Expected at most {} annotation errors, got {}",
        max,
        count
    );
}

fn main() {
    futures::executor::block_on(CovguardWorld::cucumber().run("../../bdd/features"));
}
