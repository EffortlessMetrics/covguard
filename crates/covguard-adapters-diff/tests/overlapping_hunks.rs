use covguard_adapters_diff::parse_patch;

#[test]
fn parse_patch_overlapping_hunks_merges_lines() {
    let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
index 1111111..2222222 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -0,0 +1,2 @@
+line1
+line2
@@ -0,0 +2,2 @@
+line2_again
+line3
"#;

    let ranges = parse_patch(diff).unwrap();
    let file_ranges = ranges.get("src/lib.rs").expect("ranges for src/lib.rs");
    assert_eq!(file_ranges, &vec![1..=3]);
}
