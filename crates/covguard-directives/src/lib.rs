//! Directive utilities for covguard.
//!
//! The module provides reusable, pure logic for ignore directive parsing and
//! changed-range scanning that is shared across app and domain adapters.

use std::collections::{BTreeMap, BTreeSet};

use covguard_ports::{ChangedRanges, RepoReader};

/// Check if a line contains a `covguard: ignore` directive.
///
/// The directive can appear in comment contexts and supports:
///
/// - `// covguard: ignore` (Rust, C, JS, etc.)
/// - `# covguard: ignore` (Python, Shell, YAML, etc.)
/// - `-- covguard: ignore` (SQL, Haskell, Lua)
/// - `/* covguard: ignore */` (block comments)
/// - `covguard-ignore`
///
/// Matching is case-insensitive and tolerant of whitespace.
pub fn has_ignore_directive(line: &str) -> bool {
    let line_lower = line.to_lowercase();

    if let Some(pos) = line_lower.find("covguard:") {
        let after = &line_lower[pos + 9..]; // len("covguard:") = 9
        let trimmed = after.trim_start();
        return trimmed.starts_with("ignore");
    }

    if let Some(pos) = line_lower.find("covguard-ignore") {
        let before = &line_lower[..pos];
        return before.contains("//")
            || before.contains('#')
            || before.contains("--")
            || before.contains("/*");
    }

    false
}

/// Detect lines with `covguard: ignore` directives in changed ranges.
///
/// For each file in `changed_ranges`, reads the relevant lines from `reader` and
/// records the line numbers that contain ignore directives.
pub fn detect_ignored_lines<R: RepoReader>(
    changed_ranges: &ChangedRanges,
    reader: &R,
) -> BTreeMap<String, BTreeSet<u32>> {
    let mut ignored = BTreeMap::new();

    for (path, ranges) in changed_ranges {
        let mut file_ignored = BTreeSet::new();

        for range in ranges {
            for line_no in range.clone() {
                if let Some(line_content) = reader.read_line(path, line_no)
                    && has_ignore_directive(&line_content)
                {
                    file_ignored.insert(line_no);
                }
            }
        }

        if !file_ignored.is_empty() {
            ignored.insert(path.clone(), file_ignored);
        }
    }

    ignored
}

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_ports::RepoReader;
    use std::collections::BTreeMap;

    struct MapReader {
        lines: BTreeMap<(String, u32), String>,
    }

    impl MapReader {
        fn new(entries: Vec<(&str, u32, &str)>) -> Self {
            let mut lines = BTreeMap::new();
            for (path, line_no, content) in entries {
                lines.insert((path.to_string(), line_no), content.to_string());
            }
            Self { lines }
        }
    }

    impl RepoReader for MapReader {
        fn read_line(&self, path: &str, line_no: u32) -> Option<String> {
            self.lines.get(&(path.to_string(), line_no)).cloned()
        }
    }

    #[test]
    fn test_has_ignore_directive_rust_comment() {
        assert!(has_ignore_directive("let x = 1; // covguard: ignore"));
        assert!(has_ignore_directive("// covguard: ignore"));
        assert!(has_ignore_directive("    // covguard: ignore"));
        assert!(has_ignore_directive("// COVGUARD: IGNORE"));
        assert!(has_ignore_directive("// covguard:ignore"));
    }

    #[test]
    fn test_has_ignore_directive_python_comment() {
        assert!(has_ignore_directive("x = 1  # covguard: ignore"));
        assert!(has_ignore_directive("# covguard: ignore"));
        assert!(has_ignore_directive("#covguard:ignore"));
    }

    #[test]
    fn test_has_ignore_directive_block_comment() {
        assert!(has_ignore_directive("/* covguard: ignore */"));
        assert!(has_ignore_directive("int x = 1; /* covguard: ignore */"));
    }

    #[test]
    fn test_has_ignore_directive_sql_comment() {
        assert!(has_ignore_directive("-- covguard: ignore"));
        assert!(has_ignore_directive("SELECT 1; -- covguard: ignore"));
    }

    #[test]
    fn test_has_ignore_directive_hyphen_syntax() {
        assert!(has_ignore_directive("// covguard-ignore"));
        assert!(has_ignore_directive("# covguard-ignore"));
        assert!(has_ignore_directive("-- covguard-ignore"));
        assert!(has_ignore_directive("/* covguard-ignore */"));
    }

    #[test]
    fn test_has_ignore_directive_negative_cases() {
        assert!(!has_ignore_directive("let x = 1;"));
        assert!(!has_ignore_directive("// some other comment"));
        assert!(!has_ignore_directive("// covguard")); // missing ignore
        assert!(!has_ignore_directive("// ignore covguard")); // wrong order
    }

    #[test]
    fn test_detect_ignored_lines_with_reader() {
        let mut changed_ranges = BTreeMap::new();
        changed_ranges.insert("src/lib.rs".to_string(), vec![1..=3]);
        changed_ranges.insert("src/main.rs".to_string(), vec![10..=11]);

        let reader = MapReader::new(vec![
            ("src/lib.rs", 2, "let x = 1; // covguard: ignore"),
            ("src/main.rs", 11, "# covguard: ignore"),
        ]);

        let ignored = detect_ignored_lines(&changed_ranges, &reader);
        assert_eq!(
            ignored.get("src/lib.rs").cloned(),
            Some(BTreeSet::from([2]))
        );
        assert_eq!(
            ignored.get("src/main.rs").cloned(),
            Some(BTreeSet::from([11]))
        );
    }
}
