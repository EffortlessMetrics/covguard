//! Shared path normalization utilities used by multiple adapters.
//!
//! The crate intentionally keeps behavior small and deterministic:
//! - convert backslashes to forward slashes
//! - normalize diff-like `a/` and `b/` prefixes
//! - handle leading `./` and common absolute-path stripping cases

const COMMON_SOURCE_MARKERS: [&str; 4] = ["/src/", "/lib/", "/test/", "/tests/"];

/// Normalize a repository-relative path as seen in unified diff headers.
///
/// Behavior:
/// - trim outer whitespace
/// - convert backslashes to forward slashes
/// - strip `a/` or `b/` prefix
/// - strip leading `./` (once)
pub fn normalize_diff_path(path: &str) -> String {
    let path = path.trim();
    let path = path.replace('\\', "/");

    let path = path
        .strip_prefix("b/")
        .or_else(|| path.strip_prefix("a/"))
        .unwrap_or(&path);

    path.strip_prefix("./").unwrap_or(path).to_string()
}

/// Normalize an LCOV/coverage path with optional configured strip prefixes.
pub fn normalize_coverage_path_with_strip(path: &str, strip_prefixes: &[String]) -> String {
    let mut normalized = path.replace('\\', "/");

    for prefix in strip_prefixes {
        let prefix_norm = prefix.replace('\\', "/");
        if normalized.starts_with(&prefix_norm) {
            normalized = normalized[prefix_norm.len()..].to_string();
            break;
        }
    }

    while normalized.starts_with("./") {
        normalized = normalized[2..].to_string();
    }

    if normalized.starts_with('/') {
        for marker in &COMMON_SOURCE_MARKERS {
            if let Some(pos) = normalized.find(marker) {
                normalized = normalized[pos + 1..].to_string();
                break;
            }
        }
    }

    if normalized.len() > 2 && normalized.chars().nth(1) == Some(':') {
        for marker in &COMMON_SOURCE_MARKERS {
            if let Some(pos) = normalized.find(marker) {
                normalized = normalized[pos + 1..].to_string();
                break;
            }
        }
    }

    normalized
}

/// Normalize a simple coverage path without configured prefixes.
pub fn normalize_coverage_path(path: &str) -> String {
    normalize_coverage_path_with_strip(path, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_diff_path() {
        assert_eq!(normalize_diff_path("b/src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_diff_path("a/src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_diff_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_diff_path("src\\lib.rs"), "src/lib.rs");
        assert_eq!(normalize_diff_path("b/./src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_diff_path("./b/src/lib.rs"), "b/src/lib.rs");
    }

    #[test]
    fn test_normalize_coverage_paths() {
        assert_eq!(normalize_coverage_path("src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_coverage_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_coverage_path("././src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_coverage_path("src\\lib.rs"), "src/lib.rs");
        assert_eq!(
            normalize_coverage_path("src\\sub\\lib.rs"),
            "src/sub/lib.rs"
        );
        assert_eq!(
            normalize_coverage_path("/home/user/project/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(
            normalize_coverage_path("C:\\Users\\user\\project\\src\\lib.rs"),
            "src/lib.rs"
        );
    }
}
