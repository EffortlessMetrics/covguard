//! Filesystem repository reader adapter.

use covguard_ports::RepoReader;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Filesystem-backed repo reader with line caching.
pub struct FsRepoReader {
    root: PathBuf,
    cache: Mutex<HashMap<String, Vec<String>>>,
}

impl FsRepoReader {
    /// Create a new filesystem reader rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn read_file_lines(&self, path: &str) -> Option<Vec<String>> {
        let full_path = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.root.join(path)
        };
        let content = std::fs::read_to_string(full_path).ok()?;
        Some(content.lines().map(|line| line.to_string()).collect())
    }
}

impl RepoReader for FsRepoReader {
    fn read_line(&self, path: &str, line_no: u32) -> Option<String> {
        if line_no == 0 {
            return None;
        }

        let mut cache = self.cache.lock().ok()?;
        if !cache.contains_key(path) {
            let lines = self.read_file_lines(path)?;
            cache.insert(path.to_string(), lines);
        }

        cache
            .get(path)
            .and_then(|lines| lines.get((line_no - 1) as usize))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use covguard_ports::RepoReader;

    #[test]
    fn reads_relative_and_absolute_paths() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("covguard-repo-reader-{unique}"));
        let src = root.join("src");

        std::fs::create_dir_all(&src).expect("create dir");
        let file_path = src.join("lib.rs");
        std::fs::write(&file_path, "line1\nline2\nline3\n").expect("write file");

        let reader = FsRepoReader::new(&root);
        assert_eq!(reader.read_line("src/lib.rs", 2), Some("line2".to_string()));
        assert_eq!(reader.read_line("src/lib.rs", 0), None);
        assert_eq!(reader.read_line("src/lib.rs", 99), None);

        let abs_path = file_path.to_string_lossy().to_string();
        assert_eq!(reader.read_line(&abs_path, 1), Some("line1".to_string()));

        let _ = std::fs::remove_dir_all(&root);
    }
}
