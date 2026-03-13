# covguard-adapters-diff

[![crates.io](https://img.shields.io/crates/v/covguard-adapters-diff.svg)](https://crates.io/crates/covguard-adapters-diff)
[![docs.rs](https://docs.rs/covguard-adapters-diff/badge.svg)](https://docs.rs/covguard-adapters-diff)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Unified diff parsing and git-diff loading adapter for covguard.

## Overview

This crate provides a unified diff parser that extracts changed line ranges from patch files or git diff output. It implements the `DiffProvider` port from `covguard-ports` for git-based diff extraction and parsing.

Key features:
- Parse unified diff format strings into changed line ranges
- Load diffs directly from git using base/head refs
- Detect binary file changes
- Path normalization for diff headers

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-adapters-diff = "0.1"
```

### Example

```rust
use covguard_adapters_diff::{parse_patch, load_diff_from_git, GitDiffProvider, ChangedRanges};
use std::path::Path;

// Parse a unified diff patch
let patch = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
+fn new_function() {}
 fn existing() {}
 fn another() {}
"#;

let ranges: ChangedRanges = parse_patch(patch)?;
assert!(ranges.contains_key("src/lib.rs"));

// Load diff from git
let diff = load_diff_from_git("main", "feature-branch", Path::new("."))?;

// Use the provider directly
let provider = GitDiffProvider;
let result = provider.parse_patch(patch)?;
```

## Documentation

- [API Documentation](https://docs.rs/covguard-adapters-diff)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
