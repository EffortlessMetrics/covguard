# covguard-paths

[![crates.io](https://img.shields.io/crates/v/covguard-paths.svg)](https://crates.io/crates/covguard-paths)
[![docs.rs](https://docs.rs/covguard-paths/badge.svg)](https://docs.rs/covguard-paths)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Shared path normalization utilities used by multiple covguard adapters.

## Overview

This crate provides deterministic path normalization for the covguard project. It handles cross-platform path differences and various path formats encountered in diff files and coverage reports.

The crate intentionally keeps behavior small and deterministic:
- Convert backslashes to forward slashes (Windows compatibility)
- Normalize diff-like `a/` and `b/` prefixes
- Handle leading `./` prefixes
- Strip common absolute-path patterns (e.g., `/home/user/project/src/` → `src/`)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-paths = "0.1"
```

### Example

```rust
use covguard_paths::{normalize_diff_path, normalize_coverage_path, normalize_coverage_path_with_strip};

// Normalize paths from unified diff headers
assert_eq!(normalize_diff_path("b/src/lib.rs"), "src/lib.rs");
assert_eq!(normalize_diff_path("a/src/lib.rs"), "src/lib.rs");
assert_eq!(normalize_diff_path("./src/lib.rs"), "src/lib.rs");
assert_eq!(normalize_diff_path("src\\lib.rs"), "src/lib.rs");

// Normalize coverage paths (LCOV, etc.)
assert_eq!(normalize_coverage_path("./src/lib.rs"), "src/lib.rs");
assert_eq!(normalize_coverage_path("/home/user/project/src/lib.rs"), "src/lib.rs");

// With custom strip prefixes
let prefixes = vec!["/home/user/project/".to_string()];
assert_eq!(
    normalize_coverage_path_with_strip("/home/user/project/src/lib.rs", &prefixes),
    "src/lib.rs"
);
```

## Documentation

- [API Documentation](https://docs.rs/covguard-paths)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
