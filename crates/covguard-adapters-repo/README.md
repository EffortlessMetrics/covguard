# covguard-adapters-repo

[![crates.io](https://img.shields.io/crates/v/covguard-adapters-repo.svg)](https://crates.io/crates/covguard-adapters-repo)
[![docs.rs](https://docs.rs/covguard-adapters-repo/badge.svg)](https://docs.rs/covguard-adapters-repo)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Filesystem-backed RepoReader adapter for covguard ignore-directive lookup.

## Overview

This crate provides a filesystem-based repository reader that implements the `RepoReader` port from `covguard-ports`. It is primarily used for reading source file lines to detect ignore directives (e.g., `// covguard:ignore` comments).

Key features:
- Read specific lines from source files by line number
- File content caching for efficient repeated access
- Support for both relative and absolute paths

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-adapters-repo = "0.1"
```

### Example

```rust
use covguard_adapters_repo::FsRepoReader;
use covguard_ports::RepoReader;
use std::path::Path;

// Create a reader rooted at the repository
let reader = FsRepoReader::new(Path::new("."));

// Read a specific line from a file
if let Some(line) = reader.read_line("src/lib.rs", 42) {
    println!("Line 42: {}", line);
    
    // Check for ignore directives
    if line.contains("covguard:ignore") {
        // Handle ignored line
    }
}

// Works with absolute paths too
let abs_path = std::fs::canonicalize("src/main.rs").unwrap();
let line = reader.read_line(&abs_path.to_string_lossy(), 1);
```

## Documentation

- [API Documentation](https://docs.rs/covguard-adapters-repo)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
