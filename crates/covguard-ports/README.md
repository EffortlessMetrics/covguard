# covguard-ports

[![crates.io](https://img.shields.io/crates/v/covguard-ports.svg)](https://crates.io/crates/covguard-ports)
[![docs.rs](https://docs.rs/covguard-ports/badge.svg)](https://docs.rs/covguard-ports)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Shared port traits and boundary DTOs for covguard's hexagonal architecture.

## Overview

This crate defines the port interfaces (traits) and data transfer objects used at the boundaries of covguard's hexagonal/clean architecture:

- **`DiffProvider`**: Parse unified diff text and load diffs from git
- **`CoverageProvider`**: Parse LCOV coverage data and merge coverage maps
- **`RepoReader`**: Read source lines from the repository
- **`Clock`**: Obtain current UTC time

### Data Types

- **`ChangedRanges`**: Changed lines grouped by normalized repo-relative path
- **`CoverageMap`**: Line hit counts grouped by file path
- **`DiffParseResult`**: Parsed diff payload with changed ranges and binary files

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-ports = "0.1"
```

### Example

```rust
use covguard_ports::{
    DiffProvider, CoverageProvider, RepoReader, Clock,
    ChangedRanges, CoverageMap, DiffParseResult,
};
use std::path::Path;

// Implement the DiffProvider trait for your adapter
struct MyDiffProvider;

impl DiffProvider for MyDiffProvider {
    fn parse_patch(&self, text: &str) -> Result<DiffParseResult, String> {
        // Parse unified diff text...
        Ok(DiffParseResult::default())
    }

    fn load_diff_from_git(
        &self,
        base: &str,
        head: &str,
        repo_root: &Path,
    ) -> Result<String, String> {
        // Load diff from git repository...
        Ok(String::new())
    }
}

// Implement RepoReader for reading source lines
struct MyRepoReader;

impl RepoReader for MyRepoReader {
    fn read_line(&self, path: &str, line_no: u32) -> Option<String> {
        // Read line at 1-based line_no...
        None
    }
}
```

## Documentation

- [API Documentation](https://docs.rs/covguard-ports)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
