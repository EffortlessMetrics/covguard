# covguard-adapters-coverage

[![crates.io](https://img.shields.io/crates/v/covguard-adapters-coverage.svg)](https://crates.io/crates/covguard-adapters-coverage)
[![docs.rs](https://docs.rs/covguard-adapters-coverage/badge.svg)](https://docs.rs/covguard-adapters-coverage)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

LCOV parsing and coverage-map merge adapter for covguard.

## Overview

This crate provides parsing and merging of LCOV format coverage files, producing a normalized coverage map that can be used by the domain layer. It implements the `CoverageProvider` port from `covguard-ports` for LCOV-specific coverage data extraction.

Key features:
- Parse LCOV format strings into normalized coverage maps
- Merge multiple coverage maps from different sources
- Path normalization with configurable prefix stripping

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-adapters-coverage = "0.1"
```

### Example

```rust
use covguard_adapters_coverage::{parse_lcov, merge_coverage, LcovCoverageProvider, CoverageMap};

// Parse an LCOV file
let lcov_content = r#"TN:
SF:src/lib.rs
DA:1,5
DA:2,3
end_of_record
"#;

let coverage: CoverageMap = parse_lcov(lcov_content)?;
assert!(coverage.contains_key("src/lib.rs"));

// Merge multiple coverage maps
let merged = merge_coverage(vec![coverage1, coverage2]);

// Use the provider directly
let provider = LcovCoverageProvider;
let result = provider.parse_lcov(lcov_content, &[])?;
```

## Documentation

- [API Documentation](https://docs.rs/covguard-adapters-coverage)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
