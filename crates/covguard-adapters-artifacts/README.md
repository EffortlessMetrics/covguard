# covguard-adapters-artifacts

[![crates.io](https://img.shields.io/crates/v/covguard-adapters-artifacts.svg)](https://crates.io/crates/covguard-adapters-artifacts)
[![docs.rs](https://docs.rs/covguard-adapters-artifacts/badge.svg)](https://docs.rs/covguard-adapters-artifacts)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Filesystem artifact adapters for covguard reports and fallback outputs.

## Overview

This crate centralizes filesystem output behavior for reports and related artifacts so CLI and other adapters can share the same contract. It provides utilities for writing JSON reports, fallback receipts, and raw debugging artifacts to disk.

In the hexagonal architecture, this crate implements the `ArtifactWriter` port for filesystem-based persistence.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-adapters-artifacts = "0.1"
```

### Example

```rust
use covguard_adapters_artifacts::{write_report, write_raw_artifacts, FsArtifactWriter};
use covguard_types::Report;

// Write a report to disk
let report = Report::default();
write_report("artifacts/covguard/report.json", &report)?;

// Write raw artifacts for debugging
write_raw_artifacts(&diff_content, &lcov_texts)?;

// Use the artifact writer directly
let writer = FsArtifactWriter::new();
```

## Documentation

- [API Documentation](https://docs.rs/covguard-adapters-artifacts)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
