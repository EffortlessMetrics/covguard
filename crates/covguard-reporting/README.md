# covguard-reporting

[![crates.io](https://img.shields.io/crates/v/covguard-reporting.svg)](https://crates.io/crates/covguard-reporting)
[![docs.rs](https://docs.rs/covguard-reporting/badge.svg)](https://docs.rs/covguard-reporting)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Report assembly and schema composition for covguard.

## Overview

This crate handles the construction of schema-compliant reports from domain evaluation output. It bridges the gap between the domain layer's `EvalOutput` and the final `Report` structures that conform to the covguard report schema.

Key responsibilities:
- Build report pairs (domain report + optional sensor receipt)
- Assemble finding counts and verdict metadata
- Handle truncation of findings with proper metadata
- Construct input metadata (diff source, LCOV paths, git refs)
- Support both standard and sensor schema modes

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-reporting = "0.1"
```

### Example

```rust
use covguard_reporting::{build_report_pair, ReportContext};
use covguard_domain::EvalOutput;
use covguard_types::Scope;
use chrono::Utc;

// Create the report context with configuration
let context = ReportContext {
    threshold_pct: 80.0,
    scope: Scope::Added,
    sensor_schema: false,
    max_findings: Some(100),
    diff_file_path: Some("diff.patch".to_string()),
    base_ref: None,
    head_ref: None,
    lcov_paths: vec!["coverage.info".to_string()],
};

// Build reports from evaluation output
let eval = EvalOutput::default();
let started_at = Utc::now();
let ended_at = Utc::now();

let (report, optional_receipt) = build_report_pair(
    eval,
    &context,
    started_at,
    ended_at,
    0, // excluded files count
    None, // debug info
);
```

## Report Types

The crate produces two report types:
- **Domain Report** - The standard `covguard.report.v1` schema with findings and verdict
- **Sensor Receipt** - Optional `sensor.report.v1` with capability metadata for cockpit integration

## Documentation

- [API Documentation](https://docs.rs/covguard-reporting)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
