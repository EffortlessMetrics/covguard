# covguard-output-features

[![crates.io](https://img.shields.io/crates/v/covguard-output-features.svg)](https://crates.io/crates/covguard-output-features)
[![docs.rs](https://docs.rs/covguard-output-features/badge.svg)](https://docs.rs/covguard-output-features)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Shared output feature-flag contracts for covguard rendering.

## Overview

This crate is intentionally tiny so it can be used as a stable interoperability boundary by callers that only need output budget configuration. It provides the types and constants for configuring output limits across the covguard rendering pipeline.

The crate defines:
- `OutputFeatureConfig` - Partial configuration from external sources (config files, CLI overrides)
- `OutputFeatureFlags` - Domain-level feature flags for rendering output
- Default constants for markdown lines, annotations, and SARIF results limits
- `truncate_findings` utility for capping findings with truncation metadata

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-output-features = "0.1"
```

### Example

```rust
use covguard_output_features::{
    OutputFeatureConfig, OutputFeatureFlags,
    DEFAULT_MARKDOWN_LINES, DEFAULT_ANNOTATION_LIMIT, DEFAULT_SARIF_RESULTS,
    truncate_findings,
};

// Use default flags
let flags = OutputFeatureFlags::default();
assert_eq!(flags.max_markdown_lines, DEFAULT_MARKDOWN_LINES);
assert_eq!(flags.max_annotations, DEFAULT_ANNOTATION_LIMIT);
assert_eq!(flags.max_sarif_results, DEFAULT_SARIF_RESULTS);

// Override specific values from config
let config = OutputFeatureConfig {
    max_markdown_lines: Some(20),
    max_annotations: None,  // Uses default
    max_sarif_results: Some(100),
};
let materialized = config.materialize(flags);

// Truncate findings with a cap
let findings = vec![1, 2, 3, 4, 5];
let (truncated, truncation_meta) = truncate_findings(findings, Some(3));
assert_eq!(truncated.len(), 3);
assert!(truncation_meta.is_some());
```

## Documentation

- [API Documentation](https://docs.rs/covguard-output-features)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
