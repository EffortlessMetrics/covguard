# covguard-output

[![crates.io](https://img.shields.io/crates/v/covguard-output.svg)](https://crates.io/crates/covguard-output)
[![docs.rs](https://docs.rs/covguard-output/badge.svg)](https://docs.rs/covguard-output)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Output rendering utilities and feature flags for covguard reports.

## Overview

This crate centralizes report rendering defaults and renderer budget flags for the covguard project. It provides a unified facade over the rendering functionality while delegating feature contracts to `covguard-output-features`.

The crate offers:
- Markdown rendering for PR comments
- GitHub workflow annotation commands
- SARIF (Static Analysis Results Interchange Format) output
- Configurable output budgets (line limits, annotation limits, etc.)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-output = "0.1"
```

### Example

```rust
use covguard_output::{render_markdown, render_annotations, render_sarif, OutputFeatureFlags};
use covguard_types::Report;

let report = Report::default();

// Render with default limits
let markdown = render_markdown(&report);
let annotations = render_annotations(&report);
let sarif = render_sarif(&report);

// Or use custom limits
let markdown = render_markdown_with_limit(&report, 20);
let annotations = render_annotations_with_limit(&report, 50);
let sarif = render_sarif_with_limit(&report, 500);

// Or render all formats at once with explicit flags
let flags = OutputFeatureFlags::default();
let (md, annotations, sarif) = covguard_output::render_all(&report, &flags);
```

## Documentation

- [API Documentation](https://docs.rs/covguard-output)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
