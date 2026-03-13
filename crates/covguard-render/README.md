# covguard-render

[![crates.io](https://img.shields.io/crates/v/covguard-render.svg)](https://crates.io/crates/covguard-render)
[![docs.rs](https://docs.rs/covguard-render/badge.svg)](https://docs.rs/covguard-render)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Rendering utilities for covguard reports.

## Overview

This crate provides renderers that convert a `Report` into various output formats:
- **Markdown** - Formatted comments for pull requests with summary tables
- **GitHub Annotations** - Workflow commands for GitHub Actions
- **SARIF** - Static Analysis Results Interchange Format for security tools

Each renderer supports configurable output budgets to prevent overwhelming output in CI environments.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-render = "0.1"
```

### Example

```rust
use covguard_render::{render_markdown, render_annotations, render_sarif, status_emoji};
use covguard_types::Report;

let report = Report::default();

// Render markdown for PR comments (max 10 uncovered lines)
let markdown = render_markdown(&report, 10);

// Render GitHub workflow annotations (max 25 annotations)
let annotations = render_annotations(&report, 25);

// Render SARIF for security tools (max 1000 results)
let sarif = render_sarif(&report, 1000);

// Get status emoji for verdicts
use covguard_types::VerdictStatus;
assert_eq!(status_emoji(&VerdictStatus::Pass), "✅");
assert_eq!(status_emoji(&VerdictStatus::Fail), "❌");
```

## Output Formats

### Markdown
Generates a formatted PR comment with:
- Status indicator with emoji
- Coverage summary (diff coverage %, changed lines, covered/uncovered counts)
- Table of uncovered lines
- Reproduction instructions

### GitHub Annotations
Generates workflow commands for GitHub Actions that display findings directly in the PR files view.

### SARIF
Generates a SARIF JSON report compatible with GitHub code scanning and other security analysis tools.

## Documentation

- [API Documentation](https://docs.rs/covguard-render)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
