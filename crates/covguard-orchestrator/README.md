# covguard-orchestrator

[![crates.io](https://img.shields.io/crates/v/covguard-orchestrator.svg)](https://crates.io/crates/covguard-orchestrator)
[![docs.rs](https://docs.rs/covguard-orchestrator/badge.svg)](https://docs.rs/covguard-orchestrator)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](../../LICENSE)

Application orchestration for covguard — coordinates the diff coverage analysis pipeline.

## Overview

`covguard-orchestrator` provides the high-level `check` function that orchestrates the entire diff coverage analysis pipeline:

1. Parse the diff to extract changed line ranges
2. Parse LCOV coverage data
3. Detect ignore directives in source files
4. Evaluate coverage against the policy
5. Build and return a report with markdown and annotations

This crate is the core orchestration layer that wires together diff providers, coverage providers, domain evaluation, and output rendering.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
covguard-orchestrator = "0.1"
```

```rust
use covguard_orchestrator::{check, CheckRequest};
use covguard_types::Scope;

let request = CheckRequest {
    diff_text: "...".to_string(),
    diff_file_path: Some("test.patch".to_string()),
    lcov_texts: vec!["...".to_string()],
    lcov_paths: vec!["coverage.info".to_string()],
    threshold_pct: 80.0,
    scope: Scope::Added,
    ..Default::default()
};

let result = check(request)?;
println!("Exit code: {}", result.exit_code);
```

## Documentation

- [API Documentation](https://docs.rs/covguard-orchestrator)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
