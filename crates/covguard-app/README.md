# covguard-app

[![crates.io](https://img.shields.io/crates/v/covguard-app.svg)](https://crates.io/crates/covguard-app)
[![docs.rs](https://docs.rs/covguard-app/badge.svg)](https://docs.rs/covguard-app)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](../../LICENSE)

Backward-compatible façade for `covguard-orchestrator`.

## Overview

`covguard-app` is retained as a stable integration surface while the orchestration layer is maintained in `covguard-orchestrator`. It re-exports all public APIs from `covguard-orchestrator` to preserve backward compatibility for existing consumers.

This crate exists to allow the orchestration implementation to evolve as a separate microcrate without breaking the published public API.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
covguard-app = "0.1"
```

```rust
use covguard_app::{check, CheckRequest, SystemClock};
use covguard_types::Scope;

let request = CheckRequest {
    diff_text: "...".to_string(),
    lcov_texts: vec!["...".to_string()],
    threshold_pct: 80.0,
    scope: Scope::Added,
    ..Default::default()
};

let result = check(request)?;
```

## Main API

- `check` — Run the full diff coverage check
- `check_with_clock` — Run with a custom clock (for testing)
- `check_with_clock_and_reader` — Run with custom clock and repo reader
- `check_with_providers_and_reader` — Run with custom providers

## Documentation

- [API Documentation](https://docs.rs/covguard-app)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
