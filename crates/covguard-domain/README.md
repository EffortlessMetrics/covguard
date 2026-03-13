# covguard-domain

[![crates.io](https://img.shields.io/crates/v/covguard-domain.svg)](https://crates.io/crates/covguard-domain)
[![docs.rs](https://docs.rs/covguard-domain/badge.svg)](https://docs.rs/covguard-domain)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Pure policy evaluation engine for diff-scoped coverage decisions.

## Overview

This crate implements the core policy evaluation logic with no side effects. It takes changed line ranges and coverage data, applies a policy configuration, and produces findings with a verdict and metrics.

**Design constraints:**
- No filesystem, process, or network side effects
- Deterministic finding ordering (severity > path > line > check_id > code > message)
- Pure functions that are easy to test and reason about

**Key components:**
- [`evaluate()`](src/lib.rs:116) - Main entry point for policy evaluation
- [`Policy`](src/lib.rs:23) - Configuration for coverage evaluation (scope, threshold, fail-on behavior)
- [`EvalInput`](src/lib.rs:59) / [`EvalOutput`](src/lib.rs:92) - Input/output structures
- [`Metrics`](src/lib.rs:76) - Aggregated coverage statistics

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-domain = "0.1"
```

### Example

```rust
use std::collections::BTreeMap;
use covguard_domain::{evaluate, EvalInput, Policy};
use covguard_policy::{Scope, FailOn, MissingBehavior};

// Define changed lines (file -> ranges)
let mut changed_ranges = BTreeMap::new();
changed_ranges.insert("src/lib.rs".to_string(), vec![10..=15, 20..=25]);

// Define coverage data (file -> line -> hit count)
let mut coverage = BTreeMap::new();
let mut file_coverage = BTreeMap::new();
file_coverage.insert(10u32, 1u32);  // line 10: covered
file_coverage.insert(11u32, 0u32);  // line 11: uncovered
file_coverage.insert(20u32, 3u32);  // line 20: covered
coverage.insert("src/lib.rs".to_string(), file_coverage);

// Evaluate with default policy
let input = EvalInput {
    changed_ranges,
    coverage,
    policy: Policy::default(),
    ignored_lines: BTreeMap::new(),
};

let output = evaluate(input);

println!("Verdict: {:?}", output.verdict);
println!("Coverage: {:.1}%", output.metrics.diff_coverage_pct);
println!("Findings: {}", output.findings.len());
```

## Documentation

- [API Documentation](https://docs.rs/covguard-domain)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
