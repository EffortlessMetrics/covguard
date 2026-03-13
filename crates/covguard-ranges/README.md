# covguard-ranges

[![crates.io](https://img.shields.io/crates/v/covguard-ranges.svg)](https://crates.io/crates/covguard-ranges)
[![docs.rs](https://docs.rs/covguard-ranges/badge.svg)](https://docs.rs/covguard-ranges)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Range merging utilities for covguard.

## Overview

This crate provides efficient range merging functionality for handling line number ranges in diff hunks and coverage data. It merges overlapping or adjacent ranges into a minimal set, which is essential for accurate coverage analysis.

Key features:
- Merge overlapping ranges into contiguous blocks
- Merge adjacent ranges (e.g., `1..=3` and `4..=6` → `1..=6`)
- Input ranges need not be sorted; output is always sorted
- Zero-allocation for already-merged input

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-ranges = "0.1"
```

### Example

```rust
use covguard_ranges::merge_ranges;

// Adjacent and overlapping ranges merge together
let ranges = vec![1..=3, 5..=7, 2..=4, 8..=10];
let merged = merge_ranges(ranges);
assert_eq!(merged, vec![1..=10]);

// Non-adjacent ranges stay separate
let ranges = vec![1..=3, 10..=15];
let merged = merge_ranges(ranges);
assert_eq!(merged, vec![1..=3, 10..=15]);

// Empty input returns empty output
let merged = merge_ranges(vec![]);
assert!(merged.is_empty());

// Single range passes through unchanged
let merged = merge_ranges(vec![1..=5]);
assert_eq!(merged, vec![1..=5]);
```

## Use Cases

This crate is used in covguard for:
- Merging diff hunks that touch adjacent lines
- Combining coverage ranges for efficient lookup
- Normalizing line ranges before policy evaluation

## Documentation

- [API Documentation](https://docs.rs/covguard-ranges)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
