# covguard-policy

[![crates.io](https://img.shields.io/crates/v/covguard-policy.svg)](https://crates.io/crates/covguard-policy)
[![docs.rs](https://docs.rs/covguard-policy/badge.svg)](https://docs.rs/covguard-policy)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Shared policy model for coverage policy evaluation and profile-based presets.

## Overview

This crate provides the core policy types used across covguard for evaluating coverage requirements:

- **Scope**: Which lines to evaluate (`Added` or `Touched`)
- **FailOn**: When to fail the check (`Error`, `Warn`, or `Never`)
- **MissingBehavior**: How to handle missing coverage data (`Skip`, `Warn`, or `Fail`)
- **Profile**: Built-in policy presets (`Oss`, `Moderate`, `Team`, `Strict`, `Lenient`)
- **ProfileFlags**: Resolved policy settings for a profile

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-policy = "0.1"
```

### Example

```rust
use covguard_policy::{Profile, Scope, FailOn, MissingBehavior};

// Use a built-in profile
let profile = Profile::Strict;
let flags = profile.flags();

println!("Scope: {:?}", flags.scope);           // Added
println!("Fail on: {:?}", flags.fail_on);       // Error
println!("Threshold: {}%", flags.threshold_pct); // 90.0

// Customize behavior
let scope = Scope::Touched;  // Evaluate all touched lines
let fail_on = FailOn::Warn;  // Fail on warnings too
let missing = MissingBehavior::Skip;  // Skip missing coverage
```

## Profiles

| Profile | Threshold | Fail On | Missing Coverage |
|---------|-----------|---------|------------------|
| `Oss` | 70% | Never | Skip |
| `Lenient` | 50% | Never | Warn |
| `Moderate` | 70% | Error | Warn |
| `Team` | 80% | Error | Warn |
| `Strict` | 90% | Error | Fail |

## Documentation

- [API Documentation](https://docs.rs/covguard-policy)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
