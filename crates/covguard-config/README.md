# covguard-config

[![crates.io](https://img.shields.io/crates/v/covguard-config.svg)](https://crates.io/crates/covguard-config)
[![docs.rs](https://docs.rs/covguard-config/badge.svg)](https://docs.rs/covguard-config)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Configuration parsing and management for covguard.

## Overview

This crate provides configuration types and TOML parsing for covguard, including:

- **Configuration types**: `Config`, `Profile`, `PathConfig`, `IgnoreConfig`, `NormalizeConfig`
- **TOML parsing**: Load configuration from `covguard.toml` files
- **Profile system**: Built-in profiles (oss, team, strict, moderate, lenient)
- **Precedence handling**: CLI arguments > config file > defaults

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-config = "0.1"
```

### Example

```rust
use covguard_config::{Config, load_config, Profile, Scope, FailOn};

// Load configuration from a file
let config = load_config("covguard.toml")?;

// Or build configuration programmatically
let config = Config {
    profile: Some(Profile::Strict),
    scope: Some(Scope::Added),
    fail_on: Some(FailOn::Error),
    min_diff_coverage_pct: Some(80.0),
    ..Default::default()
};

// Merge with CLI overrides (CLI takes precedence)
let merged = config.apply_cli_overrides(cli_args);
```

## Documentation

- [API Documentation](https://docs.rs/covguard-config)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
