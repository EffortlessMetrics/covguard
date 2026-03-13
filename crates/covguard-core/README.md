# covguard-core

[![crates.io](https://img.shields.io/crates/v/covguard-core.svg)](https://crates.io/crates/covguard-core)
[![docs.rs](https://docs.rs/covguard-core/badge.svg)](https://docs.rs/covguard-core)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Backward-compatible facade crate that re-exports covguard-app.

## Overview

This crate exists for backward compatibility with earlier versions of covguard. It simply re-exports all public items from `covguard-app`, allowing existing integrations to continue working without code changes during migration.

**Migration guidance:**
- New integrations should depend on `covguard-app` directly
- Existing integrations can keep using `covguard-core` during transition
- Both crates expose the same API surface

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-core = "0.1"
```

### Example

```rust
// This works the same as covguard-app
use covguard_core::run_check;

// For new code, prefer:
// use covguard_app::run_check;
```

## Documentation

- [API Documentation](https://docs.rs/covguard-core)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
