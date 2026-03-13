# covguard-types

[![crates.io](https://img.shields.io/crates/v/covguard-types.svg)](https://crates.io/crates/covguard-types)
[![docs.rs](https://docs.rs/covguard-types/badge.svg)](https://docs.rs/covguard-types)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Core shared types and DTOs for covguard.

## Overview

This crate defines the data transfer objects used throughout covguard, including the report schema, findings, verdicts, error codes, and severity levels. It provides stable types for covguard report structures and code constants across crates and integrations.

**Key components:**
- Report schema DTOs (`Report`, `Finding`, `Verdict`, `ReportData`)
- Severity and status enums (`Severity`, `VerdictStatus`, `InputStatus`)
- Shared constants (`SCHEMA_ID`, error codes, reason tokens)
- Code registry with `explain(code)` helper for error metadata
- Fingerprint helper (`compute_fingerprint`) for stable finding identifiers

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-types = "0.1"
```

### Example

```rust
use covguard_types::{
    Finding, Location, Severity, VerdictStatus,
    CODE_UNCOVERED_LINE, explain, compute_fingerprint,
};

// Look up error code metadata
if let Some(info) = explain(CODE_UNCOVERED_LINE) {
    println!("{}: {}", info.name, info.short_description);
}

// Create a finding with a stable fingerprint
let fingerprint = compute_fingerprint(&[CODE_UNCOVERED_LINE, "src/lib.rs", "42"]);
let finding = Finding {
    severity: Severity::Error,
    check_id: "diff.uncovered_line".to_string(),
    code: CODE_UNCOVERED_LINE.to_string(),
    message: "Uncovered changed line (hits=0).".to_string(),
    location: Some(Location {
        path: "src/lib.rs".to_string(),
        line: Some(42),
        col: None,
    }),
    data: None,
    fingerprint: Some(fingerprint),
};
```

## Documentation

- [API Documentation](https://docs.rs/covguard-types)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
