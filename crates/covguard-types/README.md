# covguard-types

Core shared types for covguard.

## What This Crate Contains

- Report schema DTOs (`Report`, `Finding`, `Verdict`, `ReportData`)
- Shared constants (`SCHEMA_ID`, error codes, reason tokens)
- Code registry and `explain(code)` helper
- Fingerprint helper (`compute_fingerprint`)

## Intended Usage

Use this crate when you need stable covguard report structures or code constants across crates and integrations.
