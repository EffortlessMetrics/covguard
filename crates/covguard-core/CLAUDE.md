# covguard-core

Backward-compatibility facade for `covguard-app`.

## Purpose

This crate exists to avoid breaking downstream users that still depend on `covguard-core`.
It re-exports the full public API from `covguard-app`.

## Implementation

- `src/lib.rs` only contains:
  - `pub use covguard_app::*;`

## Guidance

- New code should depend on `covguard-app` directly.
- Keep this crate minimal and free of logic.
