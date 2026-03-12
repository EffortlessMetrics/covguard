# covguard-output-features

This crate owns the output feature-flag contract used by covguard:

- Materialized rendering feature flags
- Partial TOML/JSON configuration for overrides
- Shared output truncation helper

Keep this crate small and stable so it can be reused by core orchestration,
CLI/configuration, and BDD consumers without pulling renderer dependencies.
