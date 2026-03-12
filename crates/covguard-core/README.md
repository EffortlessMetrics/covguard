# covguard-core

Compatibility facade for legacy integrations.

This crate currently re-exports `covguard-app`.

## Guidance

- New integrations should depend on `covguard-app` directly.
- Existing integrations can keep `covguard-core` during migration.
