# covguard-ports

Shared traits for the hexagonal boundaries used by covguard crates.

## Purpose

This crate keeps port interfaces stable and dependency-light so orchestration (`covguard-app`) and adapters can depend on the same contracts without circular dependencies.

## Exposed Traits

- `Clock` - Time provider abstraction (`now() -> DateTime<Utc>`)
- `RepoReader` - Source line reader for ignore directive detection

## Dependency Rule

- Keep this crate minimal.
- Avoid bringing in parsing, rendering, or CLI concerns.