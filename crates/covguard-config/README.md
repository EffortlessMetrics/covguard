# covguard-config

Configuration crate for covguard.

## Responsibility

- Parse `covguard.toml`
- Apply built-in profiles (`oss`, `moderate`, `team`, `strict`)
- Resolve effective config with precedence: CLI overrides > file values > profile/defaults

## Main API

- `load_config`
- `discover_config`
- `resolve_config`
- `profile_defaults`
