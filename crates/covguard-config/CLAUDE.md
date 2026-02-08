# covguard-config

Configuration parsing, profiles, and CLI precedence resolution.

## Purpose

This crate handles all configuration management including TOML parsing, built-in profiles, path filtering, and the precedence chain for resolving effective configuration.

## Key Types

- **`Config`** - TOML configuration structure
- **`Profile`** - Built-in profiles: Oss, Moderate, Team, Strict
- **`EffectiveConfig`** - Resolved configuration after applying precedence
- **`CliOverrides`** - CLI argument overrides
- **`Scope`** - Added, Touched
- **`FailOn`** - Never, Error, WarnOrError
- **`MissingBehavior`** - How to handle files with no coverage data

## Key Functions

- **`parse_config(toml: &str) -> Result<Config>`** - Parse TOML
- **`load_config(path: &Path) -> Result<Config>`** - Load from file
- **`discover_config(start: &Path) -> Option<PathBuf>`** - Auto-discover covguard.toml
- **`resolve_config(profile, file, cli) -> EffectiveConfig`** - Apply precedence
- **`profile_defaults(profile: Profile) -> EffectiveConfig`** - Get profile defaults
- **`should_include_path(path, include, exclude) -> bool`** - Glob-based filtering

## Profiles

| Profile  | Threshold | Scope   | Fail On |
|----------|-----------|---------|---------|
| Oss      | 70%       | Added   | Never   |
| Moderate | 75%       | Added   | Error   |
| Team     | 80%       | Added   | Error   |
| Strict   | 90%       | Touched | Error   |

## Precedence Order

1. CLI arguments (highest)
2. Config file (covguard.toml)
3. Profile defaults
4. Global defaults (lowest)

## Configuration Discovery

Searches for `covguard.toml` starting from the current directory and walking up to parent directories.

## Testing

- Configuration parsing
- Profile defaults
- Path filtering with globs
- Precedence resolution

## Dependencies

- `serde` / `toml` - Configuration parsing
- `thiserror` - Error types
- `glob` - Path pattern matching
