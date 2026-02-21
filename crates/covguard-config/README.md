# covguard-config

Configuration crate for covguard.

## Responsibility

- Parse `covguard.toml`
- Apply built-in profiles (`oss`, `moderate`, `team`, `strict`, `lenient`)
- Resolve effective config with precedence: CLI overrides > file values > profile/defaults
- Apply rendering output budgets (`[output]`) with merge semantics from config + CLI

## Main API

- `load_config`
- `discover_config`
- `resolve_config`
- `profile_defaults`

```toml
[output]
max_markdown_lines = 120
max_annotations = 30
max_sarif_results = 25
```
