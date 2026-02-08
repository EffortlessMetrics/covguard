# covguard-cli

Command-line interface for covguard.

## Purpose

This crate provides the CLI binary that users invoke directly. It handles argument parsing, configuration loading, file I/O, and maps results to appropriate exit codes.

## Commands

### `covguard check`

Main command for diff coverage analysis.

```bash
# With patch file
covguard check \
  --diff-file fixtures/diff/simple_added.patch \
  --lcov fixtures/lcov/coverage.info \
  --out artifacts/covguard/report.json

# With git refs
covguard check \
  --base main --head HEAD \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

## Arguments

| Argument | Description |
|----------|-------------|
| `--diff-file` | Path to unified diff/patch file |
| `--base` / `--head` | Git refs for diff (mutually exclusive with --diff-file) |
| `--lcov` | LCOV file path(s), can be repeated |
| `--out` | Output report JSON path (default: artifacts/covguard/report.json) |
| `--md` | Optional markdown output path |
| `--sarif` | Optional SARIF output path |
| `--raw` | Save raw diff/LCOV inputs to artifacts/covguard/raw |
| `--config` | Config file path (auto-discovers covguard.toml if not set) |
| `--profile` | Built-in profile (oss, moderate, team, strict) |
| `--scope` | Override scope (added, touched) |
| `--threshold` | Override threshold percentage |
| `--no-ignore` | Disable ignore directive processing |

## Configuration Precedence

1. CLI arguments (highest priority)
2. Config file (covguard.toml)
3. Profile defaults
4. Global defaults

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass or Warn (non-blocking) |
| 1 | Tool/runtime error (I/O, parse failure) |
| 2 | Policy fail (blocking findings) |

## Output

- Writes `report.json` to `--out` path
- Writes markdown to `--md` path if specified
- Writes SARIF to `--sarif` path if specified
- Writes raw inputs to `artifacts/covguard/raw` if `--raw` is set
- Prints GitHub annotations to stdout

## Validation

- `--diff-file` and `--base`/`--head` are mutually exclusive
- At least one diff source must be provided (diff file, git refs, or stdin)
- `--lcov` is required

## Dependencies

- `clap` - Argument parsing
- `covguard-core` - Core logic
- `covguard-config` - Configuration
- `covguard-types` - DTOs
