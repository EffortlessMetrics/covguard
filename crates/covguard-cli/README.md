# covguard

[![crates.io](https://img.shields.io/crates/v/covguard.svg)](https://crates.io/crates/covguard)
[![docs.rs](https://docs.rs/covguard/badge.svg)](https://docs.rs/covguard)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](../../LICENSE)

A diff-scoped coverage gate for pull requests. Answers: "Did this PR add or change lines that are not covered by tests?"

## Overview

`covguard` is a CLI tool that checks whether changed lines in a pull request are covered by tests. It consumes a diff (base↔head refs or patch file) and LCOV coverage data, then emits a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).

**Not**: A coverage generator or global coverage policy tool. It's a ratchet-by-default sensor that only evaluates added lines unless configured otherwise.

## Installation

```bash
cargo install covguard
```

## Usage

### Basic check with patch file

```bash
covguard check \
  --diff-file patch.diff \
  --lcov coverage.info \
  --out report.json
```

### Reading diff from stdin

Use `-` as the diff file path to read from stdin:

```bash
git diff main...feature | covguard check --diff-file - --lcov coverage.info --out report.json
```

Or pipe diff content directly:

```bash
cat changes.patch | covguard check --diff-file - --lcov coverage.info --out report.json
```

You can also omit `--diff-file` entirely and covguard will automatically read from stdin if no other diff source is provided:

```bash
git diff main...feature | covguard check --lcov coverage.info --out report.json
```

### With git refs and markdown output

```bash
covguard check \
  --base "$BASE_SHA" --head "$HEAD_SHA" \
  --lcov coverage.info \
  --out report.json \
  --md comment.md
```

### Commands

- `covguard check` — Run diff-scoped coverage analysis
- `covguard explain <code>` — Explain covguard error codes

### Options

| Option | Description |
|--------|-------------|
| `--diff-file <PATH>` | Path to diff/patch file, or `-` to read from stdin |
| `--base <SHA>` | Base git ref (alternative to `--diff-file`) |
| `--head <SHA>` | Head git ref (alternative to `--diff-file`) |
| `--lcov <PATH>` | Path to LCOV coverage file |
| `--out <PATH>` | Output path for JSON report |
| `--md <PATH>` | Output path for markdown comment |
| `--sarif <PATH>` | Output path for SARIF report |
| `--threshold <PCT>` | Coverage threshold percentage (default: 80) |
| `--scope <SCOPE>` | Analysis scope: `added` or `touched` (default: `added`) |
| `--profile <PROFILE>` | Policy profile: `oss`, `moderate`, `team`, `strict`, `lenient` |

### Exit Codes

- `0` — Pass (or warn when not fail-configured)
- `2` — Policy fail (blocking findings)
- `1` — Tool/runtime error (I/O, parse failure)

## Documentation

- [API Documentation](https://docs.rs/covguard)
- [Main Repository](https://github.com/covguard/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
