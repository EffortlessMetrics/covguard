# covguard

[![crates.io](https://img.shields.io/crates/v/covguard-cli)](https://crates.io/crates/covguard-cli)
[![docs.rs](https://docs.rs/covguard-cli/badge.svg)](https://docs.rs/covguard-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)
[![CI](https://github.com/effortlessmetrics/cov-guard/workflows/CI/badge.svg)](https://github.com/effortlessmetrics/cov-guard/actions/workflows/ci.yml)

**covguard** is a diff-scoped coverage gate for pull requests.

It answers one question:

> Did this PR add or change lines that are not covered by tests?

## Features

- **Diff-scoped analysis** — Only evaluates added or changed lines, not entire codebase
- **LCOV support** — Consumes standard LCOV coverage reports from any language/tool
- **Multiple diff sources** — Accepts patch files, stdin, or git refs (base/head SHAs)
- **Configurable policies** — Built-in profiles (`oss`, `team`, `strict`) or custom TOML config
- **Multiple output formats** — JSON receipts, markdown PR comments, SARIF, GitHub annotations
- **Ignore directives** — Support `covguard: ignore` comments in source code
- **Deterministic output** — Sorted findings for reproducible results
- **Schema-compliant** — Reports validate against JSON schemas in `contracts/schemas/`
- **Fast** — No runtime allocations in hot paths; minimal dependencies

## Installation

### From crates.io

```bash
cargo install covguard-cli
```

This installs the `covguard` binary (published as `covguard-cli` on crates.io).

### From source

```bash
git clone https://github.com/effortlessmetrics/cov-guard.git
cd cov-guard
cargo install --path crates/covguard-cli
```

### As a library

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-app = "0.1.0"
```

Individual crates are also available:
- [`covguard-types`](crates/covguard-types) — Report DTOs, codes, constants
- [`covguard-domain`](crates/covguard-domain) — Pure policy evaluation
- [`covguard-orchestrator`](crates/covguard-orchestrator) — Orchestration layer
- [`covguard-render`](crates/covguard-render) — Markdown/SARIF/annotations renderers

**Browse all crates on [crates.io](https://crates.io/search?q=covguard)**

## Quick Start

### Using a patch file

```bash
covguard check \
  --diff-file fixtures/diff/simple_added.patch \
  --lcov fixtures/lcov/uncovered.info \
  --out artifacts/covguard/report.json
```

### Using git refs

```bash
covguard check \
  --base "$BASE_SHA" --head "$HEAD_SHA" \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

## Usage

### CLI Commands

#### `covguard check`

Check diff coverage against LCOV coverage data.

```bash
covguard check [OPTIONS]
```

**Diff source options** (choose one):
| Option | Description |
|--------|-------------|
| `--diff-file <PATH>` | Path to unified diff/patch file |
| `--base <SHA>` | Base git ref (requires `--head`) |
| `--head <SHA>` | Head git ref (requires `--base`) |

**Required options**:
| Option | Description |
|--------|-------------|
| `--lcov <PATH>` | Path to LCOV coverage file (repeatable for multiple files) |

**Output options**:
| Option | Default | Description |
|--------|---------|-------------|
| `--out <PATH>` | `artifacts/covguard/report.json` | Output path for JSON report |
| `--md <PATH>` | — | Output path for markdown comment |
| `--sarif <PATH>` | — | Output path for SARIF report |
| `--raw` | `false` | Save raw diff/LCOV inputs to `artifacts/covguard/raw` |

**Configuration options**:
| Option | Description |
|--------|-------------|
| `--config <PATH>` | Path to config file (default: auto-discover `covguard.toml`) |
| `--profile <PROFILE>` | Configuration profile: `oss`, `moderate`, `team`, `strict`, `lenient` |
| `--scope <SCOPE>` | Line scope: `added` (default) or `touched` |
| `--threshold <PCT>` | Minimum diff coverage percentage (0-100) |
| `--no-ignore` | Disable `covguard: ignore` directives |
| `--path-strip <PREFIX>` | Prefix to strip from LCOV SF paths (repeatable) |

**Truncation options**:
| Option | Description |
|--------|-------------|
| `--max-markdown-lines <N>` | Maximum markdown lines in output |
| `--max-annotations <N>` | Maximum annotations in output |
| `--max-sarif-results <N>` | Maximum SARIF results in output |
| `--max-findings <N>` | Maximum findings in report |

**Mode options**:
| Option | Description |
|--------|-------------|
| `--mode <MODE>` | `standard` (exit by verdict) or `cockpit` (exit 0 if receipt written) |
| `--payload <PATH>` | Output path for full domain payload (cockpit mode) |

#### `covguard explain`

Explain an error code.

```bash
covguard explain <CODE>
```

Example:
```bash
covguard explain covguard.diff.uncovered_line
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Pass (or warn when not configured to fail) |
| `1` | Tool/runtime error (I/O, parse failure) |
| `2` | Policy failure (blocking findings) |

## Output Formats

### JSON Report

The canonical output is a schema-compliant JSON receipt at `artifacts/covguard/report.json`:

```json
{
  "schema_id": "covguard.report.v1",
  "run_id": "uuid",
  "timestamp": "2026-03-13T00:00:00Z",
  "verdict": "fail",
  "summary": {
    "total_changed_lines": 10,
    "covered_lines": 7,
    "uncovered_lines": 3,
    "diff_coverage_pct": 70.0
  },
  "findings": [
    {
      "check_id": "covguard.diff.uncovered_line",
      "severity": "error",
      "path": "src/lib.rs",
      "line": 42,
      "message": "Changed line has no test coverage"
    }
  ]
}
```

### Markdown

Generate a PR-ready markdown comment with `--md`:

```bash
covguard check --base "$BASE" --head "$HEAD" --lcov coverage.info --out report.json --md comment.md
```

### SARIF

Generate SARIF output for GitHub Advanced Security or other tools:

```bash
covguard check --base "$BASE" --head "$HEAD" --lcov coverage.info --out report.json --sarif results.sarif.json
```

### GitHub Annotations

For inline annotations in GitHub Actions, use the SARIF output with the `github/codeql-action/upload-sarif` action.

## Configuration

### CLI Flags

All configuration options can be set via CLI flags (see [Usage](#usage) above). CLI flags take precedence over config files.

### TOML Config File

Create a `covguard.toml` in your project root:

```toml
# covguard.toml
profile = "team"          # oss|moderate|team|strict|lenient
scope = "added"           # added|touched
fail_on = "error"         # error|warn|never

min_diff_coverage_pct = 80
max_uncovered_lines = 25

# How to treat missing coverage records
missing_coverage = "warn" # skip|warn|fail
missing_file = "warn"     # skip|warn|fail

[paths]
exclude = ["target/**", "**/generated/**", "vendor/**", "fixtures/**"]
include = []              # optional allowlist

[ignore]
directives = true         # enable `covguard: ignore`

[normalize]
# Prefixes to strip from LCOV SF paths (useful in CI)
path_strip = ["/home/runner/work/repo/repo/"]
```

### Built-in Profiles

| Profile | Description |
|---------|-------------|
| `oss` | Lenient, warnings only, high thresholds |
| `moderate` | Balanced defaults for most projects |
| `team` | Stricter, fail on errors, reasonable thresholds |
| `strict` | Fail on any uncovered lines, high coverage bar |
| `lenient` | Most permissive, never fail |

## Integration Examples

### GitHub Actions

```yaml
name: Coverage Gate

on:
  pull_request:
    branches: [main]

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Important for base/head diffs

      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-llvm-cov
        run: cargo install cargo-llvm-cov --locked

      - name: Generate coverage (LCOV)
        run: cargo llvm-cov --lcov --output-path artifacts/coverage/lcov.info

      - name: Run covguard
        run: |
          covguard check \
            --base "${{ github.event.pull_request.base.sha }}" \
            --head "${{ github.sha }}" \
            --lcov artifacts/coverage/lcov.info \
            --out artifacts/covguard/report.json \
            --md artifacts/covguard/comment.md

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: covguard-artifacts
          path: artifacts/
```

### GitLab CI

```yaml
coverage-gate:
  stage: test
  image: rust:latest
  script:
    - cargo install cargo-llvm-cov covguard-cli
    - cargo llvm-cov --lcov --output-path lcov.info
    - covguard check
        --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
        --head "$CI_COMMIT_SHA"
        --lcov lcov.info
        --out covguard-report.json
        --md covguard-comment.md
  artifacts:
    paths:
      - covguard-report.json
      - covguard-comment.md
  only:
    - merge_requests
```

### Pre-commit Hook

Add to `.git/hooks/pre-push` or use with [pre-commit](https://pre-commit.com/):

```bash
#!/bin/bash
# .git/hooks/pre-push

# Generate coverage
cargo llvm-cov --lcov --output-path lcov.info

# Get the diff between local and remote main
BASE=$(git merge-base origin/main HEAD)
HEAD=$(git rev-parse HEAD)

# Run covguard
covguard check \
  --base "$BASE" \
  --head "$HEAD" \
  --lcov lcov.info \
  --out artifacts/covguard/report.json

exit $?
```

## Documentation

- **API Documentation**: [docs.rs/covguard-cli](https://docs.rs/covguard-cli)
- **Requirements**: [`docs/requirements.md`](docs/requirements.md)
- **Design**: [`docs/design.md`](docs/design.md)
- **Architecture**: [`docs/architecture.md`](docs/architecture.md)
- **Integration Guide**: [`docs/integration.md`](docs/integration.md)
- **Error Codes**: [`docs/codes.md`](docs/codes.md)
- **Testing Strategy**: [`docs/testing.md`](docs/testing.md)

## Crates

| Crate | Description |
|-------|-------------|
| [`covguard-cli`](crates/covguard-cli) | CLI binary |
| [`covguard-orchestrator`](crates/covguard-orchestrator) | Orchestration layer |
| [`covguard-app`](crates/covguard-app) | Compatibility facade |
| [`covguard-domain`](crates/covguard-domain) | Pure policy evaluation |
| [`covguard-types`](crates/covguard-types) | Report DTOs, codes, constants |
| [`covguard-ports`](crates/covguard-ports) | Port traits and boundary types |
| [`covguard-adapters-diff`](crates/covguard-adapters-diff) | Unified diff parser + git diff loader |
| [`covguard-adapters-coverage`](crates/covguard-adapters-coverage) | LCOV parser/merger |
| [`covguard-adapters-repo`](crates/covguard-adapters-repo) | Filesystem repo reader |
| [`covguard-adapters-artifacts`](crates/covguard-adapters-artifacts) | Artifact persistence adapter |
| [`covguard-render`](crates/covguard-render) | Markdown, annotations, SARIF renderers |
| [`covguard-config`](crates/covguard-config) | Config/profile resolution |

## Contributing

Contributions are welcome! Please see [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
