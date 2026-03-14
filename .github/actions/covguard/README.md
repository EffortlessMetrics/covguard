# covguard GitHub Action

> Diff-scoped coverage gate for pull requests — ensures new/changed code is covered by tests.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-covguard-blue)](https://github.com/marketplace/actions/covguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is covguard?

covguard is a diff-scoped coverage gate that answers the question: **"Did this PR add or change lines that are not covered by tests?"**

Unlike global coverage tools, covguard focuses only on the lines you're changing. This means:
- ✅ You can improve coverage incrementally
- ✅ No need to fix legacy uncovered code
- ✅ Prevents new technical debt from accumulating
- ✅ Clear, actionable feedback on PRs

## Features

- 🔍 **Diff-scoped analysis** — Only checks new/changed lines
- 📊 **Multiple formats** — LCOV, JaCoCo XML, coverage.py JSON
- 💬 **PR comments** — Automatic comments with coverage results
- 🚨 **GitHub annotations** — Inline warnings for uncovered lines
- 📈 **SARIF output** — Integration with GitHub Code Scanning
- 🎯 **Threshold support** — Set minimum coverage percentages
- ⚙️ **Configurable** — Via inputs or configuration file

## Quick Start

### Basic Usage

```yaml
name: Diff Coverage

on:
  pull_request:
    branches: [main]

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Required for git diff

      - name: Generate coverage
        run: |
          # Generate your coverage report here
          cargo llvm-cov --lcov --output-path lcov.info

      - name: Check diff coverage
        uses: covguard/covguard@v1
        with:
          coverage-file: lcov.info
```

### With PR Comments and Annotations

```yaml
- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    comment-pr: true
    annotations: true
    fail-on-uncovered: true
```

### With Minimum Threshold

```yaml
- name: Check diff coverage (80% minimum)
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    fail-threshold: 80
    comment-pr: true
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `coverage-file` | Path to coverage report (LCOV, JaCoCo, or coverage.py) | ✅ Yes | — |
| `coverage-format` | Format: `lcov`, `jacoco`, `coverage-py`. Auto-detected if not specified | No | Auto |
| `diff-base` | Base ref for diff (e.g., `origin/main`) | No | `${{ github.base_ref }}` |
| `diff-head` | Head ref for diff (e.g., `${{ github.sha }}`) | No | `${{ github.sha }}` |
| `diff-file` | Pre-generated patch file. If provided, base/head are ignored | No | — |
| `fail-threshold` | Minimum coverage % to pass (0-100) | No | `0` |
| `fail-on-uncovered` | Fail if any changed lines are uncovered | No | `true` |
| `comment-pr` | Post comment on PR with results | No | `true` |
| `comment-mode` | How to post comments: `create`, `update`, `delete-on-pass` | No | `update` |
| `annotations` | Create GitHub annotations for uncovered lines | No | `true` |
| `sarif-output` | Generate SARIF for GitHub Code Scanning | No | `false` |
| `report-output` | Path for JSON report | No | `artifacts/covguard/report.json` |
| `markdown-output` | Path for markdown comment | No | `artifacts/covguard/comment.md` |
| `token` | GitHub token for PR comments | No | `${{ github.token }}` |
| `version` | covguard version to install | No | `latest` |
| `working-directory` | Working directory for commands | No | `.` |
| `skip-missing-coverage` | Skip files without coverage data | No | `false` |
| `config-file` | Path to covguard.toml configuration file | No | — |

## Outputs

| Output | Description |
|--------|-------------|
| `passed` | Whether the coverage check passed (`true`/`false`) |
| `coverage-percent` | Diff coverage percentage (0-100) |
| `uncovered-lines` | Number of uncovered changed lines |
| `covered-lines` | Number of covered changed lines |
| `total-lines` | Total number of changed lines |
| `report-path` | Path to the generated JSON report |
| `comment-path` | Path to the generated markdown comment |

### Using Outputs

```yaml
- name: Check diff coverage
  id: covguard
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info

- name: Summary
  run: |
    echo "Passed: ${{ steps.covguard.outputs.passed }}"
    echo "Coverage: ${{ steps.covguard.outputs.coverage-percent }}%"
    echo "Uncovered lines: ${{ steps.covguard.outputs.uncovered-lines }}"
```

## Coverage Formats

### LCOV (Rust, JavaScript, etc.)

```yaml
- name: Generate LCOV coverage
  run: cargo llvm-cov --lcov --output-path lcov.info

- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    coverage-format: lcov  # Optional, auto-detected from .info extension
```

### JaCoCo (Java/Kotlin)

```yaml
- name: Generate JaCoCo coverage
  run: mvn test jacoco:report

- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: target/site/jacoco/jacoco.xml
    coverage-format: jacoco
```

### coverage.py (Python)

```yaml
- name: Generate coverage.py coverage
  run: pytest --cov=src --cov-report=json:coverage.json

- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: coverage.json
    coverage-format: coverage-py
```

## PR Comment Modes

### `create` (default)
Always creates a new comment on each run.

### `update`
Updates the existing comment if one exists (recommended for most use cases).

### `delete-on-pass`
Deletes the comment when coverage passes — keeps PRs clean when everything is good.

```yaml
- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    comment-pr: true
    comment-mode: delete-on-pass
```

## GitHub Annotations

When `annotations: true` (default), covguard creates inline warnings for each uncovered line:

```
warning[src/main.rs:42]: Changed line has no test coverage
warning[src/utils.rs:15]: Changed line has no test coverage
```

These appear in the PR's "Files changed" view and the Actions summary.

## SARIF Integration

For GitHub Code Scanning integration:

```yaml
- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    sarif-output: true
    fail-on-uncovered: false  # Non-blocking for SARIF
```

Results appear in the repository's Security > Code Scanning alerts.

## Configuration File

For complex configurations, use a `covguard.toml` file:

```toml
# covguard.toml
[coverage]
fail_threshold = 80
skip_missing = true

[diff]
base = "origin/main"

[output]
report = "artifacts/covguard/report.json"
markdown = "artifacts/covguard/comment.md"

# Ignore specific paths
[[ignore]]
path = "generated/**"

[[ignore]]
path = "**/*.test.ts"
```

Then reference it in your workflow:

```yaml
- name: Check diff coverage
  uses: covguard/covguard@v1
  with:
    coverage-file: lcov.info
    config-file: covguard.toml
```

## Complete Example

Here's a complete workflow for a Rust project:

```yaml
name: Diff Coverage

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

concurrency:
  group: diff-coverage-${{ github.ref }}
  cancel-in-progress: true

jobs:
  coverage:
    name: Generate Coverage
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Generate coverage
        run: cargo llvm-cov --lcov --output-path lcov.info

      - name: Upload coverage
        uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: lcov.info

  diff-coverage:
    name: Check Diff Coverage
    runs-on: ubuntu-latest
    needs: coverage
    if: github.event_name == 'pull_request'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Download coverage
        uses: actions/download-artifact@v4
        with:
          name: coverage

      - name: Check diff coverage
        id: covguard
        uses: covguard/covguard@v1
        with:
          coverage-file: lcov.info
          fail-threshold: 80
          comment-pr: true
          comment-mode: update
          annotations: true

      - name: Summary
        run: |
          echo "## Diff Coverage Results" >> $GITHUB_STEP_SUMMARY
          echo "" >> $GITHUB_STEP_SUMMARY
          echo "| Metric | Value |" >> $GITHUB_STEP_SUMMARY
          echo "|--------|-------|" >> $GITHUB_STEP_SUMMARY
          echo "| Passed | ${{ steps.covguard.outputs.passed }} |" >> $GITHUB_STEP_SUMMARY
          echo "| Coverage | ${{ steps.covguard.outputs.coverage-percent }}% |" >> $GITHUB_STEP_SUMMARY
          echo "| Uncovered Lines | ${{ steps.covguard.outputs.uncovered-lines }} |" >> $GITHUB_STEP_SUMMARY
```

## Exit Codes

The action uses these exit codes:
- `0` — Pass (all changed lines are covered or threshold met)
- `2` — Policy fail (uncovered lines or threshold not met)
- `1` — Tool/runtime error (I/O, parse failure, etc.)

## Troubleshooting

### "Failed to determine latest version"

This happens when the GitHub API rate limit is exceeded. Solution:
1. Pin to a specific version: `version: v0.3.0`
2. Or use a GitHub token with higher rate limits

### "No coverage data found for file"

This means a file with changes has no coverage data. Options:
1. Add tests for the file
2. Use `skip-missing-coverage: true` to skip these files
3. Use an ignore pattern in `covguard.toml`

### "fetch-depth: 0 is required"

covguard needs full git history to compute accurate diffs. Make sure your checkout includes:
```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

## Versioning

We recommend pinning to a specific version for production use:

```yaml
uses: covguard/covguard@v1.0.0  # Pin to exact version
```

Or use the major version tag for automatic minor/patch updates:

```yaml
uses: covguard/covguard@v1  # Gets latest v1.x.x
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 📖 [Documentation](https://github.com/covguard/covguard#readme)
- 🐛 [Issue Tracker](https://github.com/covguard/covguard/issues)
- 💬 [Discussions](https://github.com/covguard/covguard/discussions)
