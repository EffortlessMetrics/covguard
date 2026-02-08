# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-05

### Added

- Initial release of covguard - a diff-scoped coverage gate for pull requests
- Core diff coverage analysis pipeline
  - Parse unified diff format (patch files or git diff output)
  - Parse LCOV coverage reports with support for merging multiple files
  - Evaluate coverage policy against changed lines
- CLI interface with `check` and `explain` commands
- Multiple output formats
  - JSON report (`covguard.report.v1` schema)
  - Markdown PR comment
  - GitHub workflow annotations
  - SARIF 2.1.0 for static analysis tooling
- Configuration system
  - TOML configuration file support (`covguard.toml`)
  - Built-in profiles: `oss`, `moderate`, `team`, `strict`
  - CLI argument overrides
- Policy options
  - Configurable coverage threshold percentage
  - Scope selection: `added` (new lines only) or `touched` (all changed lines)
  - Failure behavior: `never`, `error`, `warn-or-error`
- Ignore directive support (`// covguard: ignore` comments)
- Path normalization for cross-platform compatibility
- Deterministic output ordering for reproducible builds
- Comprehensive test suite
  - Unit tests
  - Property-based tests (proptest)
  - BDD tests (Cucumber)
  - Integration tests

### Crates

- `covguard` - CLI binary
- `covguard-app` - High-level orchestration
- `covguard-domain` - Pure domain logic
- `covguard-types` - Core types and DTOs
- `covguard-config` - Configuration parsing
- `covguard-render` - Output rendering
- `covguard-adapters-diff` - Diff parsing adapter
- `covguard-adapters-coverage` - LCOV parsing adapter

[Unreleased]: https://github.com/cov-guard/cov-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cov-guard/cov-guard/releases/tag/v0.1.0
