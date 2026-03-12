# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-11

### Added

- Initial release of covguard, a diff-scoped coverage gate for pull requests
- Unified diff format support (patch files)
- Git diff output parsing with `--base` and `--head` SHA references
- Full LCOV format support with path normalization
- Configurable coverage threshold percentage
- Scope selection: `added` (new lines only) or `touched` (all changed lines)
- Failure behavior modes: `never`, `error`, `warn-or-error`
- JSON Report output in schema-compliant `covguard.report.v1` format
- Markdown PR comment rendering with configurable truncation
- GitHub Annotations output for workflow integration
- SARIF 2.1.0 output for code scanning
- `// covguard: ignore` comment support (line-level and block-level)
- TOML configuration file support (`covguard.toml`)
- Built-in profiles: `oss`, `team`, `strict`, `lenient`, `moderate`
- Dual licensing: Apache-2.0 OR MIT

[Unreleased]: https://github.com/effortlessmetrics/cov-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/effortlessmetrics/cov-guard/releases/tag/v0.1.0
