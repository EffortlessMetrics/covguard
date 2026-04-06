# covguard Roadmap

[![crates.io](https://img.shields.io/crates/v/covguard)](https://crates.io/crates/covguard)

## Vision

covguard ensures every changed line in a PR has test coverage. It's a diff-scoped coverage gate that answers: "Did this PR add or change lines that are not covered by tests?"

## Goals

### Primary Goals
- **Diff-scoped coverage gating**: Only evaluate added/changed lines
- **Ratchet-by-default**: Prevent coverage regressions, not enforce global thresholds
- **Deterministic output**: Same inputs always produce same outputs

### Quality Goals
- Schema-compliant JSON output
- Cross-platform support
- Comprehensive error handling

### Ecosystem Goals
- CI/CD integration (GitHub Actions, GitLab CI)
- Cockpit aggregation support
- Sensor composition patterns

## Release History

### v0.1.0 (2026-03-12) — Initial Release

**20 crates published to [crates.io](https://crates.io/search?q=covguard)**

**Core Features:**
- Unified diff format support (patch files)
- Git diff output parsing with `--base` and `--head` SHA references
- Full LCOV format support with path normalization
- Configurable coverage threshold percentage
- Scope selection: `added` (new lines only) or `touched` (all changed lines)
- Failure behavior modes: `never`, `error`, `warn-or-error`

**Output Formats:**
- JSON Report (schema-compliant `covguard.report.v1`)
- Markdown PR comment rendering
- GitHub Annotations output
- SARIF 2.1.0 output for code scanning

**Configuration:**
- CLI flags
- TOML configuration file support
- Built-in profiles: `oss`, `team`, `strict`, `lenient`, `moderate`
- `// covguard: ignore` comment support

See [CHANGELOG.md](../CHANGELOG.md) for detailed changes.

## Future Milestones

### v0.2.0 — Enhanced Ergonomics (Complete)

**Focus:** Developer experience and feedback quality

- [x] Improved error messages with remediation hints
- [x] JaCoCo XML coverage format support (Java ecosystem)
- [x] coverage.py JSON format support (Python ecosystem)
- [x] Stdin diff input support (`--diff-file -`)
- [x] Performance profiling with `--timing` flag
- [x] Criterion benchmarks for performance tracking
- [x] SRP microcrate extraction for better maintenance

**Status:** v0.2.0 features fully implemented, tested via BDD, and integrated into CLI/orchestrator.

### v0.3.0 — Extended Integration (Beta)

**Focus:** CI/CD ecosystem integration

- [x] Official GitHub Action (`.github/actions/covguard/`) - Support for multi-format and sensor schema
- [x] GitLab CI templates (`templates/gitlab/`) - Support for native Java/Python tools
- [ ] Community feedback integration
- [ ] Performance optimization based on profiling

**Status:** GitHub Action and GitLab templates updated to align with latest CLI features.

### v1.0.0 — Stable API

**Focus:** Production stability

- Schema stability guarantee
- Breaking change policy documented
- Long-term support commitment
- Complete ADR coverage
- Comprehensive integration testing

## Feature Categories

### Coverage Support

| Format | Status | Notes |
|--------|--------|-------|
| LCOV | Shipped (v0.1.0) | Primary format, fully integrated |
| JaCoCo XML | Shipped (v0.2.0) | Fully wired to CLI + orchestrator |
| coverage.py JSON | Shipped (v0.2.0) | Fully wired to CLI + orchestrator |

### Diff Sources

| Source | Status | Notes |
|--------|--------|-------|
| Unified diff patches | Shipped (v0.1.0) | `--diff-file` |
| Git refs | Shipped (v0.1.0) | `--base` / `--head` |
| Stdin | Shipped (v0.2.0) | `--diff-file -` pipe support |

### Output Formats

| Format | Status | Notes |
|--------|--------|-------|
| JSON Report | Shipped (v0.1.0) | Schema-compliant |
| Markdown | Shipped (v0.1.0) | PR comments |
| GitHub Annotations | Shipped (v0.1.0) | Workflow integration |
| SARIF 2.1.0 | Shipped (v0.1.0) | Code scanning |

### Configuration

| Feature | Status | Notes |
|---------|--------|-------|
| CLI flags | Shipped (v0.1.0) | Full support |
| TOML config | Shipped (v0.1.0) | `covguard.toml` |
| Built-in profiles | Shipped (v0.1.0) | 5 profiles |
| Ignore directives | Shipped (v0.1.0) | Line/block level |

## Feature Roadmap

### Core Features (v0.1.0)

| Feature | Status | Notes |
|---------|--------|-------|
| Diff parsing (unified) | Shipped | Patch files, git refs |
| LCOV parsing | Shipped | Full format support |
| Policy evaluation | Shipped | Threshold, scope, behavior |
| JSON report output | Shipped | Schema v1 compliant |
| Markdown rendering | Shipped | PR comments |
| SARIF output | Shipped | 2.1.0 format |
| GitHub Annotations | Shipped | Workflow integration |
| TOML configuration | Shipped | covguard.toml |
| Ignore directives | Shipped | Line/block level |
| Built-in profiles | Shipped | 5 profiles |

### v0.2.0–0.3.0 Features

| Feature | Status | Notes |
|---------|--------|-------|
| Stdin diff input | Shipped | `--diff-file -` pipe support |
| Enhanced error messages | Shipped | Remediation hints |
| Performance profiling | Shipped | `--timing` flag, criterion benchmarks |
| JaCoCo XML parser | Shipped | Fully wired to CLI + orchestrator |
| coverage.py JSON parser | Shipped | Fully wired to CLI + orchestrator |
| GitHub Action | Shipped | Aligned with latest CLI flags |
| GitLab CI templates | Shipped | Aligned with latest CLI flags |

### Future Features

| Feature | Status | Target | Notes |
|---------|--------|--------|-------|
| Global coverage tracking | Exploring | TBD | Opt-in feature |
| IDE integration | Exploring | TBD | VS Code, IntelliJ |

## Release Cadence

### Versioning Strategy
- **Semantic Versioning**: MAJOR.MINOR.PATCH
- **Schema versioning**: Independent of crate version
- **Breaking changes**: Require MAJOR version bump

### Release Types
- **Patch (0.0.x)**: Bug fixes, documentation
- **Minor (0.x.0)**: New features, enhancements
- **Major (x.0.0)**: Breaking changes

### Support Policy
- Latest minor version: Full support
- Previous minor version: Security fixes only
- Major versions: 6 month support window

## Community & Ecosystem

### Contribution Channels
- GitHub Issues: Bug reports, feature requests
- Pull Requests: Code contributions
- Discussions: Questions, ideas

### Integration Ecosystem
| Platform | Status | Integration Type |
|----------|--------|-----------------|
| GitHub Actions | Shipped | Aligned with latest CLI flags |
| GitLab CI | Shipped | Aligned with latest CLI flags |
| Bitbucket | Exploring | Community demand |
| Azure DevOps | Exploring | Community demand |

### Language Coverage Tooling
| Language | Coverage Tool | LCOV Support | Native Format |
|----------|--------------|--------------|---------------|
| Rust | cargo-llvm-cov | Shipped | — |
| C/C++ | gcov | Shipped | — |
| Python | coverage.py | Via lcov output | Shipped (native JSON) |
| Java | JaCoCo | Via lcov output | Shipped (native XML) |
| JavaScript | c8/istanbul | Via lcov output | — |

## Related Documentation

- [Implementation Plan](implementation-plan.md) — Phase details
- [Requirements](requirements.md) — Goals and non-goals
- [Architecture](architecture.md) — System design
- [Integration Guide](integration.md) — CI/CD setup
