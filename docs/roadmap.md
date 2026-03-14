# covguard Roadmap

[![crates.io](https://img.shields.io/crates/v/covguard-cli)](https://crates.io/crates/covguard-cli)

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

### v0.1.0 (2026-03-12) - Initial Release

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

### v0.2.0 - Enhanced Ergonomics ✅ Complete

**Focus:** Developer experience and feedback quality

- ✅ Improved error messages with remediation hints
- ✅ JaCoCo XML coverage format support (Java ecosystem)
- ✅ coverage.py JSON format support (Python ecosystem)
- ✅ Stdin diff input support (`--diff-file -`)
- ✅ Performance profiling with `--timing` flag
- ✅ Criterion benchmarks for performance tracking
- ✅ Expanded documentation and examples

### v0.3.0 - Extended Integration ✅ Complete

**Focus:** CI/CD ecosystem integration

- ✅ Official GitHub Action (`.github/actions/covguard/`)
- ✅ GitLab CI templates (`templates/gitlab/`)
- ✅ Community feedback integration
- ✅ Performance profiling and optimization

### v1.0.0 - Stable API

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
| LCOV | ✅ v0.1.0 | Primary format |
| JaCoCo XML | ✅ v0.2.0 | Java ecosystem |
| coverage.py JSON | ✅ v0.2.0 | Python ecosystem |

### Diff Sources

| Source | Status | Notes |
|--------|--------|-------|
| Unified diff patches | ✅ v0.1.0 | `--diff-file` |
| Git refs | ✅ v0.1.0 | `--base` / `--head` |
| Stdin | ✅ v0.2.0 | `--diff-file -` for pipe support |

### Output Formats

| Format | Status | Notes |
|--------|--------|-------|
| JSON Report | ✅ v0.1.0 | Schema-compliant |
| Markdown | ✅ v0.1.0 | PR comments |
| GitHub Annotations | ✅ v0.1.0 | Workflow integration |
| SARIF 2.1.0 | ✅ v0.1.0 | Code scanning |

### Configuration

| Feature | Status | Notes |
|---------|--------|-------|
| CLI flags | ✅ v0.1.0 | Full support |
| TOML config | ✅ v0.1.0 | `covguard.toml` |
| Built-in profiles | ✅ v0.1.0 | 5 profiles |
| Ignore directives | ✅ v0.1.0 | Line/block level |

## Feature Roadmap

### Core Features

| Feature | Status | Version | Notes |
|---------|--------|---------|-------|
| Diff parsing (unified) | ✅ Complete | 0.1.0 | Patch files, git refs |
| LCOV parsing | ✅ Complete | 0.1.0 | Full format support |
| Policy evaluation | ✅ Complete | 0.1.0 | Threshold, scope, behavior |
| JSON report output | ✅ Complete | 0.1.0 | Schema v1 compliant |
| Markdown rendering | ✅ Complete | 0.1.0 | PR comments |
| SARIF output | ✅ Complete | 0.1.0 | 2.1.0 format |
| GitHub Annotations | ✅ Complete | 0.1.0 | Workflow integration |
| TOML configuration | ✅ Complete | 0.1.0 | covguard.toml |
| Ignore directives | ✅ Complete | 0.1.0 | Line/block level |
| Built-in profiles | ✅ Complete | 0.1.0 | 5 profiles |

### v0.2.0–0.3.0 Features

| Feature | Status | Version | Notes |
|---------|--------|---------|-------|
| Stdin diff input | ✅ Complete | 0.2.0 | `--diff-file -` pipe support |
| Enhanced error messages | ✅ Complete | 0.2.0 | Remediation hints |
| Performance profiling | ✅ Complete | 0.2.0 | `--timing` flag, criterion benchmarks |
| JaCoCo XML parser | ✅ Complete | 0.2.0 | Java ecosystem |
| coverage.py JSON parser | ✅ Complete | 0.2.0 | Python ecosystem |
| GitHub Action | ✅ Complete | 0.3.0 | `.github/actions/covguard/` |
| GitLab CI templates | ✅ Complete | 0.3.0 | `templates/gitlab/` |

### Future Features

| Feature | Status | Target | Notes |
|---------|--------|--------|-------|
| Global coverage tracking | 💭 Exploring | TBD | Opt-in feature |
| IDE integration | 💭 Exploring | TBD | VS Code, IntelliJ |

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
| GitHub Actions | ✅ v0.3.0 | Official action (`.github/actions/covguard/`) |
| GitLab CI | ✅ v0.3.0 | Template examples (`templates/gitlab/`) |
| Bitbucket | 💭 Exploring | Community demand |
| Azure DevOps | 💭 Exploring | Community demand |

### Language Coverage Tooling
| Language | Coverage Tool | LCOV Support | Native Format |
|----------|--------------|--------------|---------------|
| Rust | cargo-llvm-cov | ✅ Native | — |
| C/C++ | gcov | ✅ Native | — |
| Python | coverage.py | ✅ Via lcov output | ✅ JSON (v0.2.0) |
| Java | JaCoCo | ✅ Via lcov output | ✅ XML (v0.2.0) |
| JavaScript | c8/istanbul | ✅ Via lcov output | — |

## Related Documentation

- [Implementation Plan](implementation-plan.md) - Phase details
- [Requirements](requirements.md) - Goals and non-goals
- [Architecture](architecture.md) - System design
- [Integration Guide](integration.md) - CI/CD setup
