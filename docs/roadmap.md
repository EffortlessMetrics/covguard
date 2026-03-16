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

### v0.2.0 — Enhanced Ergonomics (In Progress)

**Focus:** Developer experience and feedback quality

- [ ] Improved error messages with remediation hints
- [ ] JaCoCo XML coverage format support (Java ecosystem)
- [ ] coverage.py JSON format support (Python ecosystem)
- [ ] Stdin diff input support (`--diff-file -`)
- [ ] Performance profiling with `--timing` flag
- [ ] Criterion benchmarks for performance tracking
- [ ] Expanded documentation and examples

**Status:** Parser code exists for JaCoCo and coverage.py. CLI and orchestrator integration pending.

### v0.3.0 — Extended Integration (Planned)

**Focus:** CI/CD ecosystem integration

- [ ] Official GitHub Action (`.github/actions/covguard/`)
- [ ] GitLab CI templates (`templates/gitlab/`)
- [ ] Community feedback integration
- [ ] Performance profiling and optimization

**Status:** Draft Action and templates exist but use incorrect CLI flags and report field paths. Needs alignment with actual CLI interface.

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
| JaCoCo XML | Parser exists | Not yet wired to CLI or orchestrator |
| coverage.py JSON | Parser exists | Not yet wired to CLI or orchestrator |

### Diff Sources

| Source | Status | Notes |
|--------|--------|-------|
| Unified diff patches | Shipped (v0.1.0) | `--diff-file` |
| Git refs | Shipped (v0.1.0) | `--base` / `--head` |
| Stdin | In progress | `--diff-file -` pipe support |

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
| Stdin diff input | In progress | `--diff-file -` pipe support |
| Enhanced error messages | In progress | Remediation hints |
| Performance profiling | In progress | `--timing` flag, criterion benchmarks |
| JaCoCo XML parser | Parser only | Needs CLI + orchestrator wiring |
| coverage.py JSON parser | Parser only | Needs CLI + orchestrator wiring |
| GitHub Action | Draft | Needs CLI flag alignment |
| GitLab CI templates | Draft | Needs CLI flag alignment |

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
| GitHub Actions | Draft | Action exists, needs CLI alignment |
| GitLab CI | Draft | Templates exist, need CLI alignment |
| Bitbucket | Exploring | Community demand |
| Azure DevOps | Exploring | Community demand |

### Language Coverage Tooling
| Language | Coverage Tool | LCOV Support | Native Format |
|----------|--------------|--------------|---------------|
| Rust | cargo-llvm-cov | Shipped | — |
| C/C++ | gcov | Shipped | — |
| Python | coverage.py | Via lcov output | Parser exists (not wired) |
| Java | JaCoCo | Via lcov output | Parser exists (not wired) |
| JavaScript | c8/istanbul | Via lcov output | — |

## Related Documentation

- [Implementation Plan](implementation-plan.md) — Phase details
- [Requirements](requirements.md) — Goals and non-goals
- [Architecture](architecture.md) — System design
- [Integration Guide](integration.md) — CI/CD setup
