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

### v0.2.0 - Enhanced Ergonomics

**Focus:** Developer experience and feedback quality

- Improved error messages with remediation hints
- Additional coverage format support (investigation)
- Performance optimizations for large repos
- Expanded documentation and examples
- Example repository with multiple CI configurations

### v0.3.0 - Extended Integration

**Focus:** CI/CD ecosystem integration

- Official GitHub Action
- GitLab CI templates
- Additional output formats as needed
- Community feedback integration
- Performance profiling and optimization

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
| Jacoco | 🔍 Investigating | Java ecosystem |
| coverage.py | 🔍 Investigating | Python ecosystem |

### Diff Sources

| Source | Status | Notes |
|--------|--------|-------|
| Unified diff patches | ✅ v0.1.0 | `--diff-file` |
| Git refs | ✅ v0.1.0 | `--base` / `--head` |
| Stdin | 🔍 Planned | Pipe support |

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

## Related Documentation

- [Implementation Plan](implementation-plan.md) - Phase details
- [Requirements](requirements.md) - Goals and non-goals
- [Architecture](architecture.md) - System design
- [Integration Guide](integration.md) - CI/CD setup
