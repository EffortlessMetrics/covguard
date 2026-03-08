# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-08

### Summary

covguard is a diff-scoped coverage gate for pull requests. It answers the question:
"Did this PR add or change lines that are not covered by tests?"

Unlike global coverage tools, covguard focuses only on the lines that changed,
making it a ratchet-by-default sensor that enforces coverage on new and modified code
without requiring changes to existing uncovered code.

### Key Features

#### Diff Parsing
- Unified diff format support (patch files)
- Git diff output parsing
- Git refs support (`--base` and `--head` SHA references)
- Multiple file handling in single diff
- Binary file detection and graceful handling
- Renamed file tracking

#### LCOV Coverage Parsing
- Full LCOV format support
- Path normalization (repo-relative, forward slashes, no `./` prefix)
- Multiple coverage file merging
- Line coverage tracking with hit counts

#### Domain Evaluation
- Configurable coverage threshold percentage
- Scope selection: `added` (new lines only) or `touched` (all changed lines)
- Failure behavior modes: `never`, `error`, `warn-or-error`
- Policy-based decision making with pure domain logic

#### Output Formats
- **JSON Report**: Schema-compliant `covguard.report.v1` format
- **Markdown**: PR comment rendering with configurable truncation
- **GitHub Annotations**: Budgeted annotation output for workflow integration
- **SARIF 2.1.0**: Static Analysis Results Interchange Format for code scanning

#### Ignore Directives
- `// covguard: ignore` comment support
- Line-level and block-level ignoring
- Directive parsing with range awareness

#### Configuration
- TOML configuration file support (`covguard.toml`)
- Built-in profiles: `oss`, `team`, `strict`, `lenient`, `moderate`
- CLI argument overrides with proper precedence
- Profile-based default policies

#### Quality Guarantees
- Deterministic output ordering (severity > path > line > check_id > code > message)
- Schema-compliant JSON reports with validation
- Byte-stable output for reproducible builds

### Architecture

covguard follows a hexagonal/clean architecture with a pure domain core:

**Domain Core** (pure, no side effects):
- Evaluates changed lines against coverage under policy
- Produces findings + verdict + summary metrics
- Enforces deterministic ordering

**Ports** (interfaces):
- `DiffProvider`, `CoverageProvider`, `RepoReader`, `Clock`, `ArtifactWriter`

**Adapters** (side effects):
- Git/patch diff parsing, LCOV parsing, filesystem I/O, renderers

**Microcrates** (15 total):
- `covguard-types` - Core types and DTOs
- `covguard-ports` - Port trait definitions
- `covguard-domain` - Pure policy evaluation
- `covguard-policy` - Policy configuration types
- `covguard-directives` - Ignore directive parsing
- `covguard-paths` - Path normalization utilities
- `covguard-ranges` - Line range merging
- `covguard-output` - Output type definitions
- `covguard-output-features` - Feature flags for outputs
- `covguard-reporting` - Report construction
- `covguard-config` - Configuration loading
- `covguard-render` - Markdown/annotations/SARIF rendering
- `covguard-orchestrator` - Application orchestration
- `covguard-app` - Compatibility facade
- `covguard-cli` - Command-line interface
- `covguard-core` - Backward-compatible facade
- `covguard-adapters-diff` - Diff parsing adapter
- `covguard-adapters-coverage` - LCOV parsing adapter
- `covguard-adapters-repo` - Repository reader adapter
- `covguard-adapters-artifacts` - Artifact writing adapter

### Testing

Multi-layered testing approach for robustness:

- **Unit tests**: Parsers, normalization, policy edge cases
- **Property tests** (proptest): Range merging invariants, percent math
- **BDD tests** (Cucumber): End-to-end scenarios in `bdd/features/`
- **Fuzzing** (cargo-fuzz): Diff + LCOV parsers must never panic
- **Mutation tests** (cargo-mutants): Domain verdict logic
- **Golden fixtures**: Byte-stable `report.json` and `comment.md` snapshots
- **Schema validation**: JSON output validates against `contracts/schemas/`

### CLI Usage

```bash
# Basic check with patch file
covguard check \
  --diff-file fixtures/diff/simple_added.patch \
  --lcov fixtures/lcov/uncovered.info \
  --out artifacts/covguard/report.json

# With git refs and markdown output
covguard check \
  --base "$BASE_SHA" --head "$HEAD_SHA" \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

### Exit Codes

- `0` — Pass (or warn when not fail-configured)
- `2` — Policy fail (blocking findings)
- `1` — Tool/runtime error (I/O, parse failure)

[Unreleased]: https://github.com/effortlessmetrics/cov-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/effortlessmetrics/cov-guard/releases/tag/v0.1.0
