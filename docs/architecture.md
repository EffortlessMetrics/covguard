# covguard — Architecture Plan

## System context
covguard is a sensor in a receipts-first PR cockpit ecosystem.

It consumes:
- a diff (repo truth)
- a coverage artifact (build truth)

…and emits:
- a canonical receipt (`artifacts/covguard/report.json`) for cockpit ingestion.

covguard is a build-truth consumer. It does not create build truth; it interprets it.

## Architectural principles
- Boring contracts: receipts and codes are API.
- Sharp boundaries: domain core is pure; side effects live in adapters.
- Determinism first: stable ordering and stable truncation are contractual.
- Small surface area: few knobs; low-noise defaults.
- Escape hatches: ignore directives and allowlists prevent tool disablement.

## Hexagonal structure (ports/adapters)

### Domain core (inside)
Responsibilities:
- Evaluate changed lines against coverage hits under explicit policy
- Produce findings + verdict + summary metrics
- Enforce deterministic ordering

No dependencies on:
- filesystem
- git
- environment
- clocks (use injected clock)

### Ports (interfaces)
- DiffProvider
  - `changed_ranges(base, head) -> ChangedRanges`
  - or `changed_ranges_from_patch(text) -> ChangedRanges`

- CoverageProvider
  - `load_lcov(paths) -> CoverageMap`

- RepoReader
  - `read_line(path, line_no) -> Option<String>` (ignore directives)
  - `read_snippet(path, line_no, context) -> Option<String>` (optional)

- Clock
  - `now() -> DateTime`

- ArtifactWriter
  - `write_report(report)`
  - `write_comment(text)` (optional)
  - `write_sarif(json)` (optional)

### Adapters (outside)
- GitDiffProvider: spawns `git diff --unified=0`
- PatchDiffProvider: parses patch files / stdin
- LcovCoverageProvider: parses LCOV
- FsRepoReader: reads working tree files
- FsArtifactWriter: writes canonical artifacts
- Renderers:
  - MarkdownRenderer
  - GithubAnnotationsRenderer (stdout commands or file)
  - SarifRenderer

## Canonical artifacts
covguard MUST write:
- `artifacts/covguard/report.json`

covguard SHOULD write when requested:
- `artifacts/covguard/comment.md`

covguard MAY write:
- `artifacts/covguard/sarif.json`
- `artifacts/covguard/raw/*` (debug copies of diff/lcov)

## Protocol compliance
- schema: `covguard.report.v1`
- strict top-level with one extension point: `data`
- location best-effort:
  - path strongly preferred
  - line/col optional
- tool/runtime error convention:
  - exit 1
  - receipt emitted if possible with:
    - verdict.status = fail
    - verdict.reasons includes "tool_error"
    - finding code = "tool.runtime_error"

## Determinism rules
Findings MUST be ordered deterministically:
1) severity (error > warn > info)
2) path (lexical)
3) line (ascending; missing last)
4) check_id
5) code
6) message

Renders MUST use the same ordering, then apply budgets.

Truncation MUST be explicit:
- report-level `data.truncation`
- markdown includes “... truncated” marker

## Crate Structure (Implemented)

```
covguard-cli (entry point)
    │
    ▼
covguard-app (orchestration)
    ├── covguard-ports
    ├── covguard-adapters-diff
    ├── covguard-adapters-coverage
    ├── covguard-adapters-repo
    ├── covguard-domain ──► covguard-types
    ├── covguard-render ──► covguard-types
    └── covguard-config
            │
            ▼
        covguard-types
```

### Crate Descriptions

| Crate | Purpose |
|-------|---------|
| **covguard-types** | DTOs for reports, findings, verdicts, severity. Schema IDs and error code constants. |
| **covguard-ports** | Shared hexagonal port traits (Clock, RepoReader) used by orchestration and adapters. |
| **covguard-domain** | Pure policy evaluation. Takes changed ranges + coverage map + policy, produces findings + verdict + metrics. No I/O. |
| **covguard-config** | TOML configuration parsing, profile defaults (Oss/Moderate/Team/Strict), precedence resolution (CLI > file > profile > defaults). |
| **covguard-adapters-diff** | Unified diff parsing, path normalization, range merging. Handles renames, deletions, CRLF. |
| **covguard-adapters-coverage** | LCOV parsing, path normalization, coverage map merging (max hits). |
| **covguard-adapters-repo** | Filesystem-backed `RepoReader` adapter for ignore directive line inspection. |
| **covguard-render** | Renderers: Markdown (PR comments), GitHub annotations, SARIF 2.1.0. |
| **covguard-app** | Orchestration layer. Wires adapters to domain, provides `check()` entry point, handles ignore directive detection. |
| **covguard-cli** | Clap-based CLI. Argument parsing, config discovery, file I/O, exit code mapping. |
| **xtask** | Build automation: schema generation, fixture management. |

### Dependency Rules

- **covguard-types**: No internal dependencies (leaf crate)
- **covguard-ports**: Depends only on common primitives (chrono)
- **covguard-domain**: Depends only on covguard-types
- **covguard-config**: Depends on covguard-types (for Scope enum)
- **covguard-adapters-***: Standalone parsers, no internal dependencies
- **covguard-adapters-repo**: Depends on covguard-ports
- **covguard-render**: Depends on covguard-types
- **covguard-app**: Depends on all crates except CLI
- **covguard-cli**: Depends on app + config + types

### Port Traits (in covguard-ports)

- **Clock**: `fn now() -> DateTime` — Injected for deterministic tests
- **RepoReader**: `fn read_line(path, line_no) -> Option<String>` — For ignore directive detection

## Schema management
Ship schemas in-repo:
- `contracts/schemas/receipt.envelope.v1.json` (vendored contract)
- `contracts/schemas/covguard.report.v1.json`

CI validates:
- fixtures output validates against covguard schema
- report.json is byte-stable for fixture inputs

## Conformance harness
covguard must include (and CI must enforce):
- schema validation for report.json fixtures
- golden output tests (report.json, comment.md)
- fuzz targets for parsers (timeboxed)
- mutation tests for domain core (timeboxed)
- explain coverage for codes used by fixtures

## Observability
Report `data` should record:
- inputs used (lcov paths, diff source, base/head)
- path normalization actions applied
- summary counts and computed percent
- reasons for skip/warn (missing inputs, shallow clone)
- ignored/excluded counts

The goal is reproducibility: a reviewer should be able to re-run the same check locally.
