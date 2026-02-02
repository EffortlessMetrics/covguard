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

## Microcrate plan (workspace)
Recommended layout:

- `covguard-types`
  - DTOs for receipts, findings, policy, summary
  - schema id constants and code constants

- `covguard-domain`
  - policy evaluation
  - metrics aggregation
  - deterministic ordering utilities

- `covguard-ports` (optional)
  - port traits; can live in domain if you prefer fewer crates

- `covguard-adapters-diff`
  - diff acquisition (git) and parsing
  - rename handling
  - canonical path normalization

- `covguard-adapters-coverage`
  - LCOV parsing
  - canonical path normalization

- `covguard-render`
  - renderers from report: markdown, annotations, sarif

- `covguard-app`
  - use-cases that wire ports together
  - inject Clock and budgets

- `covguard-cli`
  - clap + filesystem IO
  - exit code mapping
  - artifact layout

- `xtask`
  - schema generation
  - fixture management
  - release helpers

Dependency rules:
- domain depends only on types (and maybe ports)
- adapters depend on domain/types
- CLI depends on app + adapters + render

## Schema management
Ship schemas in-repo:
- `schemas/receipt.envelope.v1.json` (vendored contract)
- `schemas/covguard.report.v1.json`

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
