# covguard — Implementation Plan

This plan is sequenced to lock contracts early, keep PRs small, and maximize test leverage.
Each phase lands with fixtures + schema + determinism gates.

## Status Legend

- ✅ Complete
- 🚧 In Progress
- ⏳ Planned

---

## Phase 0 — Scaffold + contracts ✅
Deliverables:
- Workspace skeleton with microcrates:
  - types/domain/adapters-diff/adapters-coverage/render/app/cli/xtask
- Canonical artifact writer:
  - always writes `artifacts/covguard/report.json`
- Receipt DTOs aligned to envelope semantics
- Schemas:
  - vendored `receipt.envelope.v1.json`
  - `covguard.report.v1.json` (strict, minimal v0)
- CI smoke tests:
  - schema validation
  - deterministic ordering smoke test

Acceptance:
- `covguard check --diff-file fixtures/diff/simple_added.patch --lcov fixtures/lcov/uncovered.info`
  produces a valid report.json that validates against schema.

## Phase 1 — Diff parsing + normalization ✅
Scope:
- Patch diff parser (unified diff)
- Range merging + deterministic ordering
- Rename handling (new path identity)
- Binary diff detection (count + note; skip file)
- Canonical path normalization (repo-relative, forward slashes)

Tests:
- Unit tests for:
  - new file
  - modified file
  - rename
  - multiple hunks
  - deletions only
- proptest:
  - merged ranges are sorted, non-overlapping, idempotent
- cargo-fuzz target:
  - diff parser must never panic

Acceptance:
- Changed ranges match expected output for fixture diffs.
- Windows CRLF diffs parse without flakiness.

## Phase 2 — LCOV parsing + normalization ✅
Scope:
- LCOV parser with records per SF
- hits map by (path,line)
- configurable path stripping (absolute SF)
- merging multiple LCOV inputs (max hits)

Tests:
- Unit tests for:
  - absolute and relative SF
  - DA lines and record boundaries
  - malformed LCOV rejects cleanly
- cargo-fuzz target:
  - LCOV parser must never panic

Acceptance:
- Coverage map matches fixtures.
- Invalid LCOV produces tool/runtime error receipt (exit 1 + tool.runtime_error finding).

## Phase 3 — Domain evaluation ✅
Scope:
- Evaluate in-scope changed lines against coverage hits
- Policies:
  - scope added|touched
  - thresholds + missing policies
  - include/exclude globs
  - caps for surfaced findings
- Summary metrics and verdict mapping

Tests:
- Unit tests for verdict table and edge cases:
  - no changed lines => pass or skip (choose and document; recommend pass with reason "no_changed_lines")
  - uncovered lines => warn or fail based on policy
  - missing coverage => warn/skip/fail based on policy
- cargo-mutants:
  - domain logic (threshold comparisons, missing handling, summary math)
- proptest:
  - diff_coverage_pct stays within 0..=100
  - counts add up consistently

Acceptance:
- Stable findings and summary metrics for fixtures.
- Deterministic ordering enforced.

## Phase 4 — Rendering (markdown + annotations) ✅
Scope:
- Markdown renderer:
  - short summary + top N uncovered lines
  - explicit truncation marker
  - repro command line
- GitHub annotations renderer (budgeted)

Tests:
- Golden fixtures:
  - expected comment.md
- Determinism tests:
  - repeated runs produce identical markdown
- BDD scenarios:
  - uncovered lines produce annotations, capped

Acceptance:
- comment.md is PR-friendly and capped.
- annotations are stable and limited.

## Phase 5 — Ignore directives ✅
Scope:
- RepoReader adapter reads head files
- Implement `covguard: ignore` directive (line-level)
- Record ignored counts in report.data

Tests:
- BDD scenario:
  - ignore directive excludes uncovered line from evaluation
- Unit tests:
  - directive detection across whitespace/comment styles
  - missing file/line handled gracefully (no tool crash)

Acceptance:
- ignore directives prevent false positives without disabling the tool.

## Phase 6 — SARIF renderer ✅
Scope:
- SARIF output from report.json (renderer-only)
- Rule metadata: help/url for codes

Tests:
- Golden sarif.json fixture

Acceptance:
- SARIF integrates with GitHub code scanning UI.

## Phase 7 — Config + profiles ✅
Scope:
- covguard.toml parsing
- precedence: CLI > config > defaults
- profiles (oss/team/strict) as effective-config mapping
- missing-input behavior explicit

Tests:
- Config fixtures + golden outputs
- BDD scenario:
  - oss warns but does not fail on common “missing coverage” adoption cases

Acceptance:
- ergonomics match other sensors in the ecosystem
- adoption valve works as intended

## Phase 8 — Ecosystem conformance ✅
Ongoing requirements:
- receipt validates against schemas
- deterministic output tests remain green
- explain registry covers codes used by fixtures

Release gate (v0.1):
- schemas shipped
- golden fixtures stable
- fuzz targets run timeboxed in CI
- mutants run timeboxed in CI
- docs complete (requirements/design/architecture/impl plan + codes)

## Suggested CI matrix (minimal)
- unit tests (linux)
- golden fixtures (linux)
- fuzz smoke (linux, timeboxed)
- mutants (linux, timeboxed)
- Windows path normalization tests (windows)
- schema validation (linux)

## Definition of Done for v0.1
- ratchet-by-default scope (added)
- envelope-compliant receipt with stable codes
- markdown + annotations renderers
- path normalization story is explicit and tested
- missing inputs produce skip/warn, not false confidence
