# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

covguard is a diff-scoped coverage gate for pull requests. It answers: "Did this PR add or change lines that are not covered by tests?"

**Inputs**: Diff (patch file or base↔head refs) + LCOV coverage report
**Outputs**: Schema-compliant receipt (`artifacts/covguard/report.json`), optional markdown comment, optional GitHub annotations/SARIF

**Not**: A coverage generator or global coverage policy tool. It's a ratchet-by-default sensor that only evaluates added lines unless configured otherwise.

## Build Commands

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

## Testing Strategy

Multi-layered testing approach:
- **Unit tests**: Parsers, normalization, policy edge cases
- **Property tests** (proptest): Range merging invariants, percent math
- **BDD tests** (Cucumber): End-to-end scenarios in `bdd/features/`
- **Fuzzing** (cargo-fuzz): Diff + LCOV parsers must never panic
- **Mutation tests** (cargo-mutants): Domain verdict logic
- **Golden fixtures**: Byte-stable `report.json` and `comment.md` snapshots

Test fixtures are in `fixtures/` (diff patches, LCOV files, expected outputs).

## Architecture

Hexagonal/clean architecture with pure domain core:

**Domain Core** (pure, no side effects):
- Evaluates changed lines against coverage under policy
- Produces findings + verdict + summary metrics
- Enforces deterministic ordering

**Ports** (interfaces):
- `DiffProvider`, `CoverageProvider`, `RepoReader`, `Clock`, `ArtifactWriter`

**Adapters** (side effects):
- Git/patch diff parsing, LCOV parsing, filesystem I/O, renderers

**Planned Microcrates**:
- `covguard-types` (DTOs, schema ids, codes)
- `covguard-domain` (policy evaluation)
- `covguard-adapters-diff` / `covguard-adapters-coverage`
- `covguard-render` (markdown/annotations/SARIF)
- `covguard-app` (orchestration)
- `covguard-cli` (clap + IO + exit mapping)
- `xtask` (schema generation, fixtures)

## Key Invariants

- **Deterministic output**: Findings are normatively sorted (severity > path > line > check_id > code > message)
- **Path normalization**: All paths are repo-relative, forward slashes, no `./` prefix
- **Schema compliance**: Report must validate against `contracts/schemas/covguard.report.v1.json`

## Exit Codes

- `0` — pass (or warn when not fail-configured)
- `2` — policy fail (blocking findings)
- `1` — tool/runtime error (I/O, parse failure)

## Error Codes

See `docs/codes.md` for full reference:
- `covguard.diff.uncovered_line` — Changed line has no test coverage
- `covguard.diff.coverage_below_threshold` — Diff coverage % below threshold
- `covguard.diff.missing_coverage_for_file` — File has changes but no coverage data
- `covguard.input.invalid_lcov` / `invalid_diff` — Parse failures
- `tool.runtime_error` — Internal errors

## Documentation

- `docs/requirements.md` — Goals, non-goals, inputs/outputs
- `docs/design.md` — Domain vocabulary, data models, policy evaluation
- `docs/architecture.md` — Ports/adapters, schema management, conformance
- `docs/implementation-plan.md` — Phased deliverables with acceptance criteria
