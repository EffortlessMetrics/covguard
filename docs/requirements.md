# covguard — Requirements

## Purpose
covguard answers one reviewer question with minimal noise:

> “Did this PR add or change lines that are not covered by tests?”

It consumes coverage (LCOV) and a diff (base↔head or patch) and emits a receipt suitable for cockpit ingestion.

## Truth layer
Build truth (consumer), diff-scoped presentation.

- covguard DOES NOT run tests or generate coverage.
- covguard DOES map coverage to diff lines and applies policy.

## Goals
- Diff-scoped, ratchet-by-default coverage gating (no legacy debt spam).
- Deterministic, schema’d receipts suitable for ingestion and long-term comparison.
- Low-friction CI integration: canonical artifacts, stable exit codes, budgeted output.
- Cross-platform correctness (Linux/macOS/Windows path handling).
- Clear remediation and escape hatches (ignore directives + allowlists).

## Non-goals
- Global coverage enforcement (“keep repo at 90%”) — out of scope.
- Coverage generation (cargo llvm-cov orchestration) — out of scope.
- “Adequacy” heuristics (complexity, mutation score, etc.) — out of scope for v0.
- Becoming language-specific — LCOV makes covguard naturally cross-language.
- Acting as the cockpit director — covguard is a sensor only.

## Inputs
### Required (for meaningful evaluation)
- Coverage file(s): LCOV (`.info`) as produced by upstream tooling.
- Diff source:
  - `--base` + `--head` (git-based) OR
  - `--diff-file` OR
  - stdin patch stream.

### Optional
- `--root` repo root (defaults to git toplevel when available).
- `--path-strip` prefixes (for absolute SF paths in LCOV).
- `covguard.toml` for policy, filters, budgets, ignore rules.

## Outputs (canonical artifacts)
- MUST: `artifacts/covguard/report.json` (`covguard.report.v1`, envelope-compliant)
- SHOULD: `artifacts/covguard/comment.md` (budgeted PR section)
- MAY:  `artifacts/covguard/sarif.json` (renderer output, optional but market-correct)
- MAY:  `artifacts/covguard/raw/{diff.patch,lcov.info}` for debugging/provenance

## Receipt contract (ecosystem)
covguard emits a strict-top-level envelope with one extension point:
- tool-specific payload lives under `data` (report-level) or `finding.data` (finding-level).

Required envelope fields:
- `schema`, `tool`, `run.started_at`, `verdict`, `findings[]` (empty allowed)

Verdict semantics:
- status ∈ {pass, warn, fail, skip}

Tool/runtime failures:
- exit code 1
- receipt (if possible): status=fail, reasons include "tool_error"
- one canonical finding: code="tool.runtime_error"

## Findings and codes (stable)
covguard keeps codes few and durable.

MVP codes:
- `covguard.diff.coverage_below_threshold`
- `covguard.diff.uncovered_line`
- `covguard.diff.missing_coverage_for_file`
- `covguard.input.invalid_lcov`
- `covguard.input.invalid_diff`

Prefer `check_id` + `code` split:
- check_id: producer group (e.g., `diff.coverage`, `diff.uncovered_line`)
- code: classification (e.g., `below_threshold`, `uncovered_line`)

## Policy posture (ratchet-by-default)
Default scope: added lines only (new-side `+` lines).

Optional stricter mode:
- touched (includes replacements/modifications as new-side ranges)

Missing inputs:
- missing LCOV/diff should produce SKIP with clear reasons (unless configured otherwise).

## Policy knobs (keep few, high leverage)
- scope: `added | touched`
- min diff coverage % (`min_diff_coverage_pct`, default 80)
- uncovered cap (`max_uncovered_lines`, default 25) (budget and optional gate)
- missing coverage: `skip | warn | fail`
- include/exclude globs
- ignore directives enabled/disabled
- fail_on: `error | warn | never` (standalone behavior; cockpit can override via composition policy)

## CLI (stable surface)
- `covguard check`
- `covguard md --report <report.json>`
- `covguard annotations --report <report.json>` (GitHub workflow commands)
- `covguard sarif --report <report.json>` (optional renderer)
- `covguard explain <check_id|code>`

## Exit codes
- 0: pass (or warn when warn is not configured to fail)
- 2: policy fail (blocking findings or warn-as-fail)
- 1: tool/runtime error

## Determinism requirements
Given identical inputs, covguard MUST produce byte-stable outputs:
- stable ordering for findings
- stable truncation behavior (explicit “truncated” markers + counts)

Sorting key (normative):
1) severity (error > warn > info)
2) path (lexical)
3) line (ascending; missing last)
4) check_id
5) code
6) message

## Performance requirements
- O(changed_lines + lcov_lines) with merged range matching.
- Target: < 1s for typical PR diffs and LCOV sizes.
- Memory bounded: avoid per-line sets when merged ranges suffice.

## Security / safety requirements
- No network calls.
- No arbitrary command execution beyond optional `git diff` when base/head provided.
- Treat all inputs as untrusted; parsers must be panic-free (fuzzed).
