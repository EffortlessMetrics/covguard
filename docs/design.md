# covguard — Design

## Overview
covguard is a build-truth consumer: it maps line coverage (LCOV) onto PR-changed lines (diff) and emits a receipt that a cockpit can ingest.

Design constraints (non-negotiable):
- Inputs are explicit (coverage + diff).
- Policy is explicit (scope, thresholds, missing behavior).
- Outputs are deterministic (byte-stable).
- Rendered surfaces are budgeted (no “wall of red”).
- Tool-specific details live under `data`.

## Domain vocabulary
- **Changed line**: a line number in the *head* (new-side) file that is considered in-scope.
- **Scope**:
  - `added`: only `+` lines in the diff (ratchet-by-default)
  - `touched`: all new-side ranges in hunks (stricter)
- **Coverage hit**: LCOV `DA:<line>,<hits>` where hits > 0 indicates covered.
- **Missing coverage**:
  - file missing from LCOV record, or
  - line missing from LCOV line map (policy-controlled)

## Clean / hexagonal architecture
covguard follows a hexagonal structure:
- **Domain core**: policy evaluation + aggregation (pure functions)
- **Ports**: interfaces for “get diff mapping”, “get coverage map”, “read repo line text”, “write artifacts”
- **Adapters**: git diff invocation, patch parsing, LCOV parsing, filesystem IO, renderers, CLI

### Primary use case: CheckCoverageOnDiff
1) Acquire diff mapping (changed line ranges by file)
2) Acquire coverage mapping (hits by file/line)
3) Normalize paths to canonical identity
4) Enumerate in-scope changed lines (by scope + filters + ignores)
5) Classify each in-scope line: covered / uncovered / missing
6) Aggregate metrics and generate findings
7) Emit receipt + optional renders

## Canonical path identity (protocol-level discipline)
All internal paths are normalized to:
- repo-relative
- forward slashes (`/`)
- no leading `./`

Normalization inputs:
- diff paths from `+++ b/<path>` and rename metadata
- LCOV paths from `SF:` lines (absolute or relative)
- optional `--path-strip` prefixes (CI absolute roots)
- optional repo root prefix stripping (if `SF` is absolute and under root)

Failure mode:
- If coverage paths cannot match diff paths, covguard MUST NOT silently pass.
- It emits an explicit finding (usually warn) explaining how to fix path normalization.

## Diff parsing model
### Preferred diff producer
When base/head is provided:
- `git diff --unified=0 --no-color <base>..<head>`

Why `--unified=0`:
- It shrinks the diff to only changed lines, making the mapping unambiguous and fast.

### Diff data representation
`BTreeMap<Path, Vec<RangeInclusive<u32>>>`

- per file: merged and sorted ranges in new-side line numbers
- merged ranges minimize storage and speed up intersection checks
- renames: tracked as “new path” identity

Deletions:
- hunks with new length = 0 contribute no new-side lines.

Binary diffs:
- treated as “not analyzable”; recorded under `data` with counts, but not a failure by default.

### Scope semantics
- `added`: include only explicit `+` lines (new content)
- `touched`: include entire new-side ranges for hunks (captures replacements)

Note: both scopes remain diff-scoped and avoid legacy spam.

## Coverage model (LCOV)
Parse LCOV record blocks:
- `SF:<path>`
- `DA:<line>,<hits>`
- `end_of_record`

Store:
- `BTreeMap<Path, BTreeMap<u32, u32>>` (line -> hits)

Missing lines:
- In LCOV, a line may be absent because the tool didn’t instrument it, it’s non-executable, or due to format differences.
- covguard treats “line absent” as policy-controlled:
  - default: count as uncovered but surface as warn by default in `oss`

Multiple LCOV inputs:
- Support `--lcov` repeated.
- Merge policy:
  - union by file and line
  - hits summed (or max) — default to max to match typical LCOV aggregation semantics.

## Policy evaluation (domain core)
Inputs:
- scope: added|touched
- threshold: min_diff_coverage_pct
- uncovered cap: max_uncovered_lines
- missing policies: missing_file, missing_line
- include/exclude globs
- ignore directives enabled/disabled
- fail_on: error|warn|never (standalone behavior)

Outputs:
- findings[] (stable ordering)
- verdict (pass|warn|fail|skip)
- summary metrics in `data`

### Metrics computed
For the in-scope changed line set:
- changed_lines_total
- covered_lines
- uncovered_lines
- missing_lines
- diff_coverage_pct = covered / (covered + uncovered + missing_as_counted) * 100

Note: the denominator depends on missing-line policy. The report MUST record the policy used.

### Verdict algorithm (normative)
1) If inputs missing:
   - status=skip unless configured otherwise
   - reasons include "missing_input"
2) Else:
   - status=fail if error findings exist (or warn-as-fail configured)
   - status=warn if warn findings exist and no fails
   - status=pass otherwise

## Output budgeting (a feature, not polish)
covguard is allowed to be verbose in artifacts, but the PR surface must be capped.

Budgets:
- receipt findings can be uncapped or capped by config (default: uncapped)
- comment markdown is capped (default: show top N uncovered lines)
- annotations are capped (default: 25)
- SARIF (if emitted) is capped or grouped

Truncation is explicit:
- `data.truncation = { findings_truncated, shown, total }`

## Ignore directives
Goal: give teams an escape hatch without turning the tool off.

Supported directives (v0.1):
- `covguard: ignore` (line-level)

Implementation:
- When enumerating changed lines, read the head revision file and check if the line contains the directive.
- If yes: exclude from evaluation and increment ignored count.
- Do not require line/col for correctness; it’s best-effort.

## Receipt design: covguard.report.v1
Envelope fields:
- `schema = "covguard.report.v1"`
- `tool = { name="covguard", version, commit? }`
- `run = { started_at, ended_at?, duration_ms?, git? }`
- `verdict = { status, counts, reasons[] }`
- `findings[]`

covguard-specific data lives under `data`:
- scope, thresholds
- summary counts
- inputs + provenance
- truncation and normalization notes

Findings:
- uncovered line:
  - severity error or warn based on policy
  - location.path + location.line
  - code: covguard.diff.uncovered_line
  - check_id: diff.uncovered_line
- missing coverage file:
  - location.path (file)
  - code: covguard.diff.missing_coverage_for_file
- below threshold:
  - code: covguard.diff.coverage_below_threshold
  - message includes actual pct and threshold

## Rendering
### Markdown comment contract (covguard-owned)
Keep it short and linkable:
- diff coverage summary line
- counts bullet list
- table of top N uncovered lines
- repro command line

### GitHub annotations
Emit top N uncovered lines as workflow commands:
- `::warning file=...,line=...::...` or `::error ...` based on severity mapping

### SARIF (renderer-only)
Emit SARIF results for uncovered lines and policy failures:
- ruleId = finding.code
- level derived from severity
- locations include file and line

## Failure modes (explicit)
- Missing LCOV: skip or warn per policy; not a runtime error.
- Invalid LCOV: tool error (exit 1) + tool.runtime_error finding.
- Missing base commit due to shallow clone: warn/skip with remediation (unless configured to fail).
- Path mismatch between diff and LCOV: warn and show applied strips; do not silently pass.

## Crate Layout (Implemented)

| Crate | Responsibility |
|-------|----------------|
| **covguard-types** | DTOs (Report, Finding, Verdict), schema IDs, error codes, serde |
| **covguard-domain** | Policy evaluation, metrics aggregation, deterministic ordering, ignore directive detection |
| **covguard-config** | TOML parsing, profiles (Oss/Moderate/Team/Strict), precedence resolution |
| **covguard-adapters-diff** | Unified diff parsing, path normalization, range merging |
| **covguard-adapters-coverage** | LCOV parsing, coverage map merging |
| **covguard-render** | Markdown, GitHub annotations, SARIF renderers |
| **covguard-app** | Orchestration, Clock/RepoReader traits, `check()` entry point |
| **covguard-cli** | Clap CLI, file I/O, exit code mapping |
| **xtask** | Schema generation, fixture management |

See `docs/architecture.md` for the full dependency graph and crate details.

## Test strategy
- Unit tests: parsers, normalization, policy edge cases
- Property tests (proptest): range merging invariants, normalization invariants, percent math invariants
- BDD (cucumber): end-to-end scenarios on fixtures
- Fuzzing (cargo-fuzz): diff parser + LCOV parser panic-free guarantee
- Mutation tests (cargo-mutants): domain verdict logic, missing coverage behavior
- Golden fixtures (snapshot): report.json and comment.md byte-stable outputs
