# covguard overview

**covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).**

covguard's posture is "ratchet forward": it focuses on new change surface and avoids legacy-debt spam.

---

## Where covguard fits

### Truth layer
- Build truth consumer: covguard interprets coverage artifacts. It does not generate coverage.
- Diff-scoped mapping: covguard maps coverage hits onto the PR diff's changed line ranges.

### CI lane
covguard typically runs in a build lane (tests + coverage generation), not the ultra-fast "repo truth" lane, because producing coverage is the expensive part.

### Complements
- diffguard: "did the PR introduce forbidden patterns?"
- lintdiff: "did new diagnostics land on changed lines?"
- builddiag / depguard: "is the repo contract coherent / manifests hygienic?"

---

## Inputs

### Diff sources
covguard can consume a unified diff via:
- --diff-file <path> (a patch file)
- --base <ref> --head <ref> (runs git diff in repo root)
- stdin (pipe a patch into covguard check; see examples)

Binary diff payloads are ignored for coverage evaluation. When detected, binary paths may be recorded in report.data.debug.

### Coverage sources
- One or more LCOV files via repeatable --lcov <path>
- LCOV inputs are merged deterministically (per line: max hits wins)
- Path normalization via --path-strip prefixes to reconcile absolute SF: paths

### Repo context (optional)
- --root <path> sets the repo root.
- Used for git diff (base/head mode).
- Used for reading source files to honor ignore directives.

If omitted, covguard resolves root via git rev-parse --show-toplevel and falls back to the current working directory.

---

## Outputs

### Canonical artifacts
covguard's stable contract is:

```
artifacts/covguard/report.json    # canonical receipt
artifacts/covguard/comment.md     # optional markdown (if requested)
artifacts/covguard/sarif.json     # optional SARIF (if requested)
```

### Additional optional outputs
- GitHub annotations are printed to stdout (workflow command format), capped (default 25).
- Markdown output is capped (default 10 uncovered lines shown).
- SARIF output is capped (default 1000 results).
- --raw writes raw inputs for debugging/provenance:

```
artifacts/covguard/raw/diff.patch
artifacts/covguard/raw/lcov.info  # concatenated
```

---

## Receipt contract (what cockpit ingests)

### Schema + identity
- schema: covguard.report.v1
- tool.name: covguard
- verdict.status: pass | warn | fail | skip (only)
- stable finding codes (namespaced under covguard. plus tool.runtime_error)

### Key semantics
- Uncovered changed lines always produce covguard.diff.uncovered_line findings.
- Threshold is a separate signal (covguard.diff.coverage_below_threshold); it does not make uncovered lines OK.
- missing_coverage covers missing line records within a covered file.
- missing_file covers files with no coverage data at all.

missing_coverage affects diff coverage percentage and metrics. missing_file can emit findings based on skip | warn | fail.

### Exit codes
- 0: pass or warn (unless configured warn-as-fail at the sensor level)
- 2: policy fail
- 1: tool/runtime error (invalid inputs, IO failures, etc.)

### Explainability
covguard explain <code> prints:
- meaning
- remediation
- docs link (anchors in docs/codes.md)

SARIF rule metadata is generated from the same registry.

---

## Policy knobs (what users actually tune)

The smallest set that teams reliably use:
- Scope: added (ratchet) vs touched (stricter)
- Threshold: --threshold / config min_diff_coverage_pct
- Max uncovered buffer: max_uncovered_lines (tolerance window; uncovered findings are info-level within the buffer)
- Missing coverage behaviors (missing_coverage, missing_file): skip | warn | fail
- Include/exclude globs (avoid generated/vendor paths)
- Ignore directives: covguard: ignore (disable with --no-ignore)
- Path normalization: --path-strip (reconcile absolute LCOV SF paths)

Profiles provide sane defaults (oss/moderate/team/strict) and can be overridden by config or CLI.

---

## Cockpit integration

covguard is a sensor. A director (e.g., cockpitctl ingest) should treat report.json as the source of truth and:
- show a short "Tests" summary (coverage %, uncovered count, missing count)
- cap surfaced uncovered lines
- link to comment.md, sarif.json, and report.json

Blocking vs informational behavior belongs in cockpit policy, not in covguard.

---

## Quickstart

### Patch file

```bash
covguard check \
  --diff-file fixtures/diff/simple_added.patch \
  --lcov fixtures/lcov/covered.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md \
  --sarif artifacts/covguard/sarif.json
```

### Git refs (requires base commit available)

```bash
covguard check \
  --base "$BASE_SHA" --head "$HEAD_SHA" \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json
```

### Stdin patch

```bash
git diff --unified=0 "$BASE_SHA" "$HEAD_SHA" | covguard check \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

### Multi-LCOV + path strip

```bash
covguard check \
  --diff-file patch.diff \
  --lcov unit.info --lcov integration.info \
  --path-strip /home/runner/work/repo/repo/ \
  --out artifacts/covguard/report.json
```

### Debug capture

```bash
covguard check \
  --diff-file patch.diff \
  --lcov coverage.info \
  --out artifacts/covguard/report.json \
  --raw
```

---

## Non-goals (by design)

covguard does not:
- run coverage tooling (cargo llvm-cov, etc.)
- pick tests to run
- enforce repo-wide coverage targets
- mutate the repo

Its value is mapping coverage to diff and emitting a stable, ingestible receipt.
