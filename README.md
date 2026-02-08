# covguard

covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).

covguard consumes:
- a **diff** (base↔head or patch file)
- an **LCOV** coverage report (`.info`)

…and emits:
- a **schema’d receipt** (`artifacts/covguard/report.json`) suitable for cockpit ingestion
- optional **PR-facing markdown** (`comment.md`)
- optional **GitHub annotations** and **SARIF** as renderers

It is intentionally **not** a coverage generator and intentionally **not** a global coverage policy tool.

---

## What it answers

> Did this PR add or change lines that are not covered by tests?

Default posture is **ratchet-by-default**: only **added** lines are evaluated unless configured otherwise.

---

## Quickstart

### 1) With a patch file

```bash
covguard check \
  --diff-file artifacts/raw/patch.diff \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md \
  --annotations github
```

### 2) With base/head refs (git diff)

```bash
covguard check \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

### 3) With stdin patch

```bash
git diff --unified=0 "$BASE_SHA" "$HEAD_SHA" | covguard check \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

> CI note: shallow clones frequently break `--base/--head` if the base commit is missing.
> Prefer `fetch-depth: 0` or explicitly fetch the base SHA.

---

## Artifacts

covguard writes (canonical layout):

```
artifacts/covguard/
  report.json        # canonical receipt (envelope-compliant)
  comment.md         # optional
  sarif.json         # optional
  raw/               # optional debug copies (diff/lcov) if enabled via --raw
```

---

## Exit codes

- `0` pass (or warn, when warn is not configured to fail)
- `2` policy fail (blocking findings or warn-as-fail)
- `1` tool/runtime error (I/O, parse failure, internal error)

---

## Configuration

See `config/covguard.toml` for an example.

Key knobs (kept intentionally few):
- `scope = "added" | "touched"`
- `min_diff_coverage_pct`
- `missing_coverage = "skip"|"warn"|"fail"`
- include/exclude path filters
- ignore directives (`covguard: ignore`)

---

## Development quality bar

covguard is designed to be “boring infrastructure.” The repo expects:
- golden fixtures (byte-stable `report.json` + `comment.md`)
- fuzzing on parsers (diff + LCOV)
- property tests on range merging and invariants
- mutation tests on domain verdict logic
- BDD scenarios for end-to-end behavior

Docs:
- `docs/requirements.md`
- `docs/design.md`
- `docs/architecture.md`
- `docs/implementation-plan.md`

Schemas:
- `contracts/schemas/receipt.envelope.v1.json`
- `contracts/schemas/covguard.report.v1.json`
