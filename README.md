# covguard

covguard is a diff-scoped coverage gate for pull requests.

It answers one question:

> Did this PR add or change lines that are not covered by tests?

## Inputs

- Unified diff (patch file, stdin, or git refs)
- LCOV coverage report (`.info`)

## Outputs

- Canonical receipt: `artifacts/covguard/report.json`
- Optional markdown PR comment: `artifacts/covguard/comment.md`
- Optional annotations and SARIF output

## Quickstart

```bash
covguard check \
  --diff-file fixtures/diff/simple_added.patch \
  --lcov fixtures/lcov/uncovered.info \
  --out artifacts/covguard/report.json
```

```bash
covguard check \
  --base "$BASE_SHA" --head "$HEAD_SHA" \
  --lcov artifacts/coverage/lcov.info \
  --out artifacts/covguard/report.json \
  --md artifacts/covguard/comment.md
```

## Exit Codes

- `0`: pass (or warn when warn is not configured to fail)
- `2`: policy failure
- `1`: tool/runtime error

## Crates

- `covguard` (`crates/covguard-cli`): CLI binary
- `covguard-app`: orchestration layer
- `covguard-domain`: pure policy evaluation
- `covguard-types`: report DTOs, codes, constants
- `covguard-ports`: port traits and boundary types
- `covguard-adapters-diff`: unified diff parser + git diff loader
- `covguard-adapters-coverage`: LCOV parser/merger
- `covguard-adapters-repo`: filesystem repo reader
- `covguard-render`: markdown, annotations, SARIF renderers
- `covguard-config`: config/profile resolution
- `covguard-core`: compatibility facade re-exporting `covguard-app`

## Docs

- `docs/requirements.md`
- `docs/design.md`
- `docs/architecture.md`
- `docs/implementation-plan.md`
- `docs/codes.md`
