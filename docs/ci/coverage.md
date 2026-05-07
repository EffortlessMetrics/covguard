# Coverage

Codecov coverage is Rust execution-surface evidence for the `covguard` repository.

It answers:

> Did tests execute this Rust surface?

It does **not** answer:

- whether `covguard` correctly enforces diff coverage
- whether LCOV parsing is correct
- whether diff parsing is correct
- whether `covguard: ignore` directives are correct
- whether threshold policy is correct
- whether Markdown, SARIF, annotation, or JSON report rendering is complete
- whether schema conformance is complete
- whether mutation adequacy is strong
- whether fuzzing is sufficient
- whether release readiness is proven

Those are separate proof lanes:

- **Unit tests** prove parser correctness, range merging invariants, policy logic
- **Property tests** (proptest) verify deterministic output ordering, percent math
- **BDD tests** (Cucumber) validate end-to-end scenarios
- **Fuzzing** (cargo-fuzz) stress-tests diff and LCOV parsers
- **Mutation tests** (cargo-mutants) measure domain logic adequacy
- **Conformance tests** (xtask) verify schema compliance
- **Golden fixtures** provide byte-stable output snapshots

## Workflow

The Coverage workflow runs on:

- **Push to main**: Strict upload (fails workflow if Codecov fails)
- **Workflow dispatch**: Advisory upload (completes even if upload fails)
- **PRs labeled `coverage`, `full-ci`, or `ci:full`**: Advisory upload

### Coverage Lane Artifacts

Durable receipts:

- `coverage.json` — Codecov's machine-readable format
- `coverage.txt` — Human-readable summary
- `lcov.info` — LCOV coverage report uploaded to Codecov
- GitHub Actions artifact: `coverage-report` (14-day retention)
- Codecov dashboard: codecov.io/gh/EffortlessMetrics/covguard

### Configuration

See `codecov.yml` for:

- Precision, rounding, and range thresholds
- Project and patch status flags
- Ignored paths (target, fuzz, xtask, benches, examples)
- Disabled comments and check annotations (quiet mode)
