# covguard-app

Compatibility façade for the orchestration API.

`covguard-app` now re-exports `covguard-orchestrator` to preserve the published
public API while allowing the orchestration implementation to evolve as a separate
microcrate.

## Pipeline

The orchestration implementation now lives in `covguard-orchestrator`:

1. Parse diff input
2. Parse and merge LCOV coverage
3. Detect ignore directives via `RepoReader`
4. Evaluate policy in `covguard-domain`
5. Build report and render outputs

## Main API

- `check`
- `check_with_clock`
- `check_with_clock_and_reader`
- `check_with_providers_and_reader`
