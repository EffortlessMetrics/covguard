# Deterministic Output Contract

Given identical inputs (diff, LCOV, configuration), covguard produces byte-identical output (modulo timing fields).

## Sort Order

Findings are normatively sorted by:

1. **Severity** (ascending: info < warn < error)
2. **Path** (lexicographic)
3. **Line** (numeric ascending)
4. **check_id** (lexicographic)
5. **code** (lexicographic)
6. **message** (lexicographic)

## Timing Fields

The following fields vary between runs and are excluded from determinism checks:

- `run.started_at`
- `run.ended_at`
- `run.duration_ms`
