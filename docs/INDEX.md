# covguard docs index

covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).

## Core Documentation

- [Overview](overview.md) — What covguard is, where it fits, and the stable contracts
- [Requirements](requirements.md) — Goals, non-goals, inputs/outputs, policy
- [Design](design.md) — Domain vocabulary, data models, evaluation logic
- [Architecture](architecture.md) — Hexagonal structure, ports/adapters, crate layout
- [Implementation Plan](implementation-plan.md) — Phased deliverables with status
- [Integration](integration.md) — CI setup, GitHub Actions, local debugging
- [Codes](codes.md) — Error codes, meanings, and remediation
- [Testing](testing.md) — Multi-layered testing strategy

## Crate Documentation

Each crate has its own `CLAUDE.md` with crate-specific guidance:

| Crate | Purpose | Location |
|-------|---------|----------|
| `covguard-types` | DTOs, schema definitions, error codes | `crates/covguard-types/CLAUDE.md` |
| `covguard-domain` | Pure policy evaluation logic | `crates/covguard-domain/CLAUDE.md` |
| `covguard-config` | Configuration parsing and profiles | `crates/covguard-config/CLAUDE.md` |
| `covguard-adapters-diff` | Unified diff parsing | `crates/covguard-adapters-diff/CLAUDE.md` |
| `covguard-adapters-coverage` | LCOV parsing | `crates/covguard-adapters-coverage/CLAUDE.md` |
| `covguard-render` | Markdown, annotations, SARIF output | `crates/covguard-render/CLAUDE.md` |
| `covguard-app` | Orchestration layer | `crates/covguard-app/CLAUDE.md` |
| `covguard-cli` | CLI binary | `crates/covguard-cli/CLAUDE.md` |

## Other Resources

- `contracts/schemas/` — JSON schemas for report validation
- `fixtures/` — Test fixtures (diffs, LCOV files, expected outputs)
- `fuzz/` — Cargo-fuzz targets for parser safety
- `xtask/` — Build automation tasks
