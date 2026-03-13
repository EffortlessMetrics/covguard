# covguard docs index

[![crates.io](https://img.shields.io/crates/v/covguard-cli)](https://crates.io/crates/covguard-cli)

**Install:** `cargo install covguard-cli`

---

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

## Planning & Roadmap

- [Roadmap](roadmap.md) — Vision, goals, release history, and future milestones
- [Now/Next/Later](now-next-later.md) — Current priorities and upcoming work

### Audits & Analyses

- [Crate README Audit](crate-readme-audit.md) — Crate README consistency audit results
- [ADR Gap Analysis](adr-gap-analysis.md) — Analysis of missing Architecture Decision Records

## Release Documentation

- [Release Audit](release-audit.md) — Cargo.toml audit results and publishing readiness
- [Release Checklist](release-checklist.md) — Step-by-step publishing guide

## Architecture Decision Records

ADRs document significant architectural decisions:

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-000](adr/ADR-000.md) | ADR Template | Template |
| [ADR-001](adr/ADR-001.md) | Hexagonal/Clean Architecture | Accepted |
| [ADR-002](adr/ADR-002.md) | Multi-crate Workspace Structure | Accepted |
| [ADR-003](adr/ADR-003.md) | LCOV as Primary Coverage Format | Accepted |
| [ADR-004](adr/ADR-004.md) | Unified Diff Format for Input | Accepted |
| [ADR-005](adr/ADR-005.md) | Schema-compliant JSON Output | Accepted |
| [ADR-006](adr/ADR-006.md) | Dual Licensing | Accepted |
| [ADR-007](adr/ADR-007.md) | Built-in Profiles | Accepted |
| [ADR-008](adr/ADR-008.md) | Ignore Directives | Accepted |

See [adr/README.md](adr/README.md) for the full index and ADR guidelines.

## Crate Documentation

Each crate has its own `CLAUDE.md` with crate-specific guidance:

| Crate | Purpose | Location |
|-------|---------|----------|
| `covguard-types` | DTOs, schema definitions, error codes | `crates/covguard-types/CLAUDE.md` |
| `covguard-domain` | Pure policy evaluation logic | `crates/covguard-domain/CLAUDE.md` |
| `covguard-policy` | Shared policy/profile model and profile flags | `crates/covguard-policy/CLAUDE.md` |
| `covguard-config` | Configuration parsing and profiles | `crates/covguard-config/CLAUDE.md` |
| `covguard-adapters-diff` | Unified diff parsing | `crates/covguard-adapters-diff/CLAUDE.md` |
| `covguard-adapters-coverage` | LCOV parsing | `crates/covguard-adapters-coverage/CLAUDE.md` |
| `covguard-adapters-artifacts` | Artifact persistence (report + raw artifacts) | `crates/covguard-adapters-artifacts/README.md` |
| `covguard-output` | Centralized markdown/annotation/SARIF rendering feature flags | `crates/covguard-output/README.md` |
| `covguard-render` | Markdown, annotations, SARIF output | `crates/covguard-render/CLAUDE.md` |
| `covguard-orchestrator` | Orchestration layer | `crates/covguard-orchestrator` |
| `covguard-app` | Compatibility facade | `crates/covguard-app/CLAUDE.md` |
| `covguard-cli` | CLI binary | `crates/covguard-cli/CLAUDE.md` |

## Other Resources

- `contracts/schemas/` — JSON schemas for report validation
- `fixtures/` — Test fixtures (diffs, LCOV files, expected outputs)
- `fuzz/` — Cargo-fuzz targets for parser safety
- `xtask/` — Build automation tasks
