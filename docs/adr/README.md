# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for covguard.

## What is an ADR?

An ADR is a document that captures an important architectural decision along with its context and consequences. Each ADR describes:
- The context and problem statement
- The decision made
- The consequences of that decision

## Index

| Number | Title | Status |
|--------|-------|--------|
| [ADR-000](ADR-000.md) | Template | - |
| [ADR-001](ADR-001.md) | Hexagonal/Clean Architecture | Accepted |
| [ADR-002](ADR-002.md) | Multi-crate Workspace Structure | Accepted |
| [ADR-003](ADR-003.md) | LCOV as Primary Coverage Format | Accepted |
| [ADR-004](ADR-004.md) | Unified Diff Format for Input | Accepted |
| [ADR-005](ADR-005.md) | Schema-compliant JSON Output | Accepted |
| [ADR-006](ADR-006.md) | Dual Licensing (Apache-2.0 OR MIT) | Accepted |
| [ADR-007](ADR-007.md) | Built-in Configuration Profiles | Accepted |
| [ADR-008](ADR-008.md) | Ignore Directives | Accepted |
| [ADR-009](ADR-009.md) | Exit Code Strategy | Accepted |
| [ADR-010](ADR-010.md) | Error Handling Strategy | Accepted |
| [ADR-011](ADR-011.md) | Configuration Precedence | Accepted |
| [ADR-012](ADR-012.md) | Deterministic Output | Accepted |
| [ADR-013](ADR-013.md) | Path Normalization Strategy | Accepted |
| [ADR-014](ADR-014.md) | CLI Operation Modes | Accepted |
| [ADR-015](ADR-015.md) | Multi-layered Testing Strategy | Accepted |
| [ADR-016](ADR-016.md) | Output Truncation Strategy | Accepted |
| [ADR-017](ADR-017.md) | Error Code Registry | Accepted |
| [ADR-018](ADR-018.md) | Fuzzing Target Design | Accepted |

## Creating a New ADR

1. Copy `ADR-000.md` to `ADR-NNN.md` (next available number)
2. Fill in Status, Context, Decision, Consequences
3. Update this index
4. Submit for review

## ADR Lifecycle

- **Proposed**: Under discussion, not yet approved
- **Accepted**: Approved and currently in effect
- **Deprecated**: No longer recommended for new implementations
- **Superseded**: Replaced by another ADR (link to replacement)

## Further Reading

- [Architecture Documentation](../architecture.md)
- [Design Documentation](../design.md)
- [Michael Nygard's ADR template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
