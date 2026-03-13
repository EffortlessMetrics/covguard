# ADR Gap Analysis Report

**Generated**: 2026-03-13  
**Purpose**: Identify architectural decisions that should be documented as ADRs but aren't yet.

## Executive Summary

After reviewing the codebase across domain logic, CLI, configuration, paths, and rendering components, I identified **10 potential ADRs** that were undocumented. All **10 ADRs have now been completed**:
- **4 high priority** (ADR-009 through ADR-012)
- **4 medium priority** (ADR-013 through ADR-016)
- **2 low priority** (ADR-017 through ADR-018)

## Existing ADRs (For Reference)

| Number | Title | Coverage |
|--------|-------|----------|
| ADR-001 | Hexagonal/Clean Architecture | Architecture style |
| ADR-002 | Multi-crate Workspace Structure | Code organization |
| ADR-003 | LCOV as Primary Coverage Format | Input format |
| ADR-004 | Unified Diff Format for Input | Input format |
| ADR-005 | Schema-compliant JSON Output | Output format |
| ADR-006 | Dual Licensing | Legal |
| ADR-007 | Built-in Profiles | Configuration |
| ADR-008 | Ignore Directives | Feature |

---

## Completed ADRs (Previously Identified as Missing)

### HIGH PRIORITY — ✅ COMPLETED

#### 1. Exit Code Strategy — ✅ ADR-009

**Status**: Completed as [ADR-009](adr/ADR-009.md)

The CLI exit code scheme (0=pass/warn, 1=tool error, 2=policy fail) is now formally documented.

---

#### 2. Error Handling and Propagation Strategy — ✅ ADR-010

**Status**: Completed as [ADR-010](adr/ADR-010.md)

The `thiserror`-based hierarchical error propagation pattern is now formally documented.

---

#### 3. Configuration Precedence Hierarchy — ✅ ADR-011

**Status**: Completed as [ADR-011](adr/ADR-011.md)

The configuration precedence chain (CLI > config file > profile defaults > global defaults) is now formally documented.

---

#### 4. Determinism Guarantees — ✅ ADR-012

**Status**: Completed as [ADR-012](adr/ADR-012.md)

The deterministic output requirements and findings sort order are now formally documented.

---

## Completed ADRs (Medium Priority)

### MEDIUM PRIORITY — ✅ COMPLETED

#### 5. Path Normalization Strategy — ✅ ADR-013

**Status**: Completed as [ADR-013](adr/ADR-013.md)

Path normalization ensures consistent behavior across Windows and Unix systems. The rules are now formally documented.

---

#### 6. CLI Operation Modes (Standard vs Cockpit) — ✅ ADR-014

**Status**: Completed as [ADR-014](adr/ADR-014.md)

The tool's two distinct operating modes with different behaviors for exit codes, output schemas, and error handling are now formally documented.

---

#### 7. Multi-layered Testing Strategy — ✅ ADR-015

**Status**: Completed as [ADR-015](adr/ADR-015.md)

The project's comprehensive testing approach (unit, property, BDD, fuzzing, mutation, golden) is now formally documented.

---

#### 8. Output Truncation Strategy — ✅ ADR-016

**Status**: Completed as [ADR-016](adr/ADR-016.md)

The tool's findings truncation approach that preserves verdict accuracy while limiting output size is now formally documented.

---

## Completed ADRs (Low Priority)

### LOW PRIORITY — ✅ COMPLETED

#### 9. Error Code Registry and Explain Command — ✅ ADR-017

**Status**: Completed as [ADR-017](adr/ADR-017.md)

The structured error code registry with remediation guidance and `explain` command is now formally documented.

---

#### 10. Fuzzing Target Design — ✅ ADR-018

**Status**: Completed as [ADR-018](adr/ADR-018.md)

The fuzz target design philosophy (parsers must never panic) is now formally documented.

---

## Summary Table

| Priority | ADR Title | Category | Effort | Status |
|----------|-----------|----------|--------|--------|
| High | Exit Code Strategy | CLI/UX | Small | ✅ ADR-009 |
| High | Error Handling and Propagation | Architecture | Medium | ✅ ADR-010 |
| High | Configuration Precedence Hierarchy | Configuration | Small | ✅ ADR-011 |
| High | Determinism Guarantees | Output Contract | Small | ✅ ADR-012 |
| Medium | Path Normalization Strategy | Cross-platform | Small | ✅ ADR-013 |
| Medium | CLI Operation Modes | CLI/UX | Small | ✅ ADR-014 |
| Medium | Multi-layered Testing Strategy | QA | Medium | ✅ ADR-015 |
| Medium | Output Truncation Strategy | Output Contract | Small | ✅ ADR-016 |
| Low | Error Code Registry | UX/Documentation | Small | ✅ ADR-017 |
| Low | Fuzzing Target Design | QA | Small | ✅ ADR-018 |

---

## Recommendations

1. ~~**Prioritize High-Items First**: Exit Code Strategy and Error Handling are user-facing contracts that affect CI integration.~~ ✅ Completed.

2. ~~**Leverage Existing Documentation**: Several topics (determinism, paths, truncation) already have contracts documentation that can be expanded into ADRs.~~ ✅ Completed.

3. ~~**Consider Consolidation**: Error Handling and Error Code Registry could potentially be combined into a single "Error Strategy" ADR.~~ Kept separate for clarity.

4. ~~**Review After Implementation**: CLI Operation Modes may evolve as cockpit mode matures; consider documenting after stabilization.~~ ✅ Documented as ADR-014.

---

## Files Reviewed

- `crates/covguard-domain/src/lib.rs` - Domain logic, determinism, verdict
- `crates/covguard-cli/src/main.rs` - CLI handling, exit codes, modes
- `crates/covguard-config/src/lib.rs` - Configuration, precedence
- `crates/covguard-paths/src/lib.rs` - Path normalization
- `crates/covguard-render/src/lib.rs` - Output rendering
- `crates/covguard-orchestrator/src/lib.rs` - Orchestration, errors
- `crates/covguard-types/src/lib.rs` - Types, error codes
- `crates/covguard-output-features/src/lib.rs` - Output budgets, truncation
- `docs/testing.md` - Testing strategy
- `docs/codes.md` - Error codes
- `contracts/rules/determinism.md` - Determinism contract
- `contracts/rules/paths.md` - Path rules
- `contracts/rules/truncation.md` - Truncation rules
- `fuzz/fuzz_targets/fuzz_diff_parser.rs` - Fuzzing approach
