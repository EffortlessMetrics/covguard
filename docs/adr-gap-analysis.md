# ADR Gap Analysis Report

**Generated**: 2026-03-13  
**Purpose**: Identify architectural decisions that should be documented as ADRs but aren't yet.

## Executive Summary

After reviewing the codebase across domain logic, CLI, configuration, paths, and rendering components, I identified **10 potential ADRs** that were undocumented. Of these, **4 high priority ADRs have been completed** (ADR-009 through ADR-012), leaving **4 medium priority** and **2 low priority** ADRs remaining.

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

## Remaining Missing ADRs

### MEDIUM PRIORITY

### MEDIUM PRIORITY

#### 5. Path Normalization Strategy

**Priority**: Medium  
**Category**: Cross-platform

**Rationale**:  
Path normalization ensures consistent behavior across Windows and Unix systems. The rules are partially documented in `contracts/rules/paths.md` but deserve a full ADR.

**Evidence**:
- [`crates/covguard-paths/src/lib.rs:1-104`](crates/covguard-paths/src/lib.rs:1) - normalization functions
- [`contracts/rules/paths.md`](contracts/rules/paths.md:1) - path rules contract

**Key Decisions**:
- All paths normalized to forward slashes
- Strip `a/` and `b/` diff prefixes
- Strip leading `./`
- Support configurable path stripping for LCOV SF: paths
- Handle absolute paths by detecting source markers (`/src/`, `/lib/`, etc.)

---

#### 6. CLI Operation Modes (Standard vs Cockpit)

**Priority**: Medium  
**Category**: CLI/UX

**Rationale**:  
The tool has two distinct operating modes with different behaviors for exit codes, output schemas, and error handling. This is a significant design decision affecting integration patterns.

**Evidence**:
- [`crates/covguard-cli/src/main.rs:46-53`](crates/covguard-cli/src/main.rs:46) - `CliMode` enum
- [`crates/covguard-cli/src/main.rs:730-734`](crates/covguard-cli/src/main.rs:730) - mode-based exit code logic
- Cockpit mode uses `sensor.report.v1` schema with capabilities block

**Key Decisions**:
- Standard mode: Exit codes reflect verdict (0/1/2)
- Cockpit mode: Always exit 0 if receipt written, exit 1 only on crash
- Cockpit mode emits `sensor.report.v1` schema with capabilities block
- Fallback receipts written in cockpit mode on errors

---

#### 7. Multi-layered Testing Strategy

**Priority**: Medium  
**Category**: Quality Assurance

**Rationale**:  
The project uses an unusually comprehensive testing approach (unit, property, BDD, fuzzing, mutation, golden) that should be documented as an architectural decision.

**Evidence**:
- [`docs/testing.md`](docs/testing.md:1) - testing documentation
- [`bdd/features/`](bdd/features/) - BDD tests
- [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/) - fuzz targets
- [`.cargo/mutants.toml`](.cargo/mutants.toml) likely exists for mutation testing

**Key Decisions**:
- Unit tests in each crate
- Property-based tests with `proptest` for domain invariants
- BDD tests with Cucumber for end-to-end scenarios
- Fuzzing with `cargo-fuzz` for parser robustness
- Mutation testing with `cargo-mutants` for domain logic
- Golden/snapshot tests for output stability

---

#### 8. Output Truncation Strategy

**Priority**: Medium  
**Category**: Output Contract

**Rationale**:  
The tool supports truncating findings to limit output size while preserving verdict accuracy. This affects how users interpret results and should be documented.

**Evidence**:
- [`contracts/rules/truncation.md`](contracts/rules/truncation.md:1) - truncation contract
- [`crates/covguard-output-features/src/lib.rs:62-80`](crates/covguard-output-features/src/lib.rs:62) - `truncate_findings()` function
- [`crates/covguard-cli/src/main.rs:165-167`](crates/covguard-cli/src/main.rs:165) - CLI options for limits

**Key Decisions**:
- Findings sorted before truncation
- `verdict.counts` reflects full (pre-truncation) counts
- Truncation metadata populated when truncated
- `max_findings = 0` is valid (empty findings with metadata)
- Separate limits for markdown, annotations, and SARIF outputs

---

### LOW PRIORITY

#### 9. Error Code Registry and Explain Command

**Priority**: Low  
**Category**: UX/Documentation

**Rationale**:  
The tool has a structured error code registry with remediation guidance and an `explain` command. While useful, this is more of a feature than an architectural decision.

**Evidence**:
- [`crates/covguard-types/src/lib.rs:90-164`](crates/covguard-types/src/lib.rs:90) - `CODE_REGISTRY` and `CodeInfo`
- [`crates/covguard-cli/src/main.rs:737-749`](crates/covguard-cli/src/main.rs:737) - `run_explain()` function
- [`docs/codes.md`](docs/codes.md:1) - error code documentation

**Key Decisions**:
- Error codes follow `category.subcategory.specific` pattern
- Each code has metadata: name, descriptions, remediation, help URI
- `covguard explain <code>` command for user assistance
- Codes are constants in `covguard-types` crate

---

#### 10. Fuzzing Target Design

**Priority**: Low  
**Category**: Quality Assurance

**Rationale**:  
Fuzz targets are designed with a specific philosophy (parsers must never panic). This is important but narrow in scope.

**Evidence**:
- [`fuzz/fuzz_targets/fuzz_diff_parser.rs`](fuzz/fuzz_targets/fuzz_diff_parser.rs:1) - diff fuzzer
- [`fuzz/fuzz_targets/fuzz_lcov_parser.rs`](fuzz/fuzz_targets/fuzz_lcov_parser.rs:1) - LCOV fuzzer (likely exists)
- Comment: "The parser should never panic, regardless of input"

**Key Decisions**:
- Fuzz targets focus on parser robustness
- Use `libfuzzer_sys` with `cargo-fuzz`
- Lossy UTF-8 conversion acceptable for fuzzing
- Primary invariant: parsers must never panic

---

## Summary Table

| Priority | ADR Title | Category | Effort | Status |
|----------|-----------|----------|--------|--------|
| High | Exit Code Strategy | CLI/UX | Small | ✅ ADR-009 |
| High | Error Handling and Propagation | Architecture | Medium | ✅ ADR-010 |
| High | Configuration Precedence Hierarchy | Configuration | Small | ✅ ADR-011 |
| High | Determinism Guarantees | Output Contract | Small | ✅ ADR-012 |
| Medium | Path Normalization Strategy | Cross-platform | Small | Pending |
| Medium | CLI Operation Modes | CLI/UX | Small | Pending |
| Medium | Multi-layered Testing Strategy | QA | Medium | Pending |
| Medium | Output Truncation Strategy | Output Contract | Small | Pending |
| Low | Error Code Registry | UX/Documentation | Small | Pending |
| Low | Fuzzing Target Design | QA | Small | Pending |

---

## Recommendations

1. ~~**Prioritize High-Items First**: Exit Code Strategy and Error Handling are user-facing contracts that affect CI integration.~~ ✅ Completed.

2. **Leverage Existing Documentation**: Several topics (determinism, paths, truncation) already have contracts documentation that can be expanded into ADRs.

3. **Consider Consolidation**: Error Handling and Error Code Registry could potentially be combined into a single "Error Strategy" ADR.

4. **Review After Implementation**: CLI Operation Modes may evolve as cockpit mode matures; consider documenting after stabilization.

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
