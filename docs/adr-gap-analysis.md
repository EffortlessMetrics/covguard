# ADR Gap Analysis Report

**Generated**: 2026-03-13  
**Purpose**: Identify architectural decisions that should be documented as ADRs but aren't yet.

## Executive Summary

After reviewing the codebase across domain logic, CLI, configuration, paths, and rendering components, I identified **10 potential ADRs** that are currently undocumented. Of these, **4 are high priority**, **4 are medium priority**, and **2 are low priority**.

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

## Identified Missing ADRs

### HIGH PRIORITY

#### 1. Exit Code Strategy

**Priority**: High  
**Category**: CLI/UX

**Rationale**:  
The CLI uses a specific exit code scheme (0=pass/warn, 1=tool error, 2=policy fail) that differs from typical Unix conventions. This is a user-facing contract that affects CI integration and should be formally documented.

**Evidence**:
- [`crates/covguard-cli/src/main.rs:223-227`](crates/covguard-cli/src/main.rs:223) explicitly defines exit codes
- [`crates/covguard-orchestrator/src/lib.rs:186-189`](crates/covguard-orchestrator/src/lib.rs:186) documents exit codes in `CheckResult`
- Cockpit mode introduces additional exit code behavior (always exits 0 if receipt written)

**Key Decisions**:
- 0: Pass or warn (non-blocking)
- 1: Tool/runtime error (I/O, parse failure)
- 2: Policy fail (blocking findings)
- Cockpit mode: Always 0 on successful receipt write

---

#### 2. Error Handling and Propagation Strategy

**Priority**: High  
**Category**: Architecture

**Rationale**:  
The codebase uses `thiserror` consistently across all crates with a hierarchical error propagation pattern. Each layer has its own error type that wraps lower-level errors. This is a significant architectural decision affecting maintainability and debugging.

**Evidence**:
- [`crates/covguard-cli/src/main.rs:181-221`](crates/covguard-cli/src/main.rs:181) - `CliError` enum
- [`crates/covguard-orchestrator/src/lib.rs:196-221`](crates/covguard-orchestrator/src/lib.rs:196) - `AppError` enum
- [`crates/covguard-config/src/lib.rs:20-34`](crates/covguard-config/src/lib.rs:20) - `ConfigError` enum
- [`crates/covguard-adapters-diff/src/lib.rs:33-43`](crates/covguard-adapters-diff/src/lib.rs:33) - `DiffError` enum
- [`crates/covguard-adapters-coverage/src/lib.rs:27-36`](crates/covguard-adapters-coverage/src/lib.rs:27) - `LcovError` enum
- [`crates/covguard-adapters-artifacts/src/lib.rs:19-40`](crates/covguard-adapters-artifacts/src/lib.rs:19) - `ArtifactWriteError` enum

**Key Decisions**:
- Use `thiserror` crate for all error types
- Each crate defines its own error enum
- Errors propagate upward with `From` trait implementations
- Error codes (e.g., `covguard.diff.uncovered_line`) are separate from error types

---

#### 3. Configuration Precedence Hierarchy

**Priority**: High  
**Category**: Configuration

**Rationale**:  
The configuration system has a clear precedence chain (CLI > config file > profile defaults > global defaults) that affects how users interact with the tool. This should be formally documented.

**Evidence**:
- [`crates/covguard-config/src/lib.rs:256-315`](crates/covguard-config/src/lib.rs:256) - `resolve_config()` function
- Comment explicitly states: "Precedence: CLI > config file > profile defaults > global defaults"

**Key Decisions**:
- CLI arguments have highest priority
- Config file values override profile defaults
- Profile defaults override global defaults
- `CliOverrides` struct uses `Option<T>` to distinguish "not set" from "set to default"

---

#### 4. Determinism Guarantees

**Priority**: High  
**Category**: Output Contract

**Rationale**:  
Deterministic output is critical for CI/CD reliability and snapshot testing. The sorting algorithm for findings is a normative contract that should be documented as an ADR.

**Evidence**:
- [`crates/covguard-domain/src/lib.rs:287-328`](crates/covguard-domain/src/lib.rs:287) - `sort_findings()` function
- [`contracts/rules/determinism.md`](contracts/rules/determinism.md:1) documents the sort order
- Findings sorted by: severity > path > line > check_id > code > message

**Key Decisions**:
- Findings must be sorted deterministically for byte-stable output
- Sort order: severity (error > warn > info) > path (lexical) > line (numeric) > check_id > code > message
- Timing fields (`started_at`, `ended_at`, `duration_ms`) are excluded from determinism contracts

---

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

| Priority | ADR Title | Category | Effort |
|----------|-----------|----------|--------|
| High | Exit Code Strategy | CLI/UX | Small |
| High | Error Handling and Propagation | Architecture | Medium |
| High | Configuration Precedence Hierarchy | Configuration | Small |
| High | Determinism Guarantees | Output Contract | Small |
| Medium | Path Normalization Strategy | Cross-platform | Small |
| Medium | CLI Operation Modes | CLI/UX | Small |
| Medium | Multi-layered Testing Strategy | QA | Medium |
| Medium | Output Truncation Strategy | Output Contract | Small |
| Low | Error Code Registry | UX/Documentation | Small |
| Low | Fuzzing Target Design | QA | Small |

---

## Recommendations

1. **Prioritize High-Items First**: Exit Code Strategy and Error Handling are user-facing contracts that affect CI integration.

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
