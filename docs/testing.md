# Testing Guide

This document covers the multi-layered testing strategy for covguard.

## Quick Reference

```bash
# All tests
cargo test

# Specific crate tests
cargo test --package covguard-domain
cargo test --package covguard-app
cargo test --package covguard
cargo test --package covguard-adapters-diff
cargo test --package covguard-adapters-coverage

# Property-based tests (included in cargo test)
cargo test --package covguard-domain proptest

# Mutation testing
cargo mutants

# Fuzzing (requires nightly)
cd fuzz && cargo +nightly fuzz run fuzz_diff_parser
```

## Test Locations by Crate

| Crate | Test Type | Location |
|-------|-----------|----------|
| covguard-types | Unit tests | `crates/covguard-types/src/lib.rs` |
| covguard-domain | Unit + Property tests | `crates/covguard-domain/src/lib.rs` |
| covguard-config | Unit tests | `crates/covguard-config/src/lib.rs` |
| covguard-adapters-diff | Unit + Property tests | `crates/covguard-adapters-diff/src/lib.rs` |
| covguard-adapters-coverage | Unit + Property tests | `crates/covguard-adapters-coverage/src/lib.rs` |
| covguard-render | Unit + Snapshot tests | `crates/covguard-render/src/lib.rs` |
| covguard-app | Integration + Snapshot tests + BDD + schema tests | `crates/covguard-app/src/lib.rs`, `crates/covguard-app/tests/` |
| covguard-core | Compatibility facade (re-export only, no dedicated test suite) | `crates/covguard-core/src/lib.rs` |
| covguard | CLI unit + integration tests | `crates/covguard-cli/src/main.rs`, `crates/covguard-cli/tests/integration.rs` |

## Mutation Testing with cargo-mutants

Mutation testing verifies that our test suite catches bugs by systematically
modifying the code and checking that tests fail. If a mutant "survives" (tests
still pass), it may indicate a gap in test coverage.

### Installation

```bash
cargo install cargo-mutants
```

### Running Mutations

```bash
# Run all mutations (uses mutants.toml configuration)
cargo mutants

# List mutations without running (preview)
cargo mutants --list

# Run with parallel jobs for faster execution
cargo mutants -j4

# Run mutations on specific files
cargo mutants -f crates/covguard-domain/src/lib.rs

# Generate HTML report
cargo mutants --output mutants-report
```

### Configuration

The `.cargo/mutants.toml` file configures mutation testing:

- **examine_globs**: Files to mutate (focused on `covguard-domain`)
- **exclude_globs**: Skip test code, benchmarks, generated files
- **exclude_re**: Skip specific functions (Display, Debug, trivial getters)

### Critical Functions

The following functions in `covguard-domain` are high-priority mutation targets:

| Function | Purpose | Why It Matters |
|----------|---------|----------------|
| `evaluate()` | Main entry point | Orchestrates all policy evaluation |
| `determine_verdict()` | Maps findings to verdict | Incorrect verdict = wrong CI result |
| `calc_coverage_pct()` | Percentage calculation | Edge cases (0%, 100%, division by zero) |
| `sort_findings()` | Deterministic ordering | Required for stable output/snapshots |
| `has_ignore_directive()` | Directive parsing | Incorrect parsing = missed/wrong ignores |

### Interpreting Results

```
Mutations tested: 50
Caught: 48
Missed: 2 (INVESTIGATE THESE)
Timeout: 0
```

- **Caught**: Good! Test suite detected the mutation.
- **Missed**: Bad! Tests passed with buggy code. Add more tests.
- **Timeout**: Mutation caused infinite loop (treated as caught).

### CI Integration

Add to your CI workflow:

```yaml
- name: Mutation Testing
  run: |
    cargo install cargo-mutants
    cargo mutants --no-shuffle --timeout 120
```

Use `--no-shuffle` for deterministic ordering in CI.

## Other Testing Layers

### Property-Based Tests (proptest)

Property tests are embedded in the test modules of these crates:

- **covguard-domain** (`crates/covguard-domain/src/lib.rs`)
  - Coverage percentage is always 0-100%
  - Finding sort order is deterministic
  - Evaluation is idempotent

- **covguard-adapters-diff** (`crates/covguard-adapters-diff/src/lib.rs`)
  - Merged ranges are sorted and non-overlapping
  - Range merging is idempotent

- **covguard-adapters-coverage** (`crates/covguard-adapters-coverage/src/lib.rs`)
  - Coverage merging is commutative: `merge(a, b) == merge(b, a)`
  - Coverage merging is idempotent: `merge(a, a) == a`

### Fuzzing

Located in `fuzz/`. Targets:
- `fuzz_diff_parser`: Ensures diff parsing never panics
- `fuzz_lcov_parser`: Ensures LCOV parsing never panics

```bash
cd fuzz
cargo +nightly fuzz run fuzz_diff_parser -- -max_total_time=300
```

### Snapshot Tests (insta)

Snapshot tests use the `insta` crate for output stability:

- **covguard-render**: `crates/covguard-render/src/snapshots/`
- **covguard-app**: `crates/covguard-app/src/snapshots/`

Update snapshots with:
```bash
cargo insta review
```

### Golden Fixtures

Test fixtures in `fixtures/`:

```
fixtures/
├── diff/                    # Unified diff patches
│   ├── simple_added.patch
│   ├── multiple_files.patch
│   ├── renamed_file.patch
│   └── ...
├── lcov/                    # LCOV coverage files
│   ├── uncovered.info
│   ├── covered.info
│   ├── partial_coverage.info
│   └── ...
└── expected/                # Expected JSON outputs
    ├── report_covered.json
    ├── report_uncovered.json
    └── ...
```

### BDD Tests (Cucumber)

End-to-end scenarios in `bdd/features/`. Tests the full pipeline from
diff + LCOV input to JSON/Markdown output.
