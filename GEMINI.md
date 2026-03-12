# Gemini Context: covguard

## Project Overview
`covguard` is a diff-scoped coverage gate tool written in Rust. It analyzes code changes (diffs) against coverage reports (LCOV) to answer the question: "Did this PR add or change lines that are not covered by tests?"

It is designed as a sensor in a "receipts-first" ecosystem, emitting canonical JSON receipts (`artifacts/covguard/report.json`) rather than just failing a build.

## Architecture
The project follows a **Hexagonal Architecture (Ports & Adapters)**:
*   **Domain Core (`covguard-domain`):** Pure business logic. Evaluates coverage, produces findings/verdicts. No side effects.
*   **Ports (`covguard-types`, traits):** Interfaces for diffs, coverage, repo access, and reporting.
*   **Adapters (`covguard-adapters-*`):** Implementations for parsing Unified Diff, LCOV, reading files, etc.
*   **Application (`covguard-app`):** Orchestrates the flow, wiring adapters to the domain.
*   **CLI (`covguard-cli`):** The user-facing entry point.

### Workspace Structure
*   `crates/covguard-cli`: Binary entry point.
*   `crates/covguard-app`: Main application logic.
*   `crates/covguard-domain`: Pure policy evaluation.
*   `crates/covguard-config`: Configuration loading (TOML, profiles).
*   `crates/covguard-adapters-diff`: Diff parsing.
*   `crates/covguard-adapters-coverage`: LCOV parsing.
*   `crates/covguard-render`: Output generation (Markdown, SARIF, GitHub Annotations).
*   `crates/covguard-types`: Shared DTOs and types.
*   `xtask`: Development automation tasks.

## Build & Run

### Basic Commands
*   **Build:** `cargo build --workspace`
*   **Run:** `cargo run --bin covguard -- check --diff-file <DIFF> --lcov <LCOV> --out <REPORT>`
*   **Test (All):** `cargo test --workspace`
*   **Documentation:** `cargo doc --workspace --no-deps`

### Development Tasks (`xtask`)
The project uses `xtask` for complex maintenance tasks:
*   **Conformance Tests:** `cargo xtask conform --all` (Runs schema, determinism, and survivability tests)
*   **Schema Validation:** `cargo xtask schema --check`
*   **Fixture Management:** `cargo xtask fixtures --check` (or `--update`)

## Testing Strategy
`covguard` employs a multi-layered testing strategy:
1.  **Unit Tests:** In each crate (standard `cargo test`).
2.  **Integration Tests:** In `crates/covguard-app/tests` and `crates/covguard-cli/tests`.
3.  **Property-Based Tests:** Using `proptest` (e.g., in `covguard-domain` and adapters).
4.  **Mutation Testing:** Using `cargo-mutants` (configured in `.cargo/mutants.toml`).
5.  **Fuzzing:** Using `cargo-fuzz` in `fuzz/` directory (parsers).
6.  **BDD:** Cucumber tests in `bdd/`.
7.  **Snapshot Tests:** Using `insta` for output stability (renderers).
8.  **Conformance:** Ensures `report.json` matches schemas (`contracts/schemas/`) and behavior is deterministic.

## Configuration
Configuration is handled via `config/covguard.toml` (or CLI args).
Key settings:
*   `scope`: "added" (default) or "touched".
*   `missing_coverage`: "skip", "warn", or "fail".
*   `threshold_pct`: Minimum coverage percentage for the diff.
*   `ignore.directives`: Enable `covguard: ignore` comments in code.

## Key Files
*   `README.md`: Project entry point and quickstart.
*   `docs/architecture.md`: Detailed architectural guidelines.
*   `contracts/schemas/covguard.report.v1.json`: The canonical output schema.
*   `.github/workflows/ci.yml`: CI definition (reveals the "source of truth" for build verification).
