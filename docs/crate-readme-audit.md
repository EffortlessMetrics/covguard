# Crate README Audit Report

**Audit Date:** 2026-03-13
**Auditor:** Architect Mode
**Total Crates:** 20

## Executive Summary

All 20 crate READMEs require updates to meet consistency standards. The most significant gaps are:

- **0/20** have crates.io badges
- **0/20** have docs.rs badges
- **1/20** has usage examples (covguard-adapters-artifacts)
- **0/20** have explicit repository links
- **0/20** have license references

## Audit Matrix

| Crate | crates.io Badge | docs.rs Badge | Description Matches | Usage Examples | Repo Link | License |
|-------|:---------------:|:-------------:|:-------------------:|:--------------:|:---------:|:-------:|
| covguard-adapters-artifacts |❌ |❌ |✅ |✅ |❌ |❌ |
| covguard-adapters-coverage |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-adapters-diff |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-adapters-repo |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-app |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-cli | N/A | N/A | N/A | N/A | N/A | N/A |
| covguard-config |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-core |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-directives |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-domain |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-orchestrator |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-output |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-output-features |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-paths |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-policy |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-ports |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-ranges |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-render |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-reporting |❌ |❌ |⚠️ |❌ |❌ |❌ |
| covguard-types |❌ |❌ |⚠️ |❌ |❌ |❌ |

**Legend:**
- ✅ - Present and correct
- ⚠️ - Present but inconsistent with Cargo.toml
-❌ - Missing
- N/A - Not applicable (CLI crate has no README)

## Detailed Findings

### 1. covguard-adapters-artifacts

**README Description:** "Filesystem adapters for covguard artifact output."
**Cargo.toml Description:** "Filesystem artifact adapters for covguard reports and fallback outputs."

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description slightly differs from Cargo.toml
- Missing repository link
- Missing license reference

**Positive:** Has a usage example

### 2. covguard-adapters-coverage

**README Description:** "Coverage adapter crate for covguard."
**Cargo.toml Description:** "LCOV parsing and coverage-map merge adapter for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description too generic vs Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 3. covguard-adapters-diff

**README Description:** "Diff adapter crate for covguard."
**Cargo.toml Description:** "Unified diff parsing and git-diff loading adapter for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description too generic vs Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 4. covguard-adapters-repo

**README Description:** "Repository reader adapter for covguard."
**Cargo.toml Description:** "Filesystem-backed RepoReader adapter for covguard ignore-directive lookup"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description too generic vs Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 5. covguard-app

**README Description:** "Compatibility façade for the orchestration API."
**Cargo.toml Description:** "Compatibility facade over covguard-orchestrator"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs slightly from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 6. covguard-cli

**Note:** This crate does not have a README.md file. The CLI is the main entry point and typically documented at the repository level.

### 7. covguard-config

**README Description:** "Configuration crate for covguard."
**Cargo.toml Description:** "Configuration loading, profile defaults, and CLI precedence resolution for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description too generic vs Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 8. covguard-core

**README Description:** "Compatibility facade for legacy integrations."
**Cargo.toml Description:** "Backward-compatible facade crate that re-exports covguard-app"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 9. covguard-directives

**README Description:** "Small, isolated helpers for directive-aware behavior in covguard."
**Cargo.toml Description:** "Directive parsing and directive-range helpers for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 10. covguard-domain

**README Description:** "Pure domain logic for covguard."
**Cargo.toml Description:** "Pure policy evaluation engine for diff-scoped coverage decisions"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 11. covguard-orchestrator

**README Description:** "This crate contains the orchestration logic for covguard..."
**Cargo.toml Description:** "Application orchestration layer for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 12. covguard-output

**README Description:** "Output rendering utilities for covguard reports."
**Cargo.toml Description:** "Composable report rendering and output feature flags for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 13. covguard-output-features

**README Description:** "This crate owns the output feature-flag contract used by covguard..."
**Cargo.toml Description:** "Shared output feature-flag contracts for covguard renderers"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 14. covguard-paths

**README Description:** "Tiny crate containing shared path normalization logic for covguard adapters."
**Cargo.toml Description:** "Reusable path normalization helpers for covguard adapters"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs slightly from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 15. covguard-policy

**README Description:** "Shared policy enums, profile variants, and preset settings used by covguard core services."
**Cargo.toml Description:** "Shared policy and profile contracts for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 16. covguard-ports

**README Description:** "Hexagonal boundary contracts for covguard."
**Cargo.toml Description:** "Port traits and boundary types for covguard adapters and app orchestration"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 17. covguard-ranges

**README Description:** "Shared range-merging utilities used by covguard diff parsing and evaluation."
**Cargo.toml Description:** "Range merging utilities for covguard diff coverage"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 18. covguard-render

**README Description:** "Output renderers for covguard reports."
**Cargo.toml Description:** "Render covguard reports as markdown, GitHub annotations, and SARIF"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 19. covguard-reporting

**README Description:** "Report assembly and output metadata construction for `covguard`."
**Cargo.toml Description:** "Report construction for covguard (standard + sensor schemas)"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

### 20. covguard-types

**README Description:** "Core shared types for covguard."
**Cargo.toml Description:** "Shared report DTOs, codes, and schema constants for covguard"

**Issues:**
- Missing crates.io badge
- Missing docs.rs badge
- Description differs from Cargo.toml
- No usage examples
- Missing repository link
- Missing license reference

## Recommended README Template

Each crate README should follow this structure:

```markdown
# crate-name

[![crates.io](https://img.shields.io/crates/v/crate-name.svg)](https://crates.io/crates/crate-name)
[![docs.rs](https://docs.rs/crate-name/badge.svg)](https://docs.rs/crate-name)

Brief description matching Cargo.toml exactly.

## Features

- Feature 1
- Feature 2

## Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
crate-name = "0.1.0"
```

### Example

```rust
use crate_name::some_function;

// Example code
```

## API

- `function_one` - Description
- `function_two` - Description

## Repository

<https://github.com/owner/covguard>

## License

MIT OR Apache-2.0
```

## Recommendations

### Priority 1: Add Badges

Add crates.io and docs.rs badges to all 19 library crates:

```markdown
[![crates.io](https://img.shields.io/crates/v/CRATE_NAME.svg)](https://crates.io/crates/CRATE_NAME)
[![docs.rs](https://docs.rs/CRATE_NAME/badge.svg)](https://docs.rs/CRATE_NAME)
```

### Priority 2: Sync Descriptions

Ensure README opening description exactly matches Cargo.toml description for consistency.

### Priority 3: Add Usage Examples

Add at least one code example to each crate README showing basic usage.

### Priority 4: Add Repository Link

Add a link to the main repository:

```markdown
## Repository

<https://github.com/owner/covguard>
```

### Priority 5: Add License Reference

Add license information:

```markdown
## License

MIT OR Apache-2.0
```

## Summary Statistics

| Metric | Count | Percentage |
|--------|-------|------------|
| Has crates.io badge | 0/19 | 0% |
| Has docs.rs badge | 0/19 | 0% |
| Description matches | 1/19 | ~5% |
| Has usage examples | 1/19 | ~5% |
| Has repository link | 0/19 | 0% |
| Has license reference | 0/19 | 0% |

**Note:** Statistics exclude covguard-cli which has no README.
