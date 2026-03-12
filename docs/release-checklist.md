# Release Checklist for covguard

This document provides a comprehensive checklist for publishing covguard crates to crates.io.

## Prerequisites

- Rust 1.92+ (edition 2024)
- Cargo credentials configured (`cargo login`)
- Write access to all covguard crates on crates.io
- Clean working directory (no uncommitted changes)

---

## 1. Pre-Release Checklist

### 1.1 Version Verification

- [ ] All crates have the same version in their `Cargo.toml` (e.g., `0.1.0`)
- [ ] `CHANGELOG.md` is updated with the new version and release date
- [ ] Git tag for the release is ready to be created (e.g., `v0.1.0`)

### 1.2 Code Quality

- [ ] All tests pass: `cargo test --workspace`
- [ ] Clippy passes without warnings: `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Documentation builds: `cargo doc --workspace --no-deps`
- [ ] No TODOs or FIXMEs in released code that block release

### 1.3 Metadata Verification

- [ ] All crates have valid `license` field
- [ ] All crates have `description` field
- [ ] All crates have `repository` field
- [ ] All crates have `readme` field pointing to existing README
- [ ] All crates have valid `edition = "2024"` 
- [ ] All crates have valid `rust-version = "1.92"`
- [ ] All crates have `categories` and `keywords` for discoverability

### 1.4 Dependency Verification

- [ ] All internal dependencies use version paths (not path-only)
- [ ] No `path` dependencies remain in published crates (except dev-dependencies)
- [ ] All external dependencies are at stable versions

### 1.5 Dry Run Verification

Run dry-run for each crate to verify packaging:

```bash
# Quick check all crates
cargo publish --dry-run -p covguard-paths
cargo publish --dry-run -p covguard-ranges
cargo publish --dry-run -p covguard-policy
cargo publish --dry-run -p covguard-ports
cargo publish --dry-run -p covguard-types
cargo publish --dry-run -p covguard-directives
cargo publish --dry-run -p covguard-domain
cargo publish --dry-run -p covguard-render
cargo publish --dry-run -p covguard-output-features
cargo publish --dry-run -p covguard-reporting
cargo publish --dry-run -p covguard-adapters-artifacts
cargo publish --dry-run -p covguard-adapters-coverage
cargo publish --dry-run -p covguard-adapters-diff
cargo publish --dry-run -p covguard-adapters-repo
cargo publish --dry-run -p covguard-output
cargo publish --dry-run -p covguard-orchestrator
cargo publish --dry-run -p covguard-app
cargo publish --dry-run -p covguard-core
cargo publish --dry-run -p covguard-config
cargo publish --dry-run -p covguard-cli
```

---

## 2. Publishing Commands

**IMPORTANT**: Publish in this exact order to respect dependency chains.

### Tier 1 - Foundation Crates (No Internal Dependencies)

```bash
# 1. covguard-paths
cargo publish -p covguard-paths

# 2. covguard-ranges
cargo publish -p covguard-ranges

# 3. covguard-policy
cargo publish -p covguard-policy

# 4. covguard-ports
cargo publish -p covguard-ports
```

**Wait 30 seconds** for crates.io to index these packages.

### Tier 2 - Core Types (Depends on Tier 1)

```bash
# 5. covguard-types (needs policy)
cargo publish -p covguard-types

# 6. covguard-directives (needs ports)
cargo publish -p covguard-directives
```

**Wait 30 seconds** for crates.io to index.

### Tier 3 - Domain Layer

```bash
# 7. covguard-domain (needs directives)
cargo publish -p covguard-domain

# 8. covguard-render (needs types)
cargo publish -p covguard-render
```

**Wait 30 seconds** for crates.io to index.

### Tier 4 - Adapters and Reporting

```bash
# 9. covguard-output-features (needs render)
cargo publish -p covguard-output-features

# 10. covguard-reporting (needs domain)
cargo publish -p covguard-reporting

# 11. covguard-adapters-artifacts (needs types)
cargo publish -p covguard-adapters-artifacts

# 12. covguard-adapters-coverage (needs paths)
cargo publish -p covguard-adapters-coverage

# 13. covguard-adapters-diff (needs paths)
cargo publish -p covguard-adapters-diff

# 14. covguard-adapters-repo (needs ports)
cargo publish -p covguard-adapters-repo
```

**Wait 30 seconds** for crates.io to index.

### Tier 5 - Output and Orchestration

```bash
# 15. covguard-output (needs output-features)
cargo publish -p covguard-output

# 16. covguard-orchestrator (needs adapters-coverage + others)
cargo publish -p covguard-orchestrator
```

**Wait 30 seconds** for crates.io to index.

### Tier 6 - Application Layer

```bash
# 17. covguard-app (needs orchestrator)
cargo publish -p covguard-app
```

**Wait 30 seconds** for crates.io to index.

### Tier 7 - Core Facade

```bash
# 18. covguard-core (needs app)
cargo publish -p covguard-core
```

**Wait 30 seconds** for crates.io to index.

### Tier 8 - Configuration

```bash
# 19. covguard-config (needs output-features)
cargo publish -p covguard-config
```

**Wait 30 seconds** for crates.io to index.

### Tier 9 - CLI (Final Package)

```bash
# 20. covguard-cli (needs adapters-artifacts + others)
cargo publish -p covguard-cli
```

### One-Command Alternative (Script)

Save this as `publish.sh` for automated publishing:

```bash
#!/bin/bash
set -e

CRATES=(
    "covguard-paths"
    "covguard-ranges"
    "covguard-policy"
    "covguard-ports"
    "covguard-types"
    "covguard-directives"
    "covguard-domain"
    "covguard-render"
    "covguard-output-features"
    "covguard-reporting"
    "covguard-adapters-artifacts"
    "covguard-adapters-coverage"
    "covguard-adapters-diff"
    "covguard-adapters-repo"
    "covguard-output"
    "covguard-orchestrator"
    "covguard-app"
    "covguard-core"
    "covguard-config"
    "covguard-cli"
)

for crate in "${CRATES[@]}"; do
    echo "Publishing $crate..."
    cargo publish -p "$crate" || {
        echo "Failed to publish $crate"
        exit 1
    }
    echo "Waiting for crates.io to index..."
    sleep 30
done

echo "All crates published successfully!"
```

---

## 3. Post-Release Verification

### 3.1 Verify Crates on crates.io

Check that all crates are visible:

```bash
# Check individual crates
cargo search covguard-cli
cargo search covguard-core
cargo search covguard-domain

# Or check all at once
for crate in covguard-paths covguard-ranges covguard-policy covguard-ports covguard-types covguard-directives covguard-domain covguard-render covguard-output-features covguard-reporting covguard-adapters-artifacts covguard-adapters-coverage covguard-adapters-diff covguard-adapters-repo covguard-output covguard-orchestrator covguard-app covguard-core covguard-config covguard-cli; do
    cargo search "$crate"
done
```

### 3.2 Test Installation from crates.io

```bash
# Create a temporary directory
mkdir -p /tmp/covguard-test
cd /tmp/covguard-test
cargo new test-install
cd test-install

# Add covguard as dependency
cargo add covguard-cli

# Build to verify dependencies resolve
cargo build
```

### 3.3 Create Git Tag

```bash
cd /path/to/cov-guard
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### 3.4 GitHub Release

1. Go to https://github.com/your-org/cov-guard/releases
2. Click "Draft a new release"
3. Select the tag `v0.1.0`
4. Title: `v0.1.0`
5. Copy release notes from `CHANGELOG.md`
6. Publish the release

---

## 4. Rollback Plan

### 4.1 If a Crate Fails to Publish

1. **Check the error message** - usually it's:
   - Missing metadata (fix `Cargo.toml`)
   - Dependency not found (wait longer for indexing)
   - Version already exists (bump version)

2. **If dependency not found**:
   ```bash
   # Wait longer and retry
   sleep 60
   cargo publish -p <failed-crate>
   ```

3. **If version already exists**:
   - You cannot yank and republish the same version
   - Bump the patch version and retry

### 4.2 If a Published Crate Has Critical Bugs

1. **Yank the problematic version**:
   ```bash
   cargo yank --vers 0.1.0 <crate-name>
   ```

2. **This prevents new projects from using that version** but doesn't affect existing lockfiles.

3. **Publish a patch release** (0.1.1) with the fix.

### 4.3 Complete Rollback (Nuclear Option)

If the entire release is broken:

1. **Yank all crates**:
   ```bash
   for crate in covguard-paths covguard-ranges covguard-policy covguard-ports covguard-types covguard-directives covguard-domain covguard-render covguard-output-features covguard-reporting covguard-adapters-artifacts covguard-adapters-coverage covguard-adapters-diff covguard-adapters-repo covguard-output covguard-orchestrator covguard-app covguard-core covguard-config covguard-cli; do
       cargo yank --vers 0.1.0 "$crate"
   done
   ```

2. **Delete the Git tag**:
   ```bash
   git push --delete origin v0.1.0
   git tag -d v0.1.0
   ```

3. **Delete the GitHub release** (via web UI)

4. **Fix the issues and prepare 0.1.1**

---

## 5. Version Bump Process

After a successful release, prepare for the next development cycle:

### 5.1 Bump Version in All Cargo.toml Files

```bash
# Using cargo-release (recommended)
cargo install cargo-release
cargo release version 0.2.0-alpha.0

# Or manually update each Cargo.toml
```

### 5.2 Update Internal Dependencies

Ensure all internal `version` fields reference the new version:

```bash
# This is automated by cargo-release
# Or manually update version = "0.1.0" to version = "0.2.0-alpha.0"
```

### 5.3 Update CHANGELOG.md

Add a new `[Unreleased]` section:

```markdown
## [Unreleased]

### Added
- 

### Changed
- 

### Fixed
- 

## [0.1.0] - 2026-03-11
...existing entries...
```

### 5.4 Commit and Push

```bash
git add -A
git commit -m "chore: prepare for next development iteration"
git push origin main
```

---

## 6. Quick Reference

### Crate Count: 20 crates

### Dependency Tiers

| Tier | Crates | Dependencies |
|------|--------|--------------|
| 1 | paths, ranges, policy, ports | None (external only) |
| 2 | types, directives | Tier 1 |
| 3 | domain, render | Tier 2 |
| 4 | output-features, reporting, adapters-* | Tier 3 |
| 5 | output, orchestrator | Tier 4 |
| 6 | app | Tier 5 |
| 7 | core | Tier 6 |
| 8 | config | Tier 7 |
| 9 | cli | Tier 8 |

### Useful Commands

```bash
# Check workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Dry run all crates
cargo publish --dry-run -p <crate-name>

# Check crate on crates.io
cargo search <crate-name>

# Yank a version
cargo yank --vers <version> <crate-name>

# View crate details
cargo info <crate-name>@<version>
```

---

## 7. Troubleshooting

### "dependency `foo` is not found"

- Wait longer for crates.io to index (30-60 seconds between publishes)
- Check that the dependency was actually published

### "crate `foo` already exists"

- You cannot republish the same version
- Bump the version number

### "the remote server responded with an error"

- Check your `cargo login` credentials
- Check crates.io status at https://status.crates.io/

### "failed to verify the tarball"

- Check that all files referenced in `Cargo.toml` exist
- Check that `readme`, `license-file` paths are correct

### Path dependencies in published crate

- Ensure all internal dependencies have both `version` and `path`
- The `path` is stripped during publishing, leaving only `version`
