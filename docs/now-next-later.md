# covguard - Now/Next/Later

This document tracks current priorities using the Now/Next/Later framework.

---

## Now

*Current sprint focus and immediate priorities*

### Active Work
- Post-v0.1.0 monitoring and bug fixes
- Documentation improvements based on user feedback
- Example repository setup

### Maintenance
- Dependency updates
- CI pipeline optimization
- Fuzz target maintenance

### Metrics
- crates.io download monitoring
- Issue triage and response

---

## Next

*Upcoming features and improvements (next 1-2 releases)*

### v0.2.0 Candidates
- Enhanced error messages with actionable remediation
- Performance profiling for large repositories
- Additional examples for different CI platforms
- Expanded built-in test fixtures

### Investigation
- Alternative coverage format support (Jacoco, coverage.py)
- Incremental diff processing for large PRs
- Caching strategies for repeated runs

### Documentation
- Video tutorials
- Migration guides
- Troubleshooting playbook

---

## Later

*Future considerations (no commitment, exploratory)*

### Potential Features
- Global coverage tracking (opt-in, separate from diff-scope)
- Coverage trend visualization
- Team-specific policy profiles
- IDE integration

### Ecosystem
- Official GitHub Action
- GitLab CI integration
- Bitbucket Pipelines support

### Architecture
- Plugin system for custom coverage formats
- WebAssembly build for browser-based tools

---

## Deprioritized / Explicit Non-Goals

*Items explicitly out of scope per [requirements.md](requirements.md)*

- Coverage generation (cargo llvm-cov orchestration)
- Global coverage enforcement
- Adequacy heuristics (complexity, mutation score)
- Language-specific features beyond LCOV
