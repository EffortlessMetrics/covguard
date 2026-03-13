# covguard - Now/Next/Later

This document tracks current priorities using the Now/Next/Later framework.

---

## Now

*Current priorities - post-v0.1.0 monitoring*

### Active Work
- Monitor crates.io downloads and user feedback
- Triage and respond to issues
- Update documentation based on feedback

### Maintenance
- Dependency updates (weekly check for security patches)
- CI pipeline optimization (review and improve caching)
- Fuzz target maintenance (weekly fuzz run)

### Metrics
- crates.io download tracking (weekly report)
- Issue response time (target: <24 hours)

---

## Next

*Upcoming work - next 1-2 releases*

### v0.2.0 Candidates
- Enhanced error messages with actionable remediation hints
- Performance profiling for large repositories (identify hot paths)
- Additional examples for different CI platforms (GitLab CI, CircleCI)
- Expanded built-in test fixtures

### Investigation
- Alternative coverage formats (Jacoco, coverage.py)
- Incremental diff processing for large PRs
- Caching strategies for repeated runs
- GitHub API integration (investigate API rate limits)
- GitLab API integration (investigate complexity)

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

---

## Metrics & Success Criteria

### Adoption Metrics
- crates.io downloads (weekly tracking)
- GitHub stars (monthly tracking)
- Issue resolution time (target: <48 hours)

### Quality Metrics
- Test coverage percentage (target: >80%)
- Zero false positives in CI (target: 100%)
- Documentation completeness score (target: 100%)
- Performance: large repo check <5s (target: <10s)

---

## Risk Assessment

### Technical Risks
| Risk | Likelihood | Impact |
|----------------|---------------|
| Large repo performance | Medium | Memory usage, parsing speed |
| Alternative coverage formats | Low | format complexity |
| Dependencies | Low | Multiple platforms, templates |
| CI integration complexity | Low | Multiple platforms |
| Documentation maintenance | Low | Keeping docs in sync with code |

---

## Decision Log

| Date | Decision | Rationale |
|------------|----------|---------|
| 2026-03-12 | Adopted hexagonal architecture | Enables pure domain core, easy testing |
| 2026-03-12 | Multi-crate workspace | Provides clear boundaries and granular publishing |
| 2026-03-12 | LCOV as primary format | Ensures language-agnostic coverage |
| 2026-03-12 | Unified diff format | Provides universal diff source |
| 2026-03-12 | Schema-compliant JSON | Ensures deterministic output and reliable programmatic consumption |

### Future Decisions
| Date | Decision | Likelihood | Rationale |
|------------|----------|---------|---------|
| TBD | Add GitHub Action | High | Official action, easy CI setup |
| TBD | Add global coverage tracking | Medium | Scope creep, requires careful design |
| TBD | Add IDE integration | Low | Limited ecosystem demand, complex implementation |
