# covguard Project Status

**Last Updated:** 2026-03-16
**Version:** 0.1.0 (released)

## Executive Summary

covguard v0.1.0 has been released with diff-scoped coverage gating for pull requests. It supports LCOV coverage format, unified diff parsing, configurable policies, and multiple output formats (JSON, Markdown, SARIF, GitHub Annotations).

Work toward v0.2.0 (enhanced ergonomics) and v0.3.0 (extended integrations) is in progress on feature branches.

## Released

### v0.1.0 Release (2026-03-12)
- [x] All 20 crates published to crates.io
- [x] CHANGELOG.md updated for v0.1.0
- [x] Cargo.toml metadata complete for all crates
- [x] Installation: `cargo install covguard-cli`

### Documentation
- [x] Project README.md comprehensive update
- [x] CONTRIBUTING.md created
- [x] SECURITY.md created
- [x] docs/roadmap.md with feature tracking
- [x] docs/now-next-later.md with metrics and decision log
- [x] 19 Architecture Decision Records (ADR-001 through ADR-019)
- [x] docs/INDEX.md updated with all documentation

## In Progress

### v0.2.0 — Enhanced Ergonomics
- [x] Stdin diff input support (`--diff-file -`, `-` from stdin)
- [ ] JaCoCo XML coverage parser (parser code exists, not yet wired to CLI)
- [ ] coverage.py JSON parser (parser code exists, not yet wired to CLI)
- [ ] Enhanced error messages with remediation hints
- [x] Performance profiling with `--timing` flag
- [ ] Criterion benchmarks for performance tracking

### v0.3.0 — Extended Integration
- [ ] Official GitHub Action (draft exists, needs CLI alignment)
- [ ] GitLab CI templates (drafts exist, need CLI alignment)
- [ ] Multi-format orchestrator support (parsers exist, orchestrator is LCOV-only)

## Outstanding Work

### High Priority
1. **Wire multi-format parsers to CLI** — Add `--jacoco`, `--coverage-py` flags or `--format` flag
2. **Fix orchestrator** — Route through appropriate parser based on format
3. **Fix integration wrappers (Action/templates)** — Publish and align CLI usage
4. **Fix coverage.py semantics in parser + evaluator path** — Ensure zero-coverage files map to uncovered lines when reported

### Medium Priority (v1.0.0)
1. Schema stability guarantee
2. Breaking change policy documentation
3. Long-term support commitment
4. Comprehensive integration testing

### Low Priority (Backlog)
1. Video tutorials
2. Migration guides
3. IDE integration exploration
4. Global coverage tracking (opt-in feature)

## Metrics

| Metric | Current | Target |
|--------|---------|--------|
| crates.io downloads | Tracking | Growth |
| Test coverage | ~80% | >80% |
| Documentation completeness | ~90% | 100% |
| Open issues | TBD | <10 |
| Coverage formats | 1 shipped (LCOV), 2 draft (JaCoCo, coverage.py) | 3 |
| CI integrations | 0 shipped, 2 draft (GitHub, GitLab) | 2 |

## References

- [Roadmap](roadmap.md)
- [Now/Next/Later](now-next-later.md)
- [ADR Index](adr/README.md)
