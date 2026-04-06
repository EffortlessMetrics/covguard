# Stability Policy

**Effective Date:** 2026-03-29  
**Version:** 0.1.0

---

## Overview

This document defines the stability guarantees, support commitments, and long-term support policy for covguard versions.

---

## Support Timeline

### Current Version: v0.1.x

| Version | Status | Support Level |
|---------|--------|---------------|
| v0.1.x | Active | Full support |
| v0.0.x | End-of-life | None |

### Support Levels

| Level | Description |
|-------|-------------|
| **Full** | Bug fixes, security patches, new features |
| **Security** | Security fixes only |
| **End-of-life** | No support, upgrade recommended |

---

## Version Support Policy

### Pre-v1.0 (0.y.z)

During the pre-v1.0 phase:

- **Latest minor version**: Full support
- **Previous minor version**: Security fixes only
- **Older versions**: End-of-life

Example:
- v0.1.x active → v0.0.x security only
- v0.2.x active → v0.1.x security only, v0.0.x EOL

### Post-v1.0 (1.0.0+)

Once v1.0.0 is released:

- **Latest minor version**: Full support (12 months)
- **Previous minor version**: Security fixes only (6 months)
- **Major versions**: 6 month support window

---

## API Stability

### Stable APIs (Guaranteed)

The following APIs have stability guarantees:

| API | Guarantee |
|-----|-----------|
| CLI exit codes | 0=pass/warn, 1=error, 2=fail |
| Error codes | All documented in `docs/codes.md` |
| Report schema | Validated against `covguard.report.v1.json` |
| Configuration keys | Documented in `docs/configuration.md` |

### Unstable APIs (May Change)

The following are subject to change:

| API | Notes |
|-----|-------|
| Internal crate APIs | May refactor without notice |
| Feature flags | Default-off features unstable |
| Performance characteristics | May optimize without notice |
| Internal error messages | May improve without notice |

---

## Schema Stability

### Current Schemas

| Schema | Version | Status |
|--------|---------|--------|
| Report | v1 | Stable (validated) |
| Sensor | v1 | Stable (validated) |
| Envelope | v1 | Stable (validated) |

### Schema Versioning

- Schemas follow their own versioning
- New schema versions may be added without bumping crate version
- Old schemas remain valid for backward compatibility

---

## Long-Term Support (LTS)

covguard does not currently offer a Long-Term Support (LTS) release model. We release frequently (approximately monthly) and recommend users stay on the latest version.

### Rationale

- Security fixes are backported to supported versions
- New features land frequently in 0.y.z releases
- Migration burden is low (CLI is simple)

---

## Security Updates

### Supported Versions

| Version | Supported | CVE Patches |
|---------|-----------|-------------|
| v0.1.x | ✅ Yes | ✅ Yes |
| v0.0.x | ❌ No | ⚠️ Last release only |

### Reporting Security Issues

If you find a security vulnerability:

1. **Do NOT** open a public issue
2. Email security@effortlessmetrics.com
3. We will respond within 48 hours
4. We will coordinate disclosure with you

### Security Release Process

1. Patch prepared in private
2. Security advisory drafted
3. Release published with CVE
4. Users notified via GitHub Security Advisories

---

## Performance Stability

### Benchmarks

We track performance via Criterion benchmarks in `crates/covguard-benchmarks/`.

| Benchmark | Target |
|-----------|--------|
| Diff parsing | <100ms for 1000 files |
| LCOV parsing | <200ms for 1000 files |
| Policy evaluation | <50ms for typical PR |
| Report generation | <100ms |

### Performance Regression

If a performance regression is detected:

1. Issue filed with benchmark data
2. Fix targeted for next release
3. Performance improvements documented in changelog

---

## Compatibility

### Platform Support

| Platform | Support Level |
|----------|---------------|
| Linux (glibc 2.31+) | Full |
| macOS 12+ | Full |
| Windows 10+ | Full |
| Other Unix-like | Best effort |

### Rust Version

- **Minimum Supported Rust Version (MSRV)**: 1.92
- MSRV may increase in minor versions
- MSRV changes documented in changelog

### Dependencies

- We pin dependencies in `Cargo.lock` for reproducibility
- Security advisories applied promptly
- Major dependency changes announced in advance

---

## Deprecation Policy

See [Breaking Change Policy](./breaking-policy.md) for detailed deprecation process.

### Quick Summary

1. **Announce**: Deprecation in changelog + warning in tool
2. **Support**: Old API works for at least 1 minor release
3. **Remove**: Old API removed in next minor/major version

---

## Upgrade Path

### Within 0.y.z

- Read CHANGELOG.md for changes
- Most changes are additive
- Breaking changes announced in advance

### To v1.0.0

- Review breaking changes in release notes
- Migration guide provided
- Schema changes documented

---

## Monitoring Stability

### What We Monitor

| Metric | How |
|--------|-----|
| Test pass rate | CI runs on every PR |
| BDD scenario coverage | 70+ scenarios |
| Fuzz tests | 3 fuzz targets, run in CI |
| Mutation tests | cargo-mutants in CI |
| Schema validation | xtask conform tests |

### What Users Can Monitor

- Watch [GitHub Releases](https://github.com/EffortlessMetrics/covguard/releases)
- Subscribe to [CHANGELOG.md](../CHANGELOG.md)
- Monitor [Security Advisories](https://github.com/EffortlessMetrics/covguard/security/advisories)

---

## Related Documents

- [Breaking Change Policy](./breaking-policy.md) - Change process
- [Roadmap](./roadmap.md) - Release schedule
- [CHANGELOG.md](../CHANGELOG.md) - Release history
- [codes.md](./codes.md) - Error code reference
