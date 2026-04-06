# Breaking Change Policy

**Effective Date:** 2026-03-29  
**Version:** 0.1.0

---

## Overview

This document defines the breaking change policy for covguard, including what constitutes a breaking change, how we announce changes, and the guarantees we provide to users during the pre-v1.0 (0.y.z) phase and beyond.

## Versioning Strategy

covguard follows [Semantic Versioning 2.0.0](https://semver.org/) (SemVer):

- **MAJOR** (x.0.0): Incompatible API changes
- **MINOR** (0.y.0): New backward-compatible functionality
- **PATCH** (0.0.z): Backward-compatible bug fixes

### Schema Versioning

Schema versions (`covguard.report.v1`, `sensor.report.v1`, `receipt.envelope.v1`) are independent of crate versions. Schema changes follow their own versioning and will be clearly documented.

---

## Pre-v1.0 Phase (0.y.z)

During the pre-v1.0 phase, covguard is in active development. We provide the following guarantees:

### Current Guarantees (v0.1.x)

| Aspect | Guarantee |
|--------|-----------|
| **Exit codes** | Stable: 0=pass/warn, 1=error, 2=fail |
| **Error codes** | Stable: All codes documented in `docs/codes.md` |
| **Schema** | Stable: v1 schema validated for all reports |
| **CLI flags** | Additive: New flags may be added |
| **Behavior** | Best effort: Breaking changes possible with notice |

### What Can Change Without Notice

- Internal crate structure (microcrate refactoring)
- Internal function signatures (non-public APIs)
- Documentation content
- Optional features (default-off features may change)
- Performance characteristics

### What Requires Deprecation Notice

- CLI flag removal or semantic changes
- Configuration key removal
- Output format changes (report.json structure)
- Exit code behavior changes

### What Constitutes a Major Version Bump

- Removal or semantic change to documented CLI flags
- Changes to exit code mapping
- Schema version bumps (v1 → v2)
- Removal of supported coverage formats (LCOV, JaCoCo, coverage.py)
- Removal of supported diff sources (patch files, git refs)

---

## Deprecation Process

When we need to remove or change functionality:

### 1. Announce Deprecation (Minimum 1 Minor Release)

```markdown
## Deprecation Notice (v0.2.0)

The `--old-flag` flag is deprecated and will be removed in v0.3.0.

**Migration**: Use `--new-flag` instead.
```

### 2. Emit Warnings

During the deprecation period, the tool should:
- Print a deprecation warning to stderr when deprecated flag is used
- Continue to function as before (no breaking behavior)
- Document the deprecation in output

### 3. Remove in Next Minor/Major

- After at least 1 minor release with deprecation warning
- Major version bump if removing core functionality
- Minor version bump if adding replacement functionality

---

## Post-v1.0 Phase (1.0.0+)

Once we reach v1.0.0, we provide stronger guarantees:

### v1.0.0+ Guarantees

| Aspect | Guarantee |
|--------|-----------|
| **CLI flags** | Stable for MAJOR version |
| **Config keys** | Stable for MAJOR version |
| **Exit codes** | Stable forever |
| **Error codes** | Stable forever |
| **Schema** | Stable forever (new versions, not breaking changes) |
| **Behavior** | Consistent within MAJOR version |

### Backward Compatibility

- New MINOR versions may add features but not break existing behavior
- New PATCH versions may fix bugs but not change behavior unexpectedly
- MAJOR versions may break backward compatibility with proper migration guide

---

## Schema Stability

### Current Schemas

- `covguard.report.v1.json` - Main report format
- `sensor.report.v1.json` - Sensor schema with capabilities
- `receipt.envelope.v1.json` - Envelope wrapper

### Schema Guarantees

| Phase | Guarantee |
|-------|-----------|
| Pre-v1.0 | Schemas validated, but may change |
| v1.0.0+ | Schemas stable within MAJOR version |

### Schema Deprecation

- Old schema versions remain valid for at least 1 MAJOR version
- Deprecation announced with clear migration path
- Tool may accept old schemas with warning

---

## Migration Guide Process

For any breaking change:

1. **Document the change** in CHANGELOG.md
2. **Provide migration path** in release notes
3. **Update documentation** with new usage
4. **Emit helpful errors** pointing to documentation

Example migration guide section:

```markdown
## Migration Guide: v0.1.0 → v0.2.0

### Changed: `--old-flag` → `--new-flag`

**Before:**
```bash
covguard check --old-flag value
```

**After:**
```bash
covguard check --new-flag value
```
```

---

## Requesting Breaking Changes

If you're a user affected by a potential breaking change:

1. Check the [issues](https://github.com/EffortlessMetrics/covguard/issues)
2. Open a new issue if not found
3. Label with `breaking-change-request`
4. Provide use case and migration suggestion

---

## Exceptions

We reserve the right to make emergency fixes without following the deprecation process if:

- Security vulnerability requires immediate fix
- Critical bug causes data loss or corruption
- Legal compliance requires immediate change

Such changes will be documented retrospectively in release notes.

---

## Related Documents

- [Roadmap](./roadmap.md) - Release schedule and feature planning
- [Stability Policy](./stability.md) - Detailed stability guarantees
- [CHANGELOG.md](../CHANGELOG.md) - Release history
- [codes.md](./codes.md) - Error code reference
