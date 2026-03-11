# covguard-adapters-coverage

Coverage adapter crate for covguard.

## What It Does

- Parses LCOV text into normalized coverage maps
- Applies optional path-prefix stripping during normalization
- Merges multiple LCOV maps deterministically

## Main API

- `parse_lcov`
- `parse_lcov_with_strip`
- `merge_coverage`
- `LcovCoverageProvider` (implements `covguard-ports::CoverageProvider`)
