# covguard-ports

Hexagonal boundary contracts for covguard.

## What This Crate Contains

- `DiffProvider` trait
- `CoverageProvider` trait
- `RepoReader` trait
- `Clock` trait
- Shared boundary aliases (`ChangedRanges`, `CoverageMap`)

## Intended Usage

Implement these traits in adapters, then wire them into `covguard-app`.
