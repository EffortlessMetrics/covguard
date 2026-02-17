# covguard-adapters-repo

Repository reader adapter for covguard.

## What It Does

- Provides `FsRepoReader` for reading source lines from disk
- Supports relative paths (repo root) and absolute paths
- Caches file lines for repeated directive checks

## Intended Usage

Used by `covguard-app` to detect `covguard: ignore` directives.
