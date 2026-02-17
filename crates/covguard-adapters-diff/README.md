# covguard-adapters-diff

Diff adapter crate for covguard.

## What It Does

- Parses unified diffs into normalized changed-line ranges
- Detects binary file entries in patch metadata
- Loads diff text from `git diff <base> <head>`

## Main API

- `parse_patch`
- `parse_patch_with_meta`
- `load_diff_from_git`
- `GitDiffProvider` (implements `covguard-ports::DiffProvider`)
