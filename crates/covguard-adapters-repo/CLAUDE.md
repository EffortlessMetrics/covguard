# covguard-adapters-repo

Filesystem-backed repository-reading adapter.

## Purpose

Implements `RepoReader` from `covguard-ports` so `covguard-app` can detect ignore directives from working-tree files without owning filesystem concerns.

## Key Type

- `FsRepoReader` - Caching file reader rooted at a repo path

## Notes

- Paths may be relative to the configured root or absolute.
- Reading failures should be handled as "line unavailable" (`None`), not panics.