# Path Normalization Rules

All file paths in covguard output are normalized to a canonical form.

## Rules

1. **Repo-relative**: Paths are relative to the repository root, never absolute.
2. **Forward slashes**: Always use `/` as separator, even on Windows.
3. **No `./` prefix**: Leading `./` is stripped.
4. **No trailing slash**: Paths never end with `/`.
5. **LCOV `SF:` paths**: Stripped of configured prefixes (`--path-strip`) before normalization.
