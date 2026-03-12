# covguard-paths

Tiny crate containing shared path normalization logic for covguard adapters.

It currently exposes:

- `normalize_diff_path` for diff header file names.
- `normalize_coverage_path` for LCOV `SF:` file entries.
- `normalize_coverage_path_with_strip` for LCOV entries with configured strip prefixes.

