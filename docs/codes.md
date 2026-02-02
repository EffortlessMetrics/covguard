# covguard — Codes

This file is the source of truth for code meanings and remediation guidance.

## covguard.diff.coverage_below_threshold
Meaning:
- Diff-scoped coverage percentage is below the configured threshold.

Common causes:
- Missing tests for newly introduced logic
- Coverage tooling excludes the file or module
- Path normalization mismatch causing coverage to not match diff paths

Remediation:
- Add tests that execute the changed lines.
- Fix coverage tooling configuration to include the files.
- Configure path normalization (`--path-strip`) if LCOV uses absolute paths.

## covguard.diff.uncovered_line
Meaning:
- A changed in-scope line has `hits == 0` in LCOV.

Remediation:
- Add/adjust tests to execute the line.
- If the line is intentionally non-executable or coverage is known-bad:
  - use `covguard: ignore` (line-level) OR
  - exclude the path via config.

## covguard.diff.missing_coverage_for_file
Meaning:
- A file contains changed lines but has no LCOV record.

Remediation:
- Ensure coverage generation includes the file.
- Check for generated/vendor paths and exclude them if desired.
- Fix path normalization so `SF:` paths match repo-relative paths.

## covguard.input.invalid_lcov
Meaning:
- LCOV input could not be parsed.

Remediation:
- Verify the coverage generation step produced valid LCOV.
- Upload raw LCOV as an artifact for debugging.
- Ensure the LCOV file is not truncated.

## covguard.input.invalid_diff
Meaning:
- Diff input could not be parsed.

Remediation:
- Ensure the base commit exists in CI (avoid shallow clone issues).
- Use `--diff-file` with a saved patch if base/head is not available.
- Ensure the diff is unified diff format.

## tool.runtime_error
Meaning:
- covguard failed due to a runtime/tool error (I/O, internal error, unexpected parse failure).

Remediation:
- Re-run with raw inputs captured.
- If reproducible, file a bug with:
  - diff patch
  - LCOV file
  - covguard version and OS
