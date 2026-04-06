# covguard — Codes

This file is the source of truth for code meanings and remediation guidance.

## Enhanced Error Format

All errors follow a consistent format with actionable guidance:

```
Error [CODE]: Brief description
  Context: <specific context, e.g., "at line 5">
  
  Hint: <remediation hint with actionable guidance>
  
  See: <documentation URL>
```

## Error Codes Reference

| Code | Description | Exit Code |
|------|-------------|-----------|
| `covguard.diff.coverage_below_threshold` | Diff coverage below threshold | 2 |
| `covguard.diff.uncovered_line` | Uncovered changed line | 2 |
| `covguard.diff.missing_coverage_for_file` | Missing coverage for file | 2 |
| `covguard.input.invalid_lcov` | Invalid LCOV input | 1 |
| `covguard.input.invalid_diff` | Invalid diff input | 1 |
| `tool.runtime_error` | Tool runtime error | 1 |

## Exit Codes

- `0` — Pass (or warn when not fail-configured)
- `1` — Tool/runtime error (I/O, parse failure)
- `2` — Policy fail (blocking findings)

---

## covguard.diff.coverage_below_threshold

**Meaning:**
- Diff-scoped coverage percentage is below the configured threshold.

**Common causes:**
- Missing tests for newly introduced logic
- Coverage tooling excludes the file or module
- Path normalization mismatch causing coverage to not match diff paths

**Remediation:**
- Add tests that execute the changed lines.
- Fix coverage tooling configuration to include the files.
- Configure path normalization (`--path-strip`) if LCOV uses absolute paths.

**Example (CLI):**
```
Error [covguard.diff.coverage_below_threshold]: Diff coverage below threshold
  Diff coverage 60.0% is below threshold 80.0%.

  Hint: Add tests for changed lines, or adjust your configured threshold.
        If LCOV `SF:` paths are absolute or use a different root, use `--path-strip` (repeatable) so coverage paths match repo paths.
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#coverage_below_threshold
```

---

## covguard.diff.uncovered_line

**Meaning:**
- A changed in-scope line has `hits == 0` in LCOV.

**Remediation:**
- Add/adjust tests to execute the line.
- If the line is intentionally non-executable or coverage is known-bad:
  - use `covguard: ignore` (line-level) OR
  - exclude the path via config.

**Example (CLI):**
```
Error [covguard.diff.uncovered_line]: Uncovered changed line
  src/lib.rs:42 has 0 hits

  Hint: Add tests that execute the changed line.
        If the line is intentionally uncovered, use `covguard: ignore` (line/block) or exclude the path via `covguard.toml`.
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#uncovered_line
```

---

## covguard.diff.missing_coverage_for_file

**Meaning:**
- A file contains changed lines but has no LCOV record.

**Remediation:**
- Ensure coverage generation includes the file.
- Check for generated/vendor paths and exclude them if desired.
- Fix path normalization so `SF:` paths match repo-relative paths.

**Example (CLI):**
```
Error [covguard.diff.missing_coverage_for_file]: Missing coverage for file
  src/new_module.rs has changes but no coverage data

  Hint: Ensure your coverage generation includes the file.
        If LCOV `SF:` paths don't match repo-relative paths, use `--path-strip`.
        If the file is generated/vendor content, exclude it via `covguard.toml`.
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#missing_coverage_for_file
```

---

## covguard.input.invalid_lcov

**Meaning:**
- LCOV input could not be parsed.

**Remediation:**
- Ensure your coverage tool generated an LCOV `.info` file.
- LCOV records must include `SF:<path>` lines before any `DA:<line>,<hits>`.
- For Rust: `cargo llvm-cov --lcov --output-path coverage.info`
- For gcov/lcov: `lcov --capture --directory . --output-file coverage.info`
- If the file looks truncated, re-run coverage and upload the raw LCOV as an artifact.

**Example (CLI):**
```
Error [covguard.input.invalid_lcov]: Invalid LCOV input
  DA record at line 5 without preceding SF record

  Hint: Ensure your coverage tool generated an LCOV `.info` file.
        - LCOV records must include `SF:<path>` lines before any `DA:<line>,<hits>`.
        - For Rust: `cargo llvm-cov --lcov --output-path coverage.info`
        - For gcov/lcov: `lcov --capture --directory . --output-file coverage.info`
        If the file looks truncated, re-run coverage and upload the raw LCOV as an artifact.
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#invalid_lcov
```

**Before/After Example:**

Before (malformed LCOV):
```lcov
DA:1,5
DA:2,0
end_of_record
```

After (valid LCOV):
```lcov
TN:
SF:src/lib.rs
DA:1,5
DA:2,0
end_of_record
```

---

## covguard.input.invalid_diff

**Meaning:**
- Diff input could not be parsed.

**Remediation:**
- Ensure the base commit exists in CI (avoid shallow clone issues).
- Provide a unified diff via `--diff-file <path>`, `--base`+`--head`, or stdin.
- For GitHub Actions, use `actions/checkout` with `fetch-depth: 0`.

**Example (CLI):**
```
Error [covguard.input.invalid_diff]: Invalid diff input
  Invalid hunk header at line 42: '@@ -invalid @@'

  Hint: Provide a unified diff via one of:
        - `--diff-file <path>` (or `--diff-file -` to read from stdin)
        - `--base <sha>` + `--head <sha>` (requires those commits locally)
        In CI, ensure the base commit exists (e.g., `actions/checkout` with `fetch-depth: 0`).
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#invalid_diff
```

**Before/After Example:**

Before (invalid diff):
```diff
diff --git a/src/lib.rs b/src/lib.rs
@@ invalid @@
+fn new_function() {}
```

After (valid unified diff):
```diff
diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,1 @@
+fn new_function() {}
```

**Common CI Fix:**

Before (shallow clone):
```yaml
- uses: actions/checkout@v4
```

After (full history for git diff):
```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

---

## tool.runtime_error

**Meaning:**
- covguard failed due to a runtime/tool error (I/O, internal error, unexpected parse failure).

**Remediation:**
- Re-run with `--raw` to capture inputs under `artifacts/covguard/raw/`.
- If reproducible, file a bug and attach:
  - diff.patch
  - lcov.info
  - covguard version + OS

**Example (CLI):**
```
Error [tool.runtime_error]: Tool runtime error
  covguard failed due to a runtime error.

  Hint: Re-run with `--raw` to capture inputs under `artifacts/covguard/raw/`.
        If reproducible, file a bug with diff.patch + lcov.info + covguard version + OS.
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#runtime_error
```

**Before/After Example:**

Before (file not found):
```bash
$ covguard check --diff-file missing.patch --lcov coverage.info --out report.json
Error [tool.runtime_error]: Tool runtime error
  Failed to read file 'missing.patch': No such file or directory

  Hint: Re-run with `--raw` to capture inputs under `artifacts/covguard/raw/`.
        If reproducible, file a bug and attach:
        - diff.patch
        - lcov.info
        - covguard version + OS
  See: https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md#runtime_error
```

After (file exists):
```bash
$ covguard check --diff-file valid.patch --lcov coverage.info --out report.json
# Exit code 0 (pass) or 2 (policy fail)
```
