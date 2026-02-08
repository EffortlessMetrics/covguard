# Reason Token Registry

All `reason` values in capabilities and `verdict.reasons[]` entries must be lowercase snake_case tokens from this registry.

| Token | Context | Meaning |
|-------|---------|---------|
| `missing_lcov` | capability reason, verdict reason | LCOV coverage data was not provided |
| `missing_diff` | capability reason | Diff input was not provided |
| `no_changed_lines` | verdict reason | Diff contained no changed lines in scope |
| `diff_covered` | verdict reason | All diff lines are covered |
| `uncovered_lines` | verdict reason | Some changed lines are uncovered |
| `below_threshold` | verdict reason | Diff coverage % below configured threshold |
| `tool_error` | capability reason, verdict reason | A tool/runtime error occurred |
| `skipped` | verdict reason | Evaluation was skipped (e.g., missing inputs) |
| `truncated` | verdict reason | Findings were truncated due to `max_findings` limit |

## Pattern

All tokens must match: `^[a-z0-9_]+$`
