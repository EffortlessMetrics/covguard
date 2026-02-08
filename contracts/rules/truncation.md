# Truncation Behavior Contract

When `--max-findings N` is set, covguard truncates the findings array after sorting.

## Rules

1. Findings are sorted first (per determinism contract), then truncated to `N`.
2. `verdict.counts` always reflects the **full** (pre-truncation) set.
3. When truncated, `data.truncation` is populated:
   - `findings_truncated: true`
   - `shown`: number of findings in the array
   - `total`: total findings before truncation
4. `"truncated"` is added to `verdict.reasons[]`.
5. `max_findings = 0` is valid: produces an empty findings array with truncation metadata.
6. When `max_findings` is not set or findings count <= limit, `data.truncation` is omitted.
