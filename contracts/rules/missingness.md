# Input Missingness Semantics

## Status Values

| Status | Meaning |
|--------|---------|
| `available` | Input bytes were present and consumed |
| `unavailable` | Input bytes were not present (file missing, not provided) |
| `skipped` | Input was present but skipped by configuration |

## Key Rules

- **Validity is conveyed by findings, not capabilities.** A status of `available` means the bytes were present — it says nothing about whether the content was valid. Invalid LCOV that was read is still `available`; the invalidity surfaces as a `covguard.input.invalid_lcov` finding.

- **`reason` is a lowercase snake_case token** from the token registry (`contracts/rules/tokens.md`). It is only populated when the status is `unavailable` or `skipped`.

- **Both `diff` and `coverage` keys are always present** in the `capabilities.inputs` block when sensor schema is active.
