# covguard-domain

Pure domain logic for covguard.

## Responsibility

`covguard-domain` evaluates changed lines against coverage under policy and returns findings, metrics, and verdict.

## Design Constraint

- No filesystem, process, or network side effects
- Deterministic finding ordering

## Main API

- `evaluate(EvalInput) -> EvalOutput`
- Policy types: `Policy`, `Scope`, `FailOn`, `MissingBehavior`
