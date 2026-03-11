# covguard-directives

Small, isolated helpers for directive-aware behavior in covguard.

This crate intentionally stays narrow and side-effect free:

- detect whether a source line contains a `covguard: ignore` directive,
- scan changed ranges for ignore directives using a `RepoReader`.
