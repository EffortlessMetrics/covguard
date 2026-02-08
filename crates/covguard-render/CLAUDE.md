# covguard-render

Output rendering for Markdown, GitHub annotations, and SARIF.

## Purpose

This crate converts `Report` objects into various output formats for different consumers: human-readable markdown comments, GitHub workflow annotations, and SARIF for static analysis tooling.

## Key Functions

- **`render_markdown(report: &Report) -> String`** - PR comment format
- **`render_annotations(report: &Report) -> String`** - GitHub workflow commands
- **`render_sarif(report: &Report) -> String`** - SARIF 2.1.0 JSON

## Markdown Output

Produces a PR comment with:
- Status emoji (✅ ⚠️ ❌ ⏭️)
- Summary line with coverage percentage
- Table of uncovered lines (path, line, message)
- Reproduce instructions block

## GitHub Annotations

Generates `::error::`, `::warning::`, `::notice::` workflow commands:
```
::error file=src/foo.rs,line=42::Uncovered line
```

## SARIF Output

Produces SARIF 2.1.0 compliant JSON with:
- `SarifReport` - Top-level container
- `SarifRun` - Tool info and results
- `SarifDriver` - Tool name, version, rules
- `SarifResult` - Individual finding with location

Maps severity levels: Error → error, Warn → warning, Info → note

## Helper Functions

- **`status_emoji(status: VerdictStatus) -> &str`** - Map status to emoji

## Testing

- Unit tests for each renderer
- Snapshot tests (insta) for output stability
- Fixture-based tests with expected outputs

## Dependencies

- `covguard-types` - Report types
- `serde` / `serde_json` - SARIF serialization
