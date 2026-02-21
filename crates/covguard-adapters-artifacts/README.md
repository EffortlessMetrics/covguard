# covguard-adapters-artifacts

Filesystem adapters for covguard artifact output.

This crate owns side effects for:

- Writing canonical JSON receipts (`report.json`)
- Writing rendered comment outputs (markdown / SARIF)
- Writing raw repro artifacts under `artifacts/covguard/raw`

The adapter provides both convenience free functions and a lightweight
`FsArtifactWriter` handle for dependency-injected wiring.

## Public API

- `write_report`
- `write_fallback_receipt`
- `write_text`
- `write_raw_artifacts`
- `write_raw_artifacts_to`
- `ensure_parent_dir`
 

## Example

```rust
use covguard_adapters_artifacts::{FsArtifactWriter, write_fallback_receipt};
use covguard_types::Report;

let writer = FsArtifactWriter::new();
let report = Report::default();
writer.write_report("artifacts/covguard/report.json", &report)?;
writer.write_text("artifacts/covguard/comment.md", "# covguard report")?;
# Ok::<(), covguard_adapters_artifacts::ArtifactWriteError>(())
```

