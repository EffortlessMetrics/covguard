//! Artifact persistence adapters for covguard outputs.
//!
//! This crate centralizes filesystem output behavior for reports and related
//! artifacts so CLI and other adapters can share the same contract.

use std::path::Path;

use covguard_types::{
    compute_fingerprint, Capabilities, Finding, InputCapability, InputStatus, Inputs, InputsCapability,
    Report, ReportData, Run, Severity, Tool, Verdict, VerdictCounts, VerdictStatus, CHECK_ID_RUNTIME,
    CODE_RUNTIME_ERROR,
};
use chrono::Utc;
use thiserror::Error;

const RAW_ARTIFACTS_DIR: &str = "artifacts/covguard/raw";

/// Errors encountered while writing artifacts.
#[derive(Debug, Error)]
pub enum ArtifactWriteError {
    /// Failed to create a parent directory for a path.
    #[error("Failed to create directory '{path}': {source}")]
    DirCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed writing an output file.
    #[error("Failed to write file '{path}': {source}")]
    FileWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to serialize report JSON.
    #[error("Failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Concrete artifact writer used by the CLI and other adapters.
#[derive(Debug, Default)]
pub struct FsArtifactWriter;

impl FsArtifactWriter {
    /// Create a new artifact writer.
    pub fn new() -> Self {
        Self
    }
}

/// Write a domain report JSON payload to disk.
pub fn write_report(path: &str, report: &Report) -> Result<(), ArtifactWriteError> {
    let body = serde_json::to_string_pretty(report)?;
    write_text(path, &body)
}

/// Write fallback/runtime output as a JSON report.
pub fn write_fallback_receipt(
    out_path: &str,
    error_message: &str,
    diff_reason: &str,
    coverage_reason: &str,
) -> Result<(), ArtifactWriteError> {
    let report = fallback_report(error_message, diff_reason, coverage_reason);
    write_report(out_path, &report)
}

/// Write raw lint/repro inputs for debugging.
pub fn write_raw_artifacts(
    diff_content: &str,
    lcov_texts: &[String],
) -> Result<(), ArtifactWriteError> {
    write_raw_artifacts_to(Path::new(RAW_ARTIFACTS_DIR), diff_content, lcov_texts)
}

/// Write raw lint/repro inputs to a supplied directory.
pub fn write_raw_artifacts_to(
    raw_dir: &Path,
    diff_content: &str,
    lcov_texts: &[String],
) -> Result<(), ArtifactWriteError> {
    if !raw_dir.exists() {
        ensure_directory(raw_dir)?;
    }

    let diff_path = raw_dir.join("diff.patch");
    let lcov_path = raw_dir.join("lcov.info");
    let combined = lcov_texts.join("\n");

    write_text_path(&diff_path, diff_content)?;
    write_text_path(&lcov_path, &combined)?;
    Ok(())
}

/// Ensure the parent directory for a path exists.
pub fn ensure_parent_dir(path: &str) -> Result<(), ArtifactWriteError> {
    ensure_parent_dir_path(Path::new(path))
}

/// Ensure the parent directory for a path exists.
fn ensure_parent_dir_path(path: &Path) -> Result<(), ArtifactWriteError> {
    let parent = path.parent();
    if let Some(parent) = parent
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        ensure_directory(parent)?;
    }
    Ok(())
}

fn write_text_path(path: &Path, body: &str) -> Result<(), ArtifactWriteError> {
    ensure_parent_dir_path(path)?;
    std::fs::write(path, body).map_err(|source| ArtifactWriteError::FileWrite {
        path: path.display().to_string(),
        source,
    })
}

fn ensure_directory(path: &Path) -> Result<(), ArtifactWriteError> {
    std::fs::create_dir_all(path).map_err(|source| ArtifactWriteError::DirCreate {
        path: path.display().to_string(),
        source,
    })
}

/// Write markdown or SARIF output text to disk.
pub fn write_text(path: &str, body: &str) -> Result<(), ArtifactWriteError> {
    write_text_path(Path::new(path), body)
}

impl FsArtifactWriter {
    /// Write a domain report JSON payload to disk.
    pub fn write_report(&self, path: &str, report: &Report) -> Result<(), ArtifactWriteError> {
        write_report(path, report)
    }

    /// Write fallback/runtime output as a JSON report.
    pub fn write_fallback_receipt(
        &self,
        out_path: &str,
        error_message: &str,
        diff_reason: &str,
        coverage_reason: &str,
    ) -> Result<(), ArtifactWriteError> {
        write_fallback_receipt(out_path, error_message, diff_reason, coverage_reason)
    }

    /// Write markdown or SARIF output text to disk.
    pub fn write_text(&self, path: &str, body: &str) -> Result<(), ArtifactWriteError> {
        write_text(path, body)
    }

    /// Write raw lint/repro inputs for debugging.
    pub fn write_raw_artifacts(
        &self,
        diff_content: &str,
        lcov_texts: &[String],
    ) -> Result<(), ArtifactWriteError> {
        write_raw_artifacts(diff_content, lcov_texts)
    }

    /// Write raw lint/repro inputs to a supplied directory.
    pub fn write_raw_artifacts_to(
        &self,
        raw_dir: &Path,
        diff_content: &str,
        lcov_texts: &[String],
    ) -> Result<(), ArtifactWriteError> {
        write_raw_artifacts_to(raw_dir, diff_content, lcov_texts)
    }

    /// Ensure the parent directory for a path exists.
    pub fn ensure_parent_dir(&self, path: &str) -> Result<(), ArtifactWriteError> {
        ensure_parent_dir(path)
    }
}

fn fallback_report(
    error_message: &str,
    diff_reason: &str,
    coverage_reason: &str,
) -> Report {
    let started_at = Utc::now();
    let runtime_fp = compute_fingerprint(&[CODE_RUNTIME_ERROR, "covguard"]);

    Report {
        schema: "sensor.report.v1".to_string(),
        tool: Tool {
            name: "covguard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: None,
        },
        run: Run {
            started_at: started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ended_at: Some(started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            duration_ms: Some(0),
            capabilities: Some(Capabilities {
                inputs: InputsCapability {
                    diff: InputCapability {
                        status: InputStatus::Unavailable,
                        reason: Some(diff_reason.to_string()),
                    },
                    coverage: InputCapability {
                        status: InputStatus::Unavailable,
                        reason: Some(coverage_reason.to_string()),
                    },
                },
            }),
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 1,
            },
            reasons: vec![CODE_RUNTIME_ERROR.to_string()],
        },
        findings: vec![Finding {
            severity: Severity::Error,
            check_id: CHECK_ID_RUNTIME.to_string(),
            code: CODE_RUNTIME_ERROR.to_string(),
            message: format!("covguard failed due to a runtime error: {error_message}"),
            location: None,
            data: None,
            fingerprint: Some(runtime_fp),
        }],
        data: ReportData {
            scope: "added".to_string(),
            threshold_pct: 0.0,
            changed_lines_total: 0,
            covered_lines: 0,
            uncovered_lines: 0,
            missing_lines: 0,
            ignored_lines_count: 0,
            excluded_files_count: 0,
            diff_coverage_pct: 0.0,
            inputs: Inputs {
                diff_source: "unknown".to_string(),
                diff_file: None,
                base: None,
                head: None,
                lcov_paths: vec![],
            },
            debug: None,
            truncation: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn builds_fallback_receipt() {
        let report = super::fallback_report("boom", "missing_diff", "missing_lcov");

        assert_eq!(report.schema, "sensor.report.v1");
        assert_eq!(report.verdict.status, VerdictStatus::Fail);
        assert_eq!(
            report.findings.first().expect("finding").message,
            "covguard failed due to a runtime error: boom"
        );
    }

    #[test]
    fn writes_raw_artifacts_to_explicit_dir() {
        let dir = PathBuf::from(std::env::temp_dir()).join("covguard-adapters-artifacts-raw");
        let _ = fs::remove_dir_all(&dir);
        write_raw_artifacts_to(&dir, "diff", &["lcov".to_string()]).expect("write raw");

        assert_eq!(fs::read_to_string(dir.join("diff.patch")).expect("diff"), "diff");
        assert_eq!(fs::read_to_string(dir.join("lcov.info")).expect("lcov"), "lcov");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensures_parent_directory() {
        let path = std::env::temp_dir().join("covguard-adapters-artifacts").join("a.json");
        let _ = fs::remove_dir_all(path.parent().expect("parent"));
        ensure_parent_dir(path.to_str().unwrap()).expect("ensure parent");
        assert!(path.parent().expect("parent").exists());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn writes_fallback_receipt() {
        let out = std::env::temp_dir().join("covguard-adapters-artifacts-receipt.json");
        let _ = fs::remove_file(&out);
        write_fallback_receipt(out.to_str().unwrap(), "boom", "missing_diff", "missing_lcov")
            .expect("write receipt");
        let body = fs::read_to_string(&out).expect("read");
        assert!(body.contains("\"sensor.report.v1\""));
        let _ = fs::remove_file(&out);
    }

    #[test]
    fn writer_api_is_usable() {
        let writer = FsArtifactWriter::new();
        let out = std::env::temp_dir().join("covguard-adapters-artifacts-writer.json");
        let raw_dir = std::env::temp_dir().join("covguard-adapters-artifacts-writer-raw");
        let _ = fs::remove_file(&out);
        let _ = fs::remove_dir_all(&raw_dir);

        writer
            .write_fallback_receipt(
                out.to_str().unwrap(),
                "boom",
                "missing_diff",
                "missing_lcov",
            )
            .expect("write fallback");
        writer
            .write_raw_artifacts_to(&raw_dir, "diff", &["lcov".to_string()])
            .expect("write raw");
        assert!(out.exists());
        assert!(raw_dir.join("diff.patch").exists());
        assert!(raw_dir.join("lcov.info").exists());

        let _ = fs::remove_file(&out);
        let _ = fs::remove_dir_all(&raw_dir);
    }
}
