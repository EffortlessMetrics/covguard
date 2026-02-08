//! covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).
//!
//! This CLI tool checks whether changed lines in a pull request are covered by tests.

use clap::{Parser, Subcommand, ValueEnum};
use covguard_config::{
    CliOverrides, Profile, Scope as ConfigScope, discover_config, load_config, resolve_config,
};
use covguard_core::{
    AppError, CheckRequest, FailOn, FsRepoReader, MissingBehavior, SystemClock,
    check_with_clock_and_reader,
};
use covguard_types::{
    CHECK_ID_RUNTIME, CODE_RUNTIME_ERROR, Capabilities, Finding, InputCapability, InputStatus,
    Inputs, InputsCapability, REASON_MISSING_DIFF, REASON_MISSING_LCOV, REASON_TOOL_ERROR, Report,
    ReportData, Run, SENSOR_SCHEMA_ID, Scope, Tool, Verdict, VerdictCounts, VerdictStatus,
    compute_fingerprint, explain,
};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).
#[derive(Parser)]
#[command(name = "covguard")]
#[command(
    about = "covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF)."
)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// CLI operation mode
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum CliMode {
    /// Standard mode: exit based on verdict (0=pass/warn, 2=fail, 1=error)
    #[default]
    Standard,
    /// Cockpit mode: exit 0 if receipt written, exit 1 only on crash
    Cockpit,
}

/// CLI scope option
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliScope {
    Added,
    Touched,
}

/// CLI profile option
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliProfile {
    Oss,
    Moderate,
    Team,
    Strict,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Check diff coverage
    Check {
        /// Operation mode (standard: exit based on verdict, cockpit: exit 0 if receipt written)
        #[arg(long, value_enum, default_value = "standard")]
        mode: CliMode,

        /// Path to diff/patch file
        #[arg(long)]
        diff_file: Option<String>,

        /// Base git ref (alternative to --diff-file)
        #[arg(long)]
        base: Option<String>,

        /// Head git ref (alternative to --diff-file)
        #[arg(long)]
        head: Option<String>,

        /// Path to LCOV coverage file (repeatable, required in standard mode)
        #[arg(long)]
        lcov: Vec<String>,

        /// Output path for report JSON
        #[arg(long, default_value = "artifacts/covguard/report.json")]
        out: String,

        /// Output path for markdown comment
        #[arg(long)]
        md: Option<String>,

        /// Output path for SARIF report
        #[arg(long)]
        sarif: Option<String>,

        /// Save raw diff and LCOV inputs to artifacts/covguard/raw
        #[arg(long)]
        raw: bool,

        /// Repo root for diff and ignore directive reading
        #[arg(long)]
        root: Option<String>,

        /// Path to config file (default: auto-discover covguard.toml)
        #[arg(long, short = 'c')]
        config: Option<String>,

        /// Configuration profile (overrides config file)
        #[arg(long, value_enum)]
        profile: Option<CliProfile>,

        /// Scope of lines to check (overrides config file)
        #[arg(long, value_enum)]
        scope: Option<CliScope>,

        /// Minimum diff coverage percentage (0-100, overrides config file)
        #[arg(long)]
        threshold: Option<f64>,

        /// Disable ignore directives
        #[arg(long)]
        no_ignore: bool,

        /// Prefix to strip from LCOV SF paths (repeatable)
        #[arg(long)]
        path_strip: Vec<String>,

        /// Maximum number of findings to include in report (truncation)
        #[arg(long)]
        max_findings: Option<usize>,

        /// Output path for full domain payload JSON (cockpit mode only)
        #[arg(long)]
        payload: Option<String>,
    },
    /// Explain an error code
    Explain {
        /// Error code to explain
        code: String,
    },
}

/// CLI errors
#[derive(Debug, Error)]
enum CliError {
    #[error("Must provide either --diff-file or both --base and --head")]
    MissingDiffSource,

    #[error("Cannot use --diff-file together with --base/--head")]
    ConflictingDiffSource,

    #[error("--lcov is required in standard mode")]
    MissingLcov,

    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to write file '{path}': {source}")]
    FileWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to create directory '{path}': {source}")]
    DirCreate {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("Failed to load config: {0}")]
    ConfigLoad(String),

    #[error("{0}")]
    App(#[from] AppError),
}

/// Exit codes following the specification:
/// - 0: Pass (or warn when not fail-configured)
/// - 1: Tool/runtime error (I/O, parse failure)
/// - 2: Policy fail (blocking findings)
const EXIT_CODE_ERROR: i32 = 1;

/// Check raw CLI args for `--mode cockpit` (two consecutive args) or `--mode=cockpit`.
/// This avoids false-positives from file paths or other values containing "cockpit".
fn is_cockpit_in_raw_args() -> bool {
    let args: Vec<String> = std::env::args().collect();
    // Check for --mode=cockpit
    if args.iter().any(|a| a == "--mode=cockpit") {
        return true;
    }
    // Check for --mode cockpit (two consecutive args)
    args.windows(2)
        .any(|pair| pair[0] == "--mode" && pair[1] == "cockpit")
}

/// Extract the `--out` path from raw CLI args, falling back to the default.
fn extract_out_from_raw_args() -> String {
    let args: Vec<String> = std::env::args().collect();
    // Check for --out=PATH
    for arg in &args {
        if let Some(value) = arg.strip_prefix("--out=") {
            return value.to_string();
        }
    }
    // Check for --out PATH (two consecutive args)
    for pair in args.windows(2) {
        if pair[0] == "--out" {
            return pair[1].clone();
        }
    }
    "artifacts/covguard/report.json".to_string()
}

fn main() {
    let exit_code = match Cli::try_parse() {
        Ok(cli) => match run(cli) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {}", e);
                EXIT_CODE_ERROR
            }
        },
        Err(clap_err) => {
            // Check if cockpit mode was requested (scan raw args precisely)
            if is_cockpit_in_raw_args() {
                let out_path = extract_out_from_raw_args();
                let msg = format!("argument parsing failed: {}", clap_err);
                if write_fallback_receipt(&out_path, &msg, REASON_TOOL_ERROR, REASON_TOOL_ERROR)
                    .is_ok()
                {
                    eprintln!("warning: {}", msg);
                    eprintln!("wrote fallback receipt to {}", out_path);
                    0
                } else {
                    clap_err.exit()
                }
            } else {
                clap_err.exit()
            }
        }
    };
    std::process::exit(exit_code);
}

fn run(cli: Cli) -> Result<i32, CliError> {
    match cli.command {
        Commands::Check {
            mode,
            diff_file,
            base,
            head,
            lcov,
            out,
            md,
            sarif,
            raw,
            root,
            config,
            profile,
            scope,
            threshold,
            no_ignore,
            path_strip,
            max_findings,
            payload,
        } => {
            let is_cockpit = matches!(mode, CliMode::Cockpit);
            let out_path = out.clone();

            match run_check(
                mode,
                diff_file,
                base,
                head,
                lcov,
                out,
                md,
                sarif,
                raw,
                root,
                config,
                profile,
                scope,
                threshold,
                no_ignore,
                path_strip,
                max_findings,
                payload,
            ) {
                Ok(code) => Ok(code),
                Err(e) if is_cockpit => {
                    // In cockpit mode, try to write a fallback receipt
                    let (diff_reason, cov_reason) = fallback_capability_reasons(&e);
                    match write_fallback_receipt(&out_path, &e.to_string(), diff_reason, cov_reason)
                    {
                        Ok(()) => Ok(0),
                        Err(write_err) => {
                            eprintln!("error: {}", e);
                            eprintln!("error: failed to write fallback receipt: {}", write_err);
                            Err(e)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        }
        Commands::Explain { code } => run_explain(&code),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_check(
    mode: CliMode,
    diff_file: Option<String>,
    base: Option<String>,
    head: Option<String>,
    lcov: Vec<String>,
    out: String,
    md: Option<String>,
    sarif: Option<String>,
    raw: bool,
    root: Option<String>,
    config_path: Option<String>,
    profile: Option<CliProfile>,
    scope: Option<CliScope>,
    threshold: Option<f64>,
    no_ignore: bool,
    path_strip: Vec<String>,
    max_findings: Option<usize>,
    payload: Option<String>,
) -> Result<i32, CliError> {
    // In standard mode, LCOV is required
    let is_cockpit_mode = matches!(mode, CliMode::Cockpit);
    if !is_cockpit_mode && lcov.is_empty() {
        return Err(CliError::MissingLcov);
    }
    // Load configuration
    let loaded_config = if let Some(path) = &config_path {
        Some(load_config(Path::new(path)).map_err(|e| CliError::ConfigLoad(e.to_string()))?)
    } else {
        discover_config().map(|(_, c)| c)
    };

    // Build CLI overrides
    let cli_overrides = CliOverrides {
        scope: scope.map(|s| match s {
            CliScope::Added => ConfigScope::Added,
            CliScope::Touched => ConfigScope::Touched,
        }),
        fail_on: None,
        threshold_pct: threshold,
        max_uncovered_lines: None,
        ignore_directives: if no_ignore { Some(false) } else { None },
        path_strip: if path_strip.is_empty() {
            None
        } else {
            Some(path_strip.clone())
        },
    };

    // Apply profile override if specified
    let config_with_profile = if let Some(cli_profile) = profile {
        let mut config = loaded_config.clone().unwrap_or_default();
        config.profile = Some(match cli_profile {
            CliProfile::Oss => Profile::Oss,
            CliProfile::Moderate => Profile::Moderate,
            CliProfile::Team => Profile::Team,
            CliProfile::Strict => Profile::Strict,
        });
        Some(config)
    } else {
        loaded_config.clone()
    };

    // Resolve effective configuration
    let effective = resolve_config(config_with_profile.as_ref(), &cli_overrides);

    // Convert effective config to domain types
    let domain_scope = match effective.scope {
        ConfigScope::Added => Scope::Added,
        ConfigScope::Touched => Scope::Touched,
    };
    // Resolve repo root for git diff and ignore directive reading
    let repo_root = resolve_repo_root(root);

    // Determine diff source and read content
    let stdin_diff = if diff_file.as_deref() == Some("-") {
        read_stdin_diff(true)?
    } else if diff_file.is_none() && base.is_none() && head.is_none() {
        read_stdin_diff(false)?
    } else {
        None
    };

    let (diff_content, diff_file_path, base_ref, head_ref) =
        match (diff_file.as_ref(), base.as_ref(), head.as_ref()) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(CliError::ConflictingDiffSource);
            }
            (Some(path), None, None) if path == "-" => {
                if let Some(content) = stdin_diff {
                    (content, None, None, None)
                } else {
                    return Err(CliError::MissingDiffSource);
                }
            }
            (Some(path), None, None) => {
                let content = fs::read_to_string(path).map_err(|e| CliError::FileRead {
                    path: path.clone(),
                    source: e,
                })?;
                (content, Some(path.clone()), None, None)
            }
            (None, Some(base_ref), Some(head_ref)) => {
                // Execute git diff to get the diff content
                let output = std::process::Command::new("git")
                    .current_dir(&repo_root)
                    .args(["diff", base_ref, head_ref])
                    .output()
                    .map_err(|e| CliError::FileRead {
                        path: format!("git diff {}..{}", base_ref, head_ref),
                        source: e,
                    })?;
                let content = String::from_utf8_lossy(&output.stdout).to_string();
                (
                    content,
                    None,
                    Some(base_ref.clone()),
                    Some(head_ref.clone()),
                )
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                return Err(CliError::MissingDiffSource);
            }
            (None, None, None) => {
                if let Some(content) = stdin_diff {
                    (content, None, None, None)
                } else {
                    return Err(CliError::MissingDiffSource);
                }
            }
        };

    // Read LCOV contents
    let mut lcov_texts = Vec::with_capacity(lcov.len());
    for path in &lcov {
        let content = fs::read_to_string(path).map_err(|e| CliError::FileRead {
            path: path.clone(),
            source: e,
        })?;
        lcov_texts.push(content);
    }

    // Optionally write raw inputs for debugging/provenance
    if raw {
        write_raw_artifacts(&diff_content, &lcov_texts)?;
    }

    // Convert fail_on from config to app type
    let fail_on = match effective.fail_on {
        covguard_config::FailOn::Error => FailOn::Error,
        covguard_config::FailOn::Warn => FailOn::Warn,
        covguard_config::FailOn::Never => FailOn::Never,
    };

    // Map missing behaviors from config to app types
    let missing_coverage = map_missing_behavior(effective.missing_coverage);
    let missing_file = map_missing_behavior(effective.missing_file);

    // In cockpit mode, enable sensor schema for proper capabilities block
    let sensor_schema = is_cockpit_mode;

    // Build the check request using effective configuration
    let request = CheckRequest {
        diff_text: diff_content,
        diff_file_path,
        base_ref,
        head_ref,
        lcov_texts,
        lcov_paths: lcov.clone(),
        max_uncovered_lines: effective.max_uncovered_lines,
        missing_coverage,
        missing_file,
        include_patterns: effective.include_patterns.clone(),
        exclude_patterns: effective.exclude_patterns.clone(),
        path_strip: effective.path_strip.clone(),
        threshold_pct: effective.threshold_pct,
        scope: domain_scope,
        fail_on,
        ignore_directives: effective.ignore_directives,
        ignored_lines: None, // Will be detected from source files
        sensor_schema,
        max_findings,
    };

    // Run the check
    let reader = FsRepoReader::new(&repo_root);
    let result = check_with_clock_and_reader(request, &SystemClock, &reader)?;

    // Ensure output directory exists
    ensure_parent_dir(&out)?;

    // Write report JSON — in cockpit mode, --out gets the cockpit receipt;
    // in standard mode, --out gets the domain report.
    if is_cockpit_mode {
        if let Some(ref receipt) = result.cockpit_receipt {
            let receipt_json = serde_json::to_string_pretty(receipt)?;
            fs::write(&out, &receipt_json).map_err(|e| CliError::FileWrite {
                path: out.clone(),
                source: e,
            })?;
        } else {
            // Fallback: if cockpit_receipt is somehow None, write domain report
            let report_json = serde_json::to_string_pretty(&result.report)?;
            fs::write(&out, &report_json).map_err(|e| CliError::FileWrite {
                path: out.clone(),
                source: e,
            })?;
        }

        // Write domain report (full payload) to --payload or default extras path
        let payload_path = payload.unwrap_or_else(|| {
            let out_dir = Path::new(&out).parent().unwrap_or_else(|| Path::new("."));
            out_dir
                .join("extras")
                .join("payload.json")
                .display()
                .to_string()
        });
        ensure_parent_dir(&payload_path)?;
        let domain_json = serde_json::to_string_pretty(&result.report)?;
        fs::write(&payload_path, &domain_json).map_err(|e| CliError::FileWrite {
            path: payload_path,
            source: e,
        })?;
    } else {
        let report_json = serde_json::to_string_pretty(&result.report)?;
        fs::write(&out, &report_json).map_err(|e| CliError::FileWrite {
            path: out.clone(),
            source: e,
        })?;
    }

    // Write markdown if requested
    if let Some(md_path) = md {
        ensure_parent_dir(&md_path)?;
        fs::write(&md_path, &result.markdown).map_err(|e| CliError::FileWrite {
            path: md_path,
            source: e,
        })?;
    }

    // Write SARIF if requested
    if let Some(sarif_path) = sarif {
        ensure_parent_dir(&sarif_path)?;
        fs::write(&sarif_path, &result.sarif).map_err(|e| CliError::FileWrite {
            path: sarif_path,
            source: e,
        })?;
    }

    // Print annotations to stdout
    if !result.annotations.is_empty() {
        print!("{}", result.annotations);
    }

    // Return the exit code based on mode
    // In cockpit mode, exit 0 if receipt was written successfully
    // In standard mode, use the verdict-based exit code
    let exit_code = if is_cockpit_mode { 0 } else { result.exit_code };
    Ok(exit_code)
}

fn run_explain(code: &str) -> Result<i32, CliError> {
    if let Some(info) = explain(code) {
        println!("Code: {}", info.code);
        println!("Name: {}", info.name);
        println!("Meaning: {}", info.full_description);
        println!("Remediation: {}", info.remediation);
        println!("Docs: {}", info.help_uri);
        Ok(0)
    } else {
        eprintln!("Unknown code: {code}");
        Ok(1)
    }
}

fn map_missing_behavior(behavior: covguard_config::MissingBehavior) -> MissingBehavior {
    match behavior {
        covguard_config::MissingBehavior::Skip => MissingBehavior::Skip,
        covguard_config::MissingBehavior::Warn => MissingBehavior::Warn,
        covguard_config::MissingBehavior::Fail => MissingBehavior::Fail,
    }
}

fn resolve_repo_root(root: Option<String>) -> PathBuf {
    if let Some(path) = root {
        return PathBuf::from(path);
    }
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        && output.status.success()
    {
        let value = String::from_utf8_lossy(&output.stdout);
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn read_stdin_diff(explicit: bool) -> Result<Option<String>, CliError> {
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        return Ok(None);
    }

    let mut buf = String::new();
    stdin
        .read_to_string(&mut buf)
        .map_err(|e| CliError::FileRead {
            path: "stdin".to_string(),
            source: e,
        })?;

    if !explicit && buf.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some(buf))
}

fn write_raw_artifacts(diff_content: &str, lcov_texts: &[String]) -> Result<(), CliError> {
    let raw_dir = Path::new("artifacts/covguard/raw");
    if !raw_dir.exists() {
        fs::create_dir_all(raw_dir).map_err(|e| CliError::DirCreate {
            path: raw_dir.display().to_string(),
            source: e,
        })?;
    }

    let diff_path = raw_dir.join("diff.patch");
    fs::write(&diff_path, diff_content).map_err(|e| CliError::FileWrite {
        path: diff_path.display().to_string(),
        source: e,
    })?;

    let combined_lcov = lcov_texts.join("\n");
    let lcov_path = raw_dir.join("lcov.info");
    fs::write(&lcov_path, combined_lcov).map_err(|e| CliError::FileWrite {
        path: lcov_path.display().to_string(),
        source: e,
    })?;

    Ok(())
}

/// Derive capability reasons from a `CliError` for the fallback receipt.
///
/// Returns `(diff_reason, coverage_reason)` — precise when provable, `tool_error` otherwise.
fn fallback_capability_reasons(err: &CliError) -> (&'static str, &'static str) {
    match err {
        CliError::MissingDiffSource | CliError::ConflictingDiffSource => {
            (REASON_MISSING_DIFF, REASON_TOOL_ERROR)
        }
        CliError::MissingLcov => (REASON_TOOL_ERROR, REASON_MISSING_LCOV),
        _ => (REASON_TOOL_ERROR, REASON_TOOL_ERROR),
    }
}

/// Write a fallback receipt when covguard cannot complete normally in cockpit mode.
///
/// Produces a minimal sensor.report.v1 receipt with a tool.runtime_error finding.
fn write_fallback_receipt(
    out_path: &str,
    error_message: &str,
    diff_reason: &str,
    coverage_reason: &str,
) -> Result<(), CliError> {
    ensure_parent_dir(out_path)?;

    let started_at = chrono::Utc::now();
    let runtime_fp = compute_fingerprint(&[CODE_RUNTIME_ERROR, "covguard"]);

    let report = Report {
        schema: SENSOR_SCHEMA_ID.to_string(),
        tool: Tool {
            name: "covguard".to_string(),
            version: "0.2.0".to_string(),
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
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        findings: vec![Finding {
            severity: covguard_types::Severity::Error,
            check_id: CHECK_ID_RUNTIME.to_string(),
            code: CODE_RUNTIME_ERROR.to_string(),
            message: format!("covguard failed due to a runtime error: {}", error_message),
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
            inputs: Inputs::default(),
            debug: None,
            truncation: None,
        },
    };

    let json = serde_json::to_string_pretty(&report)?;
    fs::write(out_path, &json).map_err(|e| CliError::FileWrite {
        path: out_path.to_string(),
        source: e,
    })?;

    Ok(())
}

/// Ensure the parent directory of a path exists
fn ensure_parent_dir(path: &str) -> Result<(), CliError> {
    if let Some(parent) = Path::new(path).parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| CliError::DirCreate {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        let cli = Cli::try_parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_cli_default_values() {
        let cli = Cli::parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
        ]);
        match cli.command {
            Commands::Check { out, threshold, .. } => {
                assert_eq!(out, "artifacts/covguard/report.json");
                // threshold is now optional, should be None
                assert!(threshold.is_none());
            }
            Commands::Explain { .. } => panic!("unexpected explain command"),
        }
    }

    #[test]
    fn test_conflicting_diff_source() {
        let result = run_check(
            CliMode::Standard,
            Some("test.patch".to_string()),
            Some("main".to_string()),
            Some("HEAD".to_string()),
            vec!["coverage.info".to_string()],
            "out.json".to_string(),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            Vec::new(),
            None,
            None,
        );
        assert!(matches!(result, Err(CliError::ConflictingDiffSource)));
    }

    #[test]
    fn test_missing_diff_source() {
        let result = run_check(
            CliMode::Standard,
            None,
            None,
            None,
            vec!["coverage.info".to_string()],
            "out.json".to_string(),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            Vec::new(),
            None,
            None,
        );
        assert!(matches!(result, Err(CliError::MissingDiffSource)));
    }

    #[test]
    fn test_partial_git_refs() {
        let result = run_check(
            CliMode::Standard,
            None,
            Some("main".to_string()),
            None,
            vec!["coverage.info".to_string()],
            "out.json".to_string(),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            Vec::new(),
            None,
            None,
        );
        assert!(matches!(result, Err(CliError::MissingDiffSource)));
    }

    #[test]
    fn test_cli_accepts_all_scope_values() {
        for scope in ["added", "touched"] {
            let cli = Cli::try_parse_from([
                "covguard",
                "check",
                "--diff-file",
                "test.patch",
                "--lcov",
                "coverage.info",
                "--scope",
                scope,
            ]);
            assert!(cli.is_ok(), "Failed to parse scope: {}", scope);
        }
    }

    #[test]
    fn test_cli_accepts_all_profile_values() {
        for profile in ["oss", "moderate", "team", "strict"] {
            let cli = Cli::try_parse_from([
                "covguard",
                "check",
                "--diff-file",
                "test.patch",
                "--lcov",
                "coverage.info",
                "--profile",
                profile,
            ]);
            assert!(cli.is_ok(), "Failed to parse profile: {}", profile);
        }
    }

    #[test]
    fn test_cli_rejects_invalid_scope() {
        let cli = Cli::try_parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
            "--scope",
            "invalid",
        ]);
        assert!(cli.is_err());
    }

    #[test]
    fn test_cli_rejects_invalid_profile() {
        let cli = Cli::try_parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
            "--profile",
            "invalid",
        ]);
        assert!(cli.is_err());
    }

    #[test]
    fn test_cli_threshold_accepts_boundary_values() {
        for threshold in ["0", "100", "50.5", "99.99"] {
            let cli = Cli::try_parse_from([
                "covguard",
                "check",
                "--diff-file",
                "test.patch",
                "--lcov",
                "coverage.info",
                "--threshold",
                threshold,
            ]);
            assert!(cli.is_ok(), "Failed to parse threshold: {}", threshold);
        }
    }

    #[test]
    fn test_cli_threshold_rejects_non_numeric() {
        let cli = Cli::try_parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
            "--threshold",
            "abc",
        ]);
        assert!(cli.is_err());
    }

    #[test]
    fn test_cli_all_optional_args_together() {
        let cli = Cli::try_parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
            "--out",
            "report.json",
            "--md",
            "comment.md",
            "--sarif",
            "results.sarif",
            "--raw",
            "--scope",
            "touched",
            "--profile",
            "strict",
            "--threshold",
            "90",
            "--no-ignore",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_ensure_parent_dir_with_simple_path() {
        // Path with no parent should succeed
        let result = ensure_parent_dir("report.json");
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_lcov_in_standard_mode() {
        let result = run_check(
            CliMode::Standard,
            Some("test.patch".to_string()),
            None,
            None,
            vec![], // Empty lcov
            "out.json".to_string(),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            false,
            Vec::new(),
            None,
            None,
        );
        assert!(matches!(result, Err(CliError::MissingLcov)));
    }

    #[test]
    fn test_cli_mode_default() {
        let cli = Cli::parse_from([
            "covguard",
            "check",
            "--diff-file",
            "test.patch",
            "--lcov",
            "coverage.info",
        ]);
        match cli.command {
            Commands::Check { mode, .. } => {
                assert!(matches!(mode, CliMode::Standard));
            }
            Commands::Explain { .. } => panic!("unexpected explain command"),
        }
    }

    #[test]
    fn test_cli_mode_cockpit() {
        let cli = Cli::parse_from([
            "covguard",
            "check",
            "--mode",
            "cockpit",
            "--diff-file",
            "test.patch",
        ]);
        match cli.command {
            Commands::Check { mode, lcov, .. } => {
                assert!(matches!(mode, CliMode::Cockpit));
                // In cockpit mode, lcov can be empty
                assert!(lcov.is_empty());
            }
            Commands::Explain { .. } => panic!("unexpected explain command"),
        }
    }

    #[test]
    fn test_fallback_reasons_missing_diff_source() {
        let (diff, cov) = fallback_capability_reasons(&CliError::MissingDiffSource);
        assert_eq!(diff, REASON_MISSING_DIFF);
        assert_eq!(cov, REASON_TOOL_ERROR);
    }

    #[test]
    fn test_fallback_reasons_conflicting_diff_source() {
        let (diff, cov) = fallback_capability_reasons(&CliError::ConflictingDiffSource);
        assert_eq!(diff, REASON_MISSING_DIFF);
        assert_eq!(cov, REASON_TOOL_ERROR);
    }

    #[test]
    fn test_fallback_reasons_missing_lcov() {
        let (diff, cov) = fallback_capability_reasons(&CliError::MissingLcov);
        assert_eq!(diff, REASON_TOOL_ERROR);
        assert_eq!(cov, REASON_MISSING_LCOV);
    }

    #[test]
    fn test_fallback_reasons_file_read() {
        let err = CliError::FileRead {
            path: "foo.patch".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        let (diff, cov) = fallback_capability_reasons(&err);
        assert_eq!(diff, REASON_TOOL_ERROR);
        assert_eq!(cov, REASON_TOOL_ERROR);
    }
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// CLI parsing should never panic regardless of argument values
        #[test]
        fn cli_parsing_does_not_panic(
            diff_file in ".*",
            lcov in ".*",
            out in ".*",
        ) {
            // Just ensure parsing doesn't panic - we don't care about the result
            let _ = Cli::try_parse_from([
                "covguard",
                "check",
                "--diff-file",
                &diff_file,
                "--lcov",
                &lcov,
                "--out",
                &out,
            ]);
        }

        /// Threshold parsing should accept any valid f64 in string form
        #[test]
        fn threshold_accepts_valid_numbers(threshold in 0.0f64..=100.0) {
            let threshold_str = threshold.to_string();
            let cli = Cli::try_parse_from([
                "covguard",
                "check",
                "--diff-file",
                "test.patch",
                "--lcov",
                "coverage.info",
                "--threshold",
                &threshold_str,
            ]);
            // Should parse successfully
            prop_assert!(cli.is_ok());
        }

        /// diff_file + base should always produce ConflictingDiffSource error
        #[test]
        fn conflicting_sources_always_error(
            diff_file in "[a-z]+\\.patch",
            base_ref in "[a-z]+",
        ) {
            let result = run_check(
                CliMode::Standard,
                Some(diff_file),
                Some(base_ref),
                Some("HEAD".to_string()),
                vec!["coverage.info".to_string()],
                "out.json".to_string(),
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                Vec::new(),
                None,
                None,
            );
            prop_assert!(matches!(result, Err(CliError::ConflictingDiffSource)));
        }

        /// Missing diff source should always produce MissingDiffSource error
        #[test]
        fn missing_diff_source_always_error(
            lcov in "[a-z]+\\.info",
            out in "[a-z]+\\.json",
        ) {
            let result = run_check(
                CliMode::Standard,
                None,
                None,
                None,
                vec![lcov],
                out,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                Vec::new(),
                None,
                None,
            );
            prop_assert!(matches!(result, Err(CliError::MissingDiffSource)));
        }

        /// Partial git refs (only base, no head) should produce MissingDiffSource error
        #[test]
        fn partial_base_ref_error(base_ref in "[a-z]+") {
            let result = run_check(
                CliMode::Standard,
                None,
                Some(base_ref),
                None,
                vec!["coverage.info".to_string()],
                "out.json".to_string(),
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                Vec::new(),
                None,
                None,
            );
            prop_assert!(matches!(result, Err(CliError::MissingDiffSource)));
        }

        /// Partial git refs (only head, no base) should produce MissingDiffSource error
        #[test]
        fn partial_head_ref_error(head_ref in "[a-z]+") {
            let result = run_check(
                CliMode::Standard,
                None,
                None,
                Some(head_ref),
                vec!["coverage.info".to_string()],
                "out.json".to_string(),
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                false,
                Vec::new(),
                None,
                None,
            );
            prop_assert!(matches!(result, Err(CliError::MissingDiffSource)));
        }
    }
}
