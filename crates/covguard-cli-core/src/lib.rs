//! Core logic for covguard CLI.

use covguard_adapters_artifacts::{
    ArtifactWriteError, ensure_parent_dir as ensure_parent_dir_artifacts,
    write_fallback_receipt as write_fallback_receipt_artifacts,
    write_raw_artifacts as write_raw_artifacts_from_adapter,
    write_report as write_report_artifacts, write_text as write_text_artifacts,
};
use covguard_adapters_diff::{DiffError, load_diff_from_git};
use covguard_adapters_repo::FsRepoReader;
use covguard_app::{
    AppError, CheckRequest, CoverageInput, SystemClock, check_with_clock_and_reader,
};
use covguard_cli_types::{CliMode, CliProfile, CliScope, Commands};
use covguard_config::{
    CliOverrides, Scope as ConfigScope, discover_config, load_config, resolve_config,
};
use covguard_output_features::OutputFeatureConfig;
use covguard_profiling::{ProfileStats, profile_scope, set_profiling_enabled};
use covguard_types::{
    CODE_INVALID_DIFF, CODE_INVALID_LCOV, CODE_RUNTIME_ERROR, EnhancedError, REASON_MISSING_DIFF,
    REASON_MISSING_LCOV, REASON_TOOL_ERROR, Scope, explain,
};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// CLI errors
#[derive(Debug, Error)]
pub enum CliError {
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

impl EnhancedError for CliError {
    fn code(&self) -> &'static str {
        match self {
            CliError::MissingDiffSource | CliError::ConflictingDiffSource => CODE_INVALID_DIFF,
            CliError::MissingLcov => CODE_INVALID_LCOV,
            CliError::FileRead { .. }
            | CliError::FileWrite { .. }
            | CliError::DirCreate { .. }
            | CliError::Serialize(_)
            | CliError::ConfigLoad(_) => CODE_RUNTIME_ERROR,
            CliError::App(app_error) => app_error.code(),
        }
    }

    fn description(&self) -> &str {
        match self {
            CliError::MissingDiffSource | CliError::ConflictingDiffSource => "Invalid diff input",
            CliError::MissingLcov => "Invalid LCOV input",
            CliError::FileRead { .. } => "Tool runtime error",
            CliError::FileWrite { .. } => "Tool runtime error",
            CliError::DirCreate { .. } => "Tool runtime error",
            CliError::Serialize(_) => "Tool runtime error",
            CliError::ConfigLoad(_) => "Tool runtime error",
            CliError::App(app_error) => app_error.description(),
        }
    }

    fn remediation(&self) -> &str {
        explain(self.code())
            .map(|info| info.remediation)
            .unwrap_or("No remediation available.")
    }

    fn help_uri(&self) -> &'static str {
        explain(self.code())
            .map(|info| info.help_uri)
            .unwrap_or("https://github.com/EffortlessMetrics/covguard/blob/main/docs/codes.md")
    }
}

pub const EXIT_CODE_ERROR: i32 = 1;

pub fn run(command: Commands) -> Result<i32, CliError> {
    match command {
        Commands::Check {
            mode,
            diff_file,
            base,
            head,
            lcov,
            jacoco,
            coverage_py,
            coverage,
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
            max_markdown_lines,
            max_annotations,
            max_sarif_results,
            max_findings,
            payload,
            timing,
        } => {
            let is_cockpit = matches!(mode, CliMode::Cockpit);
            let out_path = out.clone();
            let output = OutputFeatureConfig {
                max_markdown_lines,
                max_annotations,
                max_sarif_results,
            };

            match run_check_with_output(
                mode,
                diff_file,
                base,
                head,
                lcov,
                jacoco,
                coverage_py,
                coverage,
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
                output,
                max_findings,
                payload,
                timing,
                read_stdin_diff,
            ) {
                Ok(code) => Ok(code),
                Err(e) if is_cockpit => {
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
pub fn run_check_with_output<F>(
    mode: CliMode,
    diff_file: Option<String>,
    base: Option<String>,
    head: Option<String>,
    lcov: Vec<String>,
    jacoco: Vec<String>,
    coverage_py: Vec<String>,
    coverage: Vec<String>,
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
    output: OutputFeatureConfig,
    max_findings: Option<usize>,
    payload: Option<String>,
    timing: bool,
    read_stdin: F,
) -> Result<i32, CliError>
where
    F: Fn(bool) -> Result<Option<String>, CliError>,
{
    set_profiling_enabled(timing);
    let profile_stats = ProfileStats::new();
    let total_start = std::time::Instant::now();

    let is_cockpit_mode = matches!(mode, CliMode::Cockpit);
    if !is_cockpit_mode
        && lcov.is_empty()
        && jacoco.is_empty()
        && coverage_py.is_empty()
        && coverage.is_empty()
    {
        return Err(CliError::MissingLcov);
    }

    let _config_guard = profile_scope!("config_load", &profile_stats);
    let loaded_config = if let Some(path) = &config_path {
        Some(load_config(Path::new(path)).map_err(|e| CliError::ConfigLoad(e.to_string()))?)
    } else {
        discover_config().map(|(_, c)| c)
    };
    drop(_config_guard);

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
        output: Some(output),
    };

    let config_with_profile = if let Some(cli_profile) = profile {
        let mut config = loaded_config.clone().unwrap_or_default();
        config.profile = Some(cli_profile.into());
        Some(config)
    } else {
        loaded_config.clone()
    };

    let effective = resolve_config(config_with_profile.as_ref(), &cli_overrides);

    let domain_scope = match effective.scope {
        ConfigScope::Added => Scope::Added,
        ConfigScope::Touched => Scope::Touched,
    };
    let repo_root = resolve_repo_root(root);

    let _diff_load_guard = profile_scope!("diff_load", &profile_stats);
    let stdin_diff = if diff_file.as_deref() == Some("-") {
        read_stdin(true)?
    } else if diff_file.is_none() && base.is_none() && head.is_none() {
        read_stdin(false)?
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
                let content =
                    load_diff_from_git(base_ref, head_ref, &repo_root).map_err(|e| match e {
                        DiffError::IoError { message, .. } => CliError::FileRead {
                            path: format!("git diff {}..{}", base_ref, head_ref),
                            source: std::io::Error::other(message),
                        },
                        DiffError::InvalidFormat { message, .. } => CliError::ConfigLoad(message),
                        DiffError::GitError { message, .. } => CliError::ConfigLoad(message),
                        DiffError::EmptyDiff => CliError::ConfigLoad("Empty diff".to_string()),
                        DiffError::BinaryFile { path, .. } => {
                            CliError::ConfigLoad(format!("Binary file: {}", path))
                        }
                        DiffError::MissingHunkHeader { line_number, .. } => CliError::ConfigLoad(
                            format!("Missing hunk header at line {}", line_number),
                        ),
                        DiffError::InvalidHunkHeader {
                            line_number,
                            actual,
                            ..
                        } => CliError::ConfigLoad(format!(
                            "Invalid hunk header at line {}: '{}'",
                            line_number, actual
                        )),
                    })?;
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

    drop(_diff_load_guard);

    let _coverage_load_guard = profile_scope!("coverage_load", &profile_stats);
    let mut coverage_inputs = Vec::new();

    let mut add_inputs =
        |paths: &[String], format: covguard_types::CoverageFormat| -> Result<(), CliError> {
            for path in paths {
                let content = fs::read_to_string(path).map_err(|e| CliError::FileRead {
                    path: path.clone(),
                    source: e,
                })?;
                coverage_inputs.push(CoverageInput {
                    content,
                    path: path.clone(),
                    format,
                });
            }
            Ok(())
        };

    add_inputs(&lcov, covguard_types::CoverageFormat::Lcov)?;
    add_inputs(&jacoco, covguard_types::CoverageFormat::Jacoco)?;
    add_inputs(&coverage_py, covguard_types::CoverageFormat::CoveragePy)?;
    add_inputs(&coverage, covguard_types::CoverageFormat::Auto)?;

    drop(_coverage_load_guard);

    if raw {
        let lcov_only: Vec<String> = coverage_inputs
            .iter()
            .filter(|i| i.format == covguard_types::CoverageFormat::Lcov)
            .map(|i| i.content.clone())
            .collect();
        write_raw_artifacts(&diff_content, &lcov_only)?;
    }

    let sensor_schema = is_cockpit_mode;

    let request = CheckRequest {
        diff_text: diff_content,
        diff_file_path,
        base_ref,
        head_ref,
        coverage_inputs,
        lcov_texts: Vec::new(),
        lcov_paths: Vec::new(),
        max_uncovered_lines: effective.max_uncovered_lines,
        missing_coverage: effective.missing_coverage,
        missing_file: effective.missing_file,
        include_patterns: effective.include_patterns.clone(),
        exclude_patterns: effective.exclude_patterns.clone(),
        path_strip: effective.path_strip.clone(),
        threshold_pct: effective.threshold_pct,
        scope: domain_scope,
        fail_on: effective.fail_on,
        ignore_directives: effective.ignore_directives,
        ignored_lines: None,
        output: effective.output,
        sensor_schema,
        max_findings,
    };

    let _check_guard = profile_scope!("policy_evaluation", &profile_stats);
    let reader = FsRepoReader::new(&repo_root);
    let result = check_with_clock_and_reader(request, &SystemClock, &reader)?;
    drop(_check_guard);

    let _render_guard = profile_scope!("report_generation", &profile_stats);

    ensure_parent_dir(&out)?;

    if is_cockpit_mode {
        let receipt = result
            .cockpit_receipt
            .as_ref()
            .expect("cockpit receipt missing");
        write_report_artifacts(&out, receipt).map_err(map_artifact_error)?;

        let payload_path = payload.unwrap_or_else(|| {
            let out_dir = Path::new(&out).parent().unwrap_or_else(|| Path::new("."));
            out_dir
                .join("extras")
                .join("payload.json")
                .display()
                .to_string()
        });
        write_report_artifacts(&payload_path, &result.report).map_err(map_artifact_error)?;
    } else {
        write_report_artifacts(&out, &result.report).map_err(map_artifact_error)?;
    }

    if let Some(md_path) = md {
        write_text_artifacts(&md_path, &result.markdown).map_err(map_artifact_error)?;
    }

    if let Some(sarif_path) = sarif {
        write_text_artifacts(&sarif_path, &result.sarif).map_err(map_artifact_error)?;
    }

    if !result.annotations.is_empty() {
        print!("{}", result.annotations);
    }
    drop(_render_guard);

    if timing {
        let total_duration = total_start.elapsed();
        eprintln!("\n=== Timing Report ===");
        eprintln!("Total time: {:.2}ms", total_duration.as_secs_f64() * 1000.0);
        profile_stats.print_report();
    }

    let exit_code = if is_cockpit_mode { 0 } else { result.exit_code };
    Ok(exit_code)
}

pub fn run_explain(code: &str) -> Result<i32, CliError> {
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

pub fn resolve_repo_root(root: Option<String>) -> PathBuf {
    if let Some(path) = root {
        return PathBuf::from(path);
    }
    let git_cmd = get_git_command();
    if let Ok(output) = std::process::Command::new(git_cmd)
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

#[cfg(test)]
fn get_git_command() -> String {
    std::env::var("COVGUARD_GIT").unwrap_or_else(|_| "git".to_string())
}

#[cfg(not(test))]
fn get_git_command() -> String {
    "git".to_string()
}

pub fn read_stdin_diff(explicit: bool) -> Result<Option<String>, CliError> {
    #[cfg(test)]
    {
        let mut cursor = io::Cursor::new("");
        read_diff_from_reader(&mut cursor, true, explicit)
    }
    #[cfg(not(test))]
    {
        use std::io::IsTerminal;
        let mut stdin = io::stdin();
        let is_terminal = stdin.is_terminal();
        read_diff_from_reader(&mut stdin, is_terminal, explicit)
    }
}

pub fn read_diff_from_reader(
    reader: &mut dyn Read,
    is_terminal: bool,
    explicit: bool,
) -> Result<Option<String>, CliError> {
    if is_terminal {
        return Ok(None);
    }

    let mut buf = String::new();
    reader
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

pub fn write_raw_artifacts(diff_content: &str, lcov_texts: &[String]) -> Result<(), CliError> {
    write_raw_artifacts_from_adapter(diff_content, lcov_texts).map_err(map_artifact_error)
}

pub fn fallback_capability_reasons(err: &CliError) -> (&'static str, &'static str) {
    match err {
        CliError::MissingDiffSource | CliError::ConflictingDiffSource => {
            (REASON_MISSING_DIFF, REASON_TOOL_ERROR)
        }
        CliError::MissingLcov => (REASON_TOOL_ERROR, REASON_MISSING_LCOV),
        _ => (REASON_TOOL_ERROR, REASON_TOOL_ERROR),
    }
}

pub fn write_fallback_receipt(
    out_path: &str,
    error_message: &str,
    diff_reason: &str,
    coverage_reason: &str,
) -> Result<(), CliError> {
    write_fallback_receipt_artifacts(out_path, error_message, diff_reason, coverage_reason)
        .map_err(map_artifact_error)
}

pub fn ensure_parent_dir(path: &str) -> Result<(), CliError> {
    ensure_parent_dir_artifacts(path).map_err(map_artifact_error)
}

pub fn map_artifact_error(err: ArtifactWriteError) -> CliError {
    match err {
        ArtifactWriteError::DirCreate { path, source } => CliError::DirCreate { path, source },
        ArtifactWriteError::FileWrite { path, source } => CliError::FileWrite { path, source },
        ArtifactWriteError::Serialize(err) => CliError::Serialize(err),
    }
}
