//! Configuration parsing and management for covguard.
//!
//! This crate provides:
//! - Configuration types (`Config`, `Profile`, etc.)
//! - TOML parsing
//! - Profile system (oss, team, strict)
//! - Precedence handling (CLI > config file > defaults)

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read the configuration file.
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    /// Failed to parse the configuration file.
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Invalid configuration value.
    #[error("Invalid config value: {0}")]
    InvalidValue(String),
}

// ============================================================================
// Configuration Types
// ============================================================================

/// Built-in configuration profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Open-source friendly: warn on uncovered + missing coverage.
    /// Good for adoption without blocking PRs.
    Oss,
    /// Moderate: transitional profile between oss and team.
    /// 75% threshold, fail on error, warn on missing.
    Moderate,
    /// Team standard: error on uncovered, warn on missing.
    #[default]
    Team,
    /// Strict: error on both uncovered and missing, higher threshold.
    /// Allows a small buffer of uncovered lines (5).
    Strict,
}

/// Scope of lines to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Only evaluate added lines.
    #[default]
    Added,
    /// Evaluate all touched (added + modified) lines.
    Touched,
}

/// Determines when the evaluation should fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    /// Fail if there are any error-level findings.
    #[default]
    Error,
    /// Fail if there are any warn-level or error-level findings.
    Warn,
    /// Never fail (always pass unless there's a runtime error).
    Never,
}

/// How to handle missing coverage data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MissingBehavior {
    /// Skip lines/files with missing coverage (don't count them).
    Skip,
    /// Warn about missing coverage but don't fail.
    #[default]
    Warn,
    /// Fail if there's any missing coverage.
    Fail,
}

/// Path filtering configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PathConfig {
    /// Glob patterns for files/directories to exclude.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Glob patterns for files/directories to include (allowlist).
    /// If empty, all files are included.
    #[serde(default)]
    pub include: Vec<String>,
}

/// Ignore directive configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IgnoreConfig {
    /// Enable `covguard: ignore` directives in source comments.
    #[serde(default = "default_true")]
    pub directives: bool,
}

/// Path normalization configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NormalizeConfig {
    /// Prefixes to strip from LCOV SF paths.
    #[serde(default)]
    pub path_strip: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Full configuration for covguard.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// Configuration profile to use.
    #[serde(default)]
    pub profile: Option<Profile>,

    /// Scope of lines to evaluate.
    #[serde(default)]
    pub scope: Option<Scope>,

    /// Determines when the evaluation should fail.
    #[serde(default)]
    pub fail_on: Option<FailOn>,

    /// Minimum diff coverage percentage (0-100).
    #[serde(default)]
    pub min_diff_coverage_pct: Option<f64>,

    /// Maximum allowed uncovered lines.
    #[serde(default)]
    pub max_uncovered_lines: Option<u32>,

    /// How to handle missing coverage data for lines.
    #[serde(default)]
    pub missing_coverage: Option<MissingBehavior>,

    /// How to handle files with no coverage data.
    #[serde(default)]
    pub missing_file: Option<MissingBehavior>,

    /// Path filtering configuration.
    #[serde(default)]
    pub paths: PathConfig,

    /// Ignore directive configuration.
    #[serde(default, rename = "ignore")]
    pub ignore_config: IgnoreConfig,

    /// Path normalization configuration.
    #[serde(default)]
    pub normalize: NormalizeConfig,
}

// ============================================================================
// Effective Configuration
// ============================================================================

/// Effective configuration with all values resolved.
///
/// This represents the final configuration after applying:
/// 1. Profile defaults
/// 2. Config file values
/// 3. CLI overrides
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub scope: Scope,
    pub fail_on: FailOn,
    pub threshold_pct: f64,
    pub max_uncovered_lines: Option<u32>,
    pub missing_coverage: MissingBehavior,
    pub missing_file: MissingBehavior,
    pub exclude_patterns: Vec<String>,
    pub include_patterns: Vec<String>,
    pub ignore_directives: bool,
    pub path_strip: Vec<String>,
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self {
            scope: Scope::Added,
            fail_on: FailOn::Error,
            threshold_pct: 80.0,
            max_uncovered_lines: None,
            missing_coverage: MissingBehavior::Warn,
            missing_file: MissingBehavior::Warn,
            exclude_patterns: vec![],
            include_patterns: vec![],
            ignore_directives: true,
            path_strip: vec![],
        }
    }
}

// ============================================================================
// Profile Defaults
// ============================================================================

/// Get default configuration for a profile.
pub fn profile_defaults(profile: Profile) -> EffectiveConfig {
    match profile {
        Profile::Oss => EffectiveConfig {
            scope: Scope::Added,
            fail_on: FailOn::Never, // Don't fail, just warn
            threshold_pct: 70.0,    // Lower threshold
            max_uncovered_lines: None,
            missing_coverage: MissingBehavior::Skip,
            missing_file: MissingBehavior::Skip,
            exclude_patterns: vec![],
            include_patterns: vec![],
            ignore_directives: true,
            path_strip: vec![],
        },
        Profile::Moderate => EffectiveConfig {
            scope: Scope::Added,
            fail_on: FailOn::Error,
            threshold_pct: 75.0, // Transitional threshold
            max_uncovered_lines: None,
            missing_coverage: MissingBehavior::Warn,
            missing_file: MissingBehavior::Skip, // More lenient on missing files
            exclude_patterns: vec![],
            include_patterns: vec![],
            ignore_directives: true,
            path_strip: vec![],
        },
        Profile::Team => EffectiveConfig {
            scope: Scope::Added,
            fail_on: FailOn::Error,
            threshold_pct: 80.0,
            max_uncovered_lines: None,
            missing_coverage: MissingBehavior::Warn,
            missing_file: MissingBehavior::Warn,
            exclude_patterns: vec![],
            include_patterns: vec![],
            ignore_directives: true,
            path_strip: vec![],
        },
        Profile::Strict => EffectiveConfig {
            scope: Scope::Touched, // Check all touched lines
            fail_on: FailOn::Error,
            threshold_pct: 90.0,          // Higher threshold
            max_uncovered_lines: Some(5), // Small buffer for edge cases
            missing_coverage: MissingBehavior::Fail,
            missing_file: MissingBehavior::Fail,
            exclude_patterns: vec![],
            include_patterns: vec![],
            ignore_directives: true,
            path_strip: vec![],
        },
    }
}

// ============================================================================
// Configuration Loading
// ============================================================================

/// Load configuration from a TOML file.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    validate_config(&config)?;
    Ok(config)
}

/// Load configuration from a TOML string.
pub fn parse_config(content: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(content)?;
    validate_config(&config)?;
    Ok(config)
}

/// Validate configuration values.
fn validate_config(config: &Config) -> Result<(), ConfigError> {
    if let Some(pct) = config.min_diff_coverage_pct
        && !(0.0..=100.0).contains(&pct)
    {
        return Err(ConfigError::InvalidValue(format!(
            "min_diff_coverage_pct must be between 0 and 100, got {}",
            pct
        )));
    }
    Ok(())
}

/// Try to find and load configuration from the standard location.
///
/// Searches for `covguard.toml` in the current directory and parent directories.
pub fn discover_config() -> Option<(std::path::PathBuf, Config)> {
    let mut current = std::env::current_dir().ok()?;

    loop {
        let config_path = current.join("covguard.toml");
        if config_path.exists()
            && let Ok(config) = load_config(&config_path)
        {
            return Some((config_path, config));
        }

        if !current.pop() {
            break;
        }
    }

    None
}

// ============================================================================
// Precedence Resolution
// ============================================================================

/// CLI override options.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub scope: Option<Scope>,
    pub fail_on: Option<FailOn>,
    pub threshold_pct: Option<f64>,
    pub max_uncovered_lines: Option<u32>,
    pub ignore_directives: Option<bool>,
    pub path_strip: Option<Vec<String>>,
}

/// Resolve effective configuration from profile, config file, and CLI overrides.
///
/// Precedence: CLI > config file > profile defaults > global defaults
pub fn resolve_config(config: Option<&Config>, cli: &CliOverrides) -> EffectiveConfig {
    // Start with profile defaults or global defaults
    let profile = config.and_then(|c| c.profile).unwrap_or(Profile::Team);
    let mut effective = profile_defaults(profile);

    // Apply config file values
    if let Some(config) = config {
        if let Some(scope) = config.scope {
            effective.scope = scope;
        }
        if let Some(fail_on) = config.fail_on {
            effective.fail_on = fail_on;
        }
        if let Some(pct) = config.min_diff_coverage_pct {
            effective.threshold_pct = pct;
        }
        if let Some(max) = config.max_uncovered_lines {
            effective.max_uncovered_lines = Some(max);
        }
        if let Some(behavior) = config.missing_coverage {
            effective.missing_coverage = behavior;
        }
        if let Some(behavior) = config.missing_file {
            effective.missing_file = behavior;
        }
        effective.exclude_patterns = config.paths.exclude.clone();
        effective.include_patterns = config.paths.include.clone();
        effective.ignore_directives = config.ignore_config.directives;
        effective.path_strip = config.normalize.path_strip.clone();
    }

    // Apply CLI overrides
    if let Some(scope) = cli.scope {
        effective.scope = scope;
    }
    if let Some(fail_on) = cli.fail_on {
        effective.fail_on = fail_on;
    }
    if let Some(pct) = cli.threshold_pct {
        effective.threshold_pct = pct;
    }
    if let Some(max) = cli.max_uncovered_lines {
        effective.max_uncovered_lines = Some(max);
    }
    if let Some(ignore) = cli.ignore_directives {
        effective.ignore_directives = ignore;
    }
    if let Some(path_strip) = &cli.path_strip {
        effective.path_strip = path_strip.clone();
    }

    effective
}

// ============================================================================
// Path Filtering
// ============================================================================

/// Check if a path matches any of the given glob patterns.
pub fn matches_any_pattern(path: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if let Ok(glob_pattern) = glob::Pattern::new(pattern)
            && glob_pattern.matches(path)
        {
            return true;
        }
    }
    false
}

/// Filter a path based on include/exclude patterns.
///
/// Returns `true` if the path should be included in evaluation.
pub fn should_include_path(
    path: &str,
    include_patterns: &[String],
    exclude_patterns: &[String],
) -> bool {
    // If exclude patterns match, exclude the path
    if matches_any_pattern(path, exclude_patterns) {
        return false;
    }

    // If include patterns are specified and path doesn't match, exclude it
    if !include_patterns.is_empty() && !matches_any_pattern(path, include_patterns) {
        return false;
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let config = parse_config("").unwrap();
        assert!(config.profile.is_none());
        assert!(config.scope.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
profile = "strict"
scope = "touched"
fail_on = "warn"
min_diff_coverage_pct = 90
max_uncovered_lines = 5
missing_coverage = "fail"
missing_file = "skip"

[paths]
exclude = ["target/**", "vendor/**"]
include = ["src/**"]

[ignore]
directives = false

[normalize]
path_strip = ["/home/runner/"]
"#;
        let config = parse_config(toml).unwrap();

        assert_eq!(config.profile, Some(Profile::Strict));
        assert_eq!(config.scope, Some(Scope::Touched));
        assert_eq!(config.fail_on, Some(FailOn::Warn));
        assert_eq!(config.min_diff_coverage_pct, Some(90.0));
        assert_eq!(config.max_uncovered_lines, Some(5));
        assert_eq!(config.missing_coverage, Some(MissingBehavior::Fail));
        assert_eq!(config.missing_file, Some(MissingBehavior::Skip));
        assert_eq!(config.paths.exclude, vec!["target/**", "vendor/**"]);
        assert_eq!(config.paths.include, vec!["src/**"]);
        assert!(!config.ignore_config.directives);
        assert_eq!(config.normalize.path_strip, vec!["/home/runner/"]);
    }

    #[test]
    fn test_invalid_threshold() {
        let toml = "min_diff_coverage_pct = 150";
        let result = parse_config(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_profile_defaults_oss() {
        let defaults = profile_defaults(Profile::Oss);
        assert_eq!(defaults.fail_on, FailOn::Never);
        assert_eq!(defaults.threshold_pct, 70.0);
        assert_eq!(defaults.missing_coverage, MissingBehavior::Skip);
        assert_eq!(defaults.missing_file, MissingBehavior::Skip);
        assert_eq!(defaults.scope, Scope::Added);
    }

    #[test]
    fn test_profile_defaults_moderate() {
        let defaults = profile_defaults(Profile::Moderate);
        assert_eq!(defaults.fail_on, FailOn::Error);
        assert_eq!(defaults.threshold_pct, 75.0);
        assert_eq!(defaults.missing_coverage, MissingBehavior::Warn);
        assert_eq!(defaults.missing_file, MissingBehavior::Skip);
        assert_eq!(defaults.scope, Scope::Added);
    }

    #[test]
    fn test_profile_defaults_team() {
        let defaults = profile_defaults(Profile::Team);
        assert_eq!(defaults.fail_on, FailOn::Error);
        assert_eq!(defaults.threshold_pct, 80.0);
        assert_eq!(defaults.missing_coverage, MissingBehavior::Warn);
        assert_eq!(defaults.missing_file, MissingBehavior::Warn);
        assert_eq!(defaults.scope, Scope::Added);
    }

    #[test]
    fn test_profile_defaults_strict() {
        let defaults = profile_defaults(Profile::Strict);
        assert_eq!(defaults.fail_on, FailOn::Error);
        assert_eq!(defaults.threshold_pct, 90.0);
        assert_eq!(defaults.max_uncovered_lines, Some(5));
        assert_eq!(defaults.missing_coverage, MissingBehavior::Fail);
        assert_eq!(defaults.missing_file, MissingBehavior::Fail);
        assert_eq!(defaults.scope, Scope::Touched);
    }

    #[test]
    fn test_resolve_config_cli_overrides() {
        let config = parse_config("min_diff_coverage_pct = 70").unwrap();
        let cli = CliOverrides {
            threshold_pct: Some(85.0),
            ..Default::default()
        };

        let effective = resolve_config(Some(&config), &cli);

        // CLI should override config
        assert_eq!(effective.threshold_pct, 85.0);
    }

    #[test]
    fn test_resolve_config_no_config() {
        let cli = CliOverrides::default();
        let effective = resolve_config(None, &cli);

        // Should use Team profile defaults
        assert_eq!(effective.threshold_pct, 80.0);
        assert_eq!(effective.fail_on, FailOn::Error);
    }

    #[test]
    fn test_matches_any_pattern() {
        assert!(matches_any_pattern(
            "target/debug/foo",
            &["target/**".to_string()]
        ));
        assert!(matches_any_pattern(
            "vendor/lib.rs",
            &["vendor/**".to_string()]
        ));
        assert!(!matches_any_pattern(
            "src/lib.rs",
            &["target/**".to_string()]
        ));
    }

    #[test]
    fn test_should_include_path() {
        let exclude = vec!["target/**".to_string(), "vendor/**".to_string()];
        let include = vec![];

        assert!(should_include_path("src/lib.rs", &include, &exclude));
        assert!(!should_include_path("target/debug/foo", &include, &exclude));
        assert!(!should_include_path("vendor/lib.rs", &include, &exclude));
    }

    #[test]
    fn test_should_include_path_with_allowlist() {
        let exclude = vec![];
        let include = vec!["src/**".to_string()];

        assert!(should_include_path("src/lib.rs", &include, &exclude));
        assert!(!should_include_path("tests/test.rs", &include, &exclude));
    }
}
