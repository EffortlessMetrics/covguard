//! Shared types for covguard CLI.

use clap::{Subcommand, ValueEnum};
use covguard_config::Profile;

/// CLI operation mode
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliMode {
    /// Standard mode: exit based on verdict (0=pass/warn, 2=fail, 1=error)
    #[default]
    Standard,
    /// Cockpit mode: exit 0 if receipt written, exit 1 only on crash
    Cockpit,
}

/// CLI scope option
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliScope {
    Added,
    Touched,
}

/// CLI profile option
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliProfile {
    Oss,
    Moderate,
    Team,
    Strict,
    Lenient,
}

impl From<CliProfile> for Profile {
    fn from(profile: CliProfile) -> Self {
        match profile {
            CliProfile::Oss => Self::Oss,
            CliProfile::Moderate => Self::Moderate,
            CliProfile::Team => Self::Team,
            CliProfile::Strict => Self::Strict,
            CliProfile::Lenient => Self::Lenient,
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Commands {
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

        /// Path to LCOV coverage file (repeatable)
        #[arg(long)]
        lcov: Vec<String>,

        /// Path to JaCoCo XML coverage file (repeatable)
        #[arg(long)]
        jacoco: Vec<String>,

        /// Path to coverage.py JSON coverage file (repeatable)
        #[arg(long)]
        coverage_py: Vec<String>,

        /// Path to coverage file with auto-detected format (repeatable)
        #[arg(long)]
        coverage: Vec<String>,

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

        /// Maximum markdown lines emitted in report output.
        #[arg(long)]
        max_markdown_lines: Option<usize>,

        /// Maximum annotations emitted in report output.
        #[arg(long)]
        max_annotations: Option<usize>,

        /// Maximum SARIF results emitted in report output.
        #[arg(long)]
        max_sarif_results: Option<usize>,

        /// Maximum number of findings to include in report (truncation)
        #[arg(long)]
        max_findings: Option<usize>,

        /// Output path for full domain payload JSON (cockpit mode only)
        #[arg(long)]
        payload: Option<String>,

        /// Enable performance profiling output
        #[arg(long)]
        timing: bool,
    },
    /// Explain an error code
    Explain {
        /// Error code to explain
        code: String,
    },
}
