//! Shared policy model for coverage policy evaluation and profile-based presets.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

// ============================================================================
// Policy enums
// ============================================================================

/// Scope of lines to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Only evaluate added lines.
    #[default]
    Added,
    /// Evaluate all touched (added + modified) lines.
    Touched,
}

impl Scope {
    /// Render the scope as the canonical protocol string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Touched => "touched",
        }
    }
}

/// Determines when the evaluation should fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MissingBehavior {
    /// Skip missing coverage from the percentage and do not emit missing-file findings.
    Skip,
    /// Warn on missing coverage (default behavior).
    #[default]
    Warn,
    /// Fail on missing coverage.
    Fail,
}

/// Built-in policy profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Open-source-friendly: warn on missing data, never fail.
    Oss,
    /// Transitional profile for teams still stabilizing strictness.
    Moderate,
    /// Team standard profile.
    #[default]
    Team,
    /// Strict profile for higher-quality checks.
    Strict,
    /// Lenient profile for exploratory or onboarding runs.
    Lenient,
}

impl Profile {
    /// Canonical string representation of the profile.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Oss => "oss",
            Self::Moderate => "moderate",
            Self::Team => "team",
            Self::Strict => "strict",
            Self::Lenient => "lenient",
        }
    }

    /// Resolve full policy settings for a profile.
    pub const fn flags(self) -> ProfileFlags {
        match self {
            Self::Oss => ProfileFlags {
                scope: Scope::Added,
                fail_on: FailOn::Never,
                threshold_pct: 70.0,
                max_uncovered_lines: None,
                missing_coverage: MissingBehavior::Skip,
                missing_file: MissingBehavior::Skip,
                ignore_directives: true,
            },
            Self::Moderate => ProfileFlags {
                scope: Scope::Added,
                fail_on: FailOn::Error,
                threshold_pct: 75.0,
                max_uncovered_lines: None,
                missing_coverage: MissingBehavior::Warn,
                missing_file: MissingBehavior::Skip,
                ignore_directives: true,
            },
            Self::Team => ProfileFlags {
                scope: Scope::Added,
                fail_on: FailOn::Error,
                threshold_pct: 80.0,
                max_uncovered_lines: None,
                missing_coverage: MissingBehavior::Warn,
                missing_file: MissingBehavior::Warn,
                ignore_directives: true,
            },
            Self::Strict => ProfileFlags {
                scope: Scope::Touched,
                fail_on: FailOn::Error,
                threshold_pct: 90.0,
                max_uncovered_lines: Some(5),
                missing_coverage: MissingBehavior::Fail,
                missing_file: MissingBehavior::Fail,
                ignore_directives: true,
            },
            Self::Lenient => ProfileFlags {
                scope: Scope::Added,
                fail_on: FailOn::Never,
                threshold_pct: 0.0,
                max_uncovered_lines: None,
                missing_coverage: MissingBehavior::Warn,
                missing_file: MissingBehavior::Warn,
                ignore_directives: true,
            },
        }
    }
}

/// Parse a profile by case-insensitive label.
pub fn profile_from_name(name: &str) -> Option<Profile> {
    match name.to_ascii_lowercase().as_str() {
        "oss" => Some(Profile::Oss),
        "moderate" => Some(Profile::Moderate),
        "team" => Some(Profile::Team),
        "strict" => Some(Profile::Strict),
        "lenient" => Some(Profile::Lenient),
        _ => None,
    }
}

impl FromStr for Profile {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        profile_from_name(name).ok_or(())
    }
}

/// Concrete policy settings for a profile.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProfileFlags {
    /// Which lines to evaluate.
    pub scope: Scope,
    /// Failure semantics for error-level and warn-level findings.
    pub fail_on: FailOn,
    /// Minimum diff coverage threshold.
    pub threshold_pct: f64,
    /// Maximum allowed uncovered lines before surfacing as error-level findings.
    pub max_uncovered_lines: Option<u32>,
    /// Missing coverage behavior for individual lines.
    pub missing_coverage: MissingBehavior,
    /// Missing coverage behavior for entire files.
    pub missing_file: MissingBehavior,
    /// Whether ignore directives can disable coverage checks for specific lines.
    pub ignore_directives: bool,
}

/// Resolve profile default flags.
pub const fn profile_defaults(profile: Profile) -> ProfileFlags {
    profile.flags()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_str() {
        assert_eq!(Scope::Added.as_str(), "added");
        assert_eq!(Scope::Touched.as_str(), "touched");
    }

    #[test]
    fn test_profile_flags_have_expected_thresholds() {
        assert_eq!(profile_defaults(Profile::Oss).threshold_pct, 70.0);
        assert_eq!(profile_defaults(Profile::Moderate).threshold_pct, 75.0);
        assert_eq!(profile_defaults(Profile::Team).threshold_pct, 80.0);
        assert_eq!(profile_defaults(Profile::Strict).threshold_pct, 90.0);
        assert_eq!(profile_defaults(Profile::Lenient).threshold_pct, 0.0);
    }

    #[test]
    fn test_profile_from_name_parsing() {
        assert_eq!(Profile::from_str("OSS").ok(), Some(Profile::Oss));
        assert_eq!(Profile::from_str("lenient").ok(), Some(Profile::Lenient));
        assert_eq!(profile_from_name("unknown"), None);
    }

    #[test]
    fn test_profile_default_behavior() {
        assert_eq!(profile_defaults(Profile::Lenient).fail_on, FailOn::Never);
        assert_eq!(profile_defaults(Profile::Strict).max_uncovered_lines, Some(5));
        assert_eq!(profile_defaults(Profile::Strict).scope, Scope::Touched);
    }
}
