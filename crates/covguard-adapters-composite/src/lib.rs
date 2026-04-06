//! Composite coverage provider that delegates to multiple format-specific providers.
//!
//! This crate provides a `CompositeCoverageProvider` that implements the `CoverageProvider`
//! port by delegating to specialized adapters for LCOV, JaCoCo, and coverage.py.

use covguard_ports::{CoverageMap, CoverageProvider};

/// A coverage provider that delegates to multiple format-specific providers.
pub struct CompositeCoverageProvider {
    lcov: covguard_adapters_coverage::LcovCoverageProvider,
    jacoco: covguard_adapters_jacoco::JacocoCoverageProvider,
    coverage_py: covguard_adapters_coverage_py::CoveragePyProvider,
}

impl Default for CompositeCoverageProvider {
    fn default() -> Self {
        Self {
            lcov: covguard_adapters_coverage::LcovCoverageProvider,
            jacoco: covguard_adapters_jacoco::JacocoCoverageProvider,
            coverage_py: covguard_adapters_coverage_py::CoveragePyProvider,
        }
    }
}

impl CoverageProvider for CompositeCoverageProvider {
    fn parse_coverage(
        &self,
        text: &str,
        format: covguard_types::CoverageFormat,
        strip_prefixes: &[String],
    ) -> Result<CoverageMap, String> {
        match format {
            covguard_types::CoverageFormat::Lcov => {
                self.lcov.parse_coverage(text, format, strip_prefixes)
            }
            covguard_types::CoverageFormat::Jacoco => {
                self.jacoco.parse_coverage(text, format, strip_prefixes)
            }
            covguard_types::CoverageFormat::CoveragePy => {
                self.coverage_py
                    .parse_coverage(text, format, strip_prefixes)
            }
            covguard_types::CoverageFormat::Auto => {
                // Try each provider in order
                if let Ok(map) = self.lcov.parse_coverage(text, format, strip_prefixes) {
                    return Ok(map);
                }
                if let Ok(map) = self.jacoco.parse_coverage(text, format, strip_prefixes) {
                    return Ok(map);
                }
                if let Ok(map) = self
                    .coverage_py
                    .parse_coverage(text, format, strip_prefixes)
                {
                    return Ok(map);
                }
                Err("Failed to auto-detect coverage format".to_string())
            }
        }
    }

    fn merge_coverage(&self, maps: Vec<CoverageMap>) -> CoverageMap {
        // All providers use the same BTreeMap merging logic, so we can use any
        self.lcov.merge_coverage(maps)
    }
}
