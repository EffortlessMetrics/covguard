//! SARIF renderer for covguard reports.

use covguard_types::{CODE_REGISTRY, CodeInfo, Report, Severity};
use serde::Serialize;

/// Default maximum number of SARIF results to emit.
pub const DEFAULT_MAX_SARIF_RESULTS: usize = 1000;

/// SARIF report version 2.1.0
#[derive(Debug, Clone, Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

/// A single SARIF run
#[derive(Debug, Clone, Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

/// SARIF tool information
#[derive(Debug, Clone, Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

/// SARIF tool driver (main component)
#[derive(Debug, Clone, Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

/// SARIF rule definition
#[derive(Debug, Clone, Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "helpUri")]
    pub help_uri: String,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifRuleConfiguration,
}

/// SARIF rule configuration
#[derive(Debug, Clone, Serialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
}

/// SARIF message
#[derive(Debug, Clone, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// SARIF result (a finding)
#[derive(Debug, Clone, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

/// SARIF location
#[derive(Debug, Clone, Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

/// SARIF physical location
#[derive(Debug, Clone, Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

/// SARIF artifact location
#[derive(Debug, Clone, Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
}

/// SARIF region
#[derive(Debug, Clone, Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
}

/// Renders the report as a SARIF 2.1.0 JSON document.
pub fn render_sarif(report: &Report, max_results: usize) -> String {
    let sarif = build_sarif_report(report, max_results);
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

/// Build a SARIF report from a covguard report.
pub fn build_sarif_report(report: &Report, max_results: usize) -> SarifReport {
    let rules: Vec<SarifRule> = CODE_REGISTRY.iter().map(codeinfo_to_rule).collect();

    // Build rule index map
    let rule_index_map: std::collections::HashMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();

    // Convert findings to SARIF results
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .take(max_results)
        .filter_map(|finding| {
            let rule_index = rule_index_map.get(finding.code.as_str()).copied()?;

            let level = match finding.severity {
                Severity::Error => "error",
                Severity::Warn => "warning",
                Severity::Info => "note",
            };

            let locations = if let Some(ref loc) = finding.location {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: loc.path.clone(),
                            uri_base_id: "%SRCROOT%".to_string(),
                        },
                        region: loc.line.map(|line| SarifRegion {
                            start_line: line,
                            start_column: loc.col,
                        }),
                    },
                }]
            } else {
                vec![]
            };

            Some(SarifResult {
                rule_id: finding.code.clone(),
                rule_index,
                level: level.to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations,
            })
        })
        .collect();

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "covguard".to_string(),
                    version: report.tool.version.clone(),
                    information_uri: "https://github.com/EffortlessMetrics/covguard".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

fn codeinfo_to_rule(info: &CodeInfo) -> SarifRule {
    SarifRule {
        id: info.code.to_string(),
        name: info.name.to_string(),
        short_description: SarifMessage {
            text: info.short_description.to_string(),
        },
        full_description: SarifMessage {
            text: info.full_description.to_string(),
        },
        help_uri: info.help_uri.to_string(),
        default_configuration: SarifRuleConfiguration {
            level: "error".to_string(),
        },
    }
}
