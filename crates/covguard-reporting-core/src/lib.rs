//! Core logic for covguard reporting.

use chrono::{DateTime, Utc};
use covguard_domain::EvalOutput;
use covguard_output::truncate_findings;
use covguard_reporting_types::ReportContext;
use covguard_types::{
    CHECK_ID_RUNTIME, CODE_RUNTIME_ERROR, Capabilities, Finding,
    InputCapability, InputStatus, InputsCapability, REASON_BELOW_THRESHOLD, REASON_DIFF_COVERED,
    REASON_MISSING_DIFF, REASON_MISSING_LCOV, REASON_NO_CHANGED_LINES, REASON_SKIPPED,
    REASON_TOOL_ERROR, REASON_TRUNCATED, REASON_UNCOVERED_LINES, Report, ReportData, SCHEMA_ID,
    SENSOR_SCHEMA_ID, Severity, Tool, Verdict, VerdictCounts, VerdictStatus, compute_fingerprint,
};

pub fn report_run(started_at: DateTime<Utc>, ended_at: DateTime<Utc>) -> covguard_types::Run {
    covguard_types::Run {
        started_at: started_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ended_at: Some(ended_at.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        duration_ms: Some((ended_at - started_at).num_milliseconds().max(0) as u64),
        capabilities: None,
    }
}

pub fn finding_counts(eval: &EvalOutput) -> VerdictCounts {
    VerdictCounts {
        info: eval
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Info)
            .count() as u32,
        warn: eval
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Warn)
            .count() as u32,
        error: eval
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count() as u32,
    }
}

/// Build a pair of reports: domain and optional cockpit receipt.
pub fn build_report_pair(
    eval: EvalOutput,
    context: &ReportContext,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    excluded_files_count: u32,
    debug: Option<serde_json::Value>,
) -> (Report, Option<Report>) {
    let inputs = context.inputs();
    let run = report_run(started_at, ended_at);
    let counts = finding_counts(&eval);
    let reasons = build_reasons(&eval);
    let scope = context.scope_str().to_string();
    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };

    let cockpit_receipt = if context.sensor_schema {
        let capabilities = Some(Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
                coverage: InputCapability {
                    status: InputStatus::Available,
                    reason: None,
                },
            },
        });

        let (cockpit_findings, cockpit_truncation) =
            truncate_findings(eval.findings.clone(), context.max_findings);

        let mut cockpit_reasons = reasons.clone();
        if cockpit_truncation.is_some() {
            cockpit_reasons.push(REASON_TRUNCATED.to_string());
        }

        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: covguard_types::Run {
                capabilities,
                ..run.clone()
            },
            verdict: Verdict {
                status: eval.verdict,
                counts: counts.clone(),
                reasons: cockpit_reasons,
            },
            findings: cockpit_findings,
            data: ReportData {
                scope: scope.clone(),
                threshold_pct: context.threshold_pct,
                changed_lines_total: eval.metrics.changed_lines_total,
                covered_lines: eval.metrics.covered_lines,
                uncovered_lines: eval.metrics.uncovered_lines,
                missing_lines: eval.metrics.missing_lines,
                ignored_lines_count: eval.metrics.ignored_lines,
                excluded_files_count,
                diff_coverage_pct: eval.metrics.diff_coverage_pct,
                inputs: inputs.clone(),
                debug: debug.clone(),
                truncation: cockpit_truncation,
            },
        })
    } else {
        None
    };

    let (domain_findings, domain_truncation) = if context.sensor_schema {
        (eval.findings, None)
    } else {
        truncate_findings(eval.findings, context.max_findings)
    };

    let mut domain_reasons = reasons;
    if domain_truncation.is_some() {
        domain_reasons.push(REASON_TRUNCATED.to_string());
    }

    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: covguard_types::Run {
            capabilities: None,
            ..run
        },
        verdict: Verdict {
            status: eval.verdict,
            counts,
            reasons: domain_reasons,
        },
        findings: domain_findings,
        data: ReportData {
            scope,
            threshold_pct: context.threshold_pct,
            changed_lines_total: eval.metrics.changed_lines_total,
            covered_lines: eval.metrics.covered_lines,
            uncovered_lines: eval.metrics.uncovered_lines,
            missing_lines: eval.metrics.missing_lines,
            ignored_lines_count: eval.metrics.ignored_lines,
            excluded_files_count,
            diff_coverage_pct: eval.metrics.diff_coverage_pct,
            inputs,
            debug,
            truncation: domain_truncation,
        },
    };

    (domain_report, cockpit_receipt)
}

/// Build only the domain report from evaluation output.
pub fn build_report(
    eval: EvalOutput,
    context: &ReportContext,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    excluded_files_count: u32,
    debug: Option<serde_json::Value>,
) -> Report {
    let (report, _) = build_report_pair(
        eval,
        context,
        started_at,
        ended_at,
        excluded_files_count,
        debug,
    );
    report
}

/// Build both domain report and optional cockpit receipt for runtime error cases.
pub fn build_error_report_pair(
    context: &ReportContext,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    code: &str,
    message: &str,
    diff_available: bool,
    coverage_available: bool,
) -> (Report, Option<Report>) {
    let inputs = context.inputs();

    let input_fp = compute_fingerprint(&[code, "covguard"]);
    let runtime_fp = compute_fingerprint(&[CODE_RUNTIME_ERROR, "covguard"]);

    let findings = vec![
        Finding {
            severity: Severity::Error,
            check_id: "input.invalid".to_string(),
            code: code.to_string(),
            message: message.to_string(),
            location: None,
            data: None,
            fingerprint: Some(input_fp),
        },
        Finding {
            severity: Severity::Error,
            check_id: CHECK_ID_RUNTIME.to_string(),
            code: CODE_RUNTIME_ERROR.to_string(),
            message: "covguard failed due to a runtime error.".to_string(),
            location: None,
            data: None,
            fingerprint: Some(runtime_fp),
        },
    ];

    let counts = VerdictCounts {
        info: 0,
        warn: 0,
        error: findings.len() as u32,
    };

    let scope = context.scope_str().to_string();
    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };
    let run = report_run(started_at, ended_at);

    let data = ReportData {
        scope,
        threshold_pct: context.threshold_pct,
        changed_lines_total: 0,
        covered_lines: 0,
        uncovered_lines: 0,
        missing_lines: 0,
        ignored_lines_count: 0,
        excluded_files_count: 0,
        diff_coverage_pct: 0.0,
        inputs,
        debug: None,
        truncation: None,
    };

    let cockpit_receipt = if context.sensor_schema {
        let capabilities = Some(Capabilities {
            inputs: InputsCapability {
                diff: InputCapability {
                    status: if diff_available {
                        InputStatus::Available
                    } else {
                        InputStatus::Unavailable
                    },
                    reason: if diff_available {
                        None
                    } else {
                        Some(REASON_MISSING_DIFF.to_string())
                    },
                },
                coverage: InputCapability {
                    status: if coverage_available {
                        InputStatus::Available
                    } else {
                        InputStatus::Unavailable
                    },
                    reason: if coverage_available {
                        None
                    } else {
                        Some(REASON_MISSING_LCOV.to_string())
                    },
                },
            },
        });

        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: covguard_types::Run {
                capabilities,
                ..run.clone()
            },
            verdict: Verdict {
                status: VerdictStatus::Fail,
                counts: counts.clone(),
                reasons: vec![REASON_TOOL_ERROR.to_string()],
            },
            findings: findings.clone(),
            data: data.clone(),
        })
    } else {
        None
    };

    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: covguard_types::Run {
            capabilities: None,
            ..run
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts,
            reasons: vec![REASON_TOOL_ERROR.to_string()],
        },
        findings,
        data,
    };

    (domain_report, cockpit_receipt)
}

/// Build both domain report and optional cockpit receipt for skip cases.
pub fn build_skip_report_pair(
    context: &ReportContext,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    diff_available: bool,
    coverage_available: bool,
    reason: &str,
) -> (Report, Option<Report>) {
    let inputs = context.inputs();
    let capabilities = Capabilities {
        inputs: InputsCapability {
            diff: InputCapability {
                status: if diff_available {
                    InputStatus::Available
                } else {
                    InputStatus::Unavailable
                },
                reason: if diff_available {
                    None
                } else {
                    Some(REASON_MISSING_DIFF.to_string())
                },
            },
            coverage: InputCapability {
                status: if coverage_available {
                    InputStatus::Available
                } else {
                    InputStatus::Unavailable
                },
                reason: if coverage_available {
                    None
                } else {
                    Some(REASON_MISSING_LCOV.to_string())
                },
            },
        },
    };

    let run = report_run(started_at, ended_at);
    let scope = context.scope_str().to_string();
    let tool = Tool {
        name: "covguard".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: None,
    };

    let data = ReportData {
        scope,
        threshold_pct: context.threshold_pct,
        changed_lines_total: 0,
        covered_lines: 0,
        uncovered_lines: 0,
        missing_lines: 0,
        ignored_lines_count: 0,
        excluded_files_count: 0,
        diff_coverage_pct: 0.0,
        inputs,
        debug: None,
        truncation: None,
    };

    let cockpit_receipt = if context.sensor_schema {
        Some(Report {
            schema: SENSOR_SCHEMA_ID.to_string(),
            tool: tool.clone(),
            run: covguard_types::Run {
                capabilities: Some(capabilities),
                ..run.clone()
            },
            verdict: Verdict {
                status: VerdictStatus::Skip,
                counts: VerdictCounts {
                    info: 0,
                    warn: 0,
                    error: 0,
                },
                reasons: vec![reason.to_string()],
            },
            findings: vec![],
            data: data.clone(),
        })
    } else {
        None
    };

    let domain_report = Report {
        schema: SCHEMA_ID.to_string(),
        tool,
        run: covguard_types::Run {
            capabilities: None,
            ..run
        },
        verdict: Verdict {
            status: VerdictStatus::Skip,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
            },
            reasons: vec![reason.to_string()],
        },
        findings: vec![],
        data,
    };

    (domain_report, cockpit_receipt)
}

/// Check if diff input looks invalid at a basic marker level.
pub fn is_invalid_diff(diff_text: &str) -> bool {
    let trimmed = diff_text.trim();
    if trimmed.is_empty() {
        return false;
    }

    let has_marker = trimmed.contains("diff --git")
        || trimmed.contains("@@")
        || trimmed.contains("+++ ")
        || trimmed.contains("--- ")
        || trimmed.contains("rename from ")
        || trimmed.contains("rename to ");
    !has_marker
}

/// Build report-level reasons from verdict metrics and findings.
pub fn build_reasons(output: &EvalOutput) -> Vec<String> {
    let mut reasons = Vec::new();

    match output.verdict {
        VerdictStatus::Pass => {
            if output.metrics.changed_lines_total == 0 {
                reasons.push(REASON_NO_CHANGED_LINES.to_string());
            } else {
                reasons.push(REASON_DIFF_COVERED.to_string());
            }
        }
        VerdictStatus::Warn | VerdictStatus::Fail => {
            if output.metrics.uncovered_lines > 0 {
                reasons.push(REASON_UNCOVERED_LINES.to_string());
            }
            if output.metrics.diff_coverage_pct < 100.0 {
                reasons.push(REASON_BELOW_THRESHOLD.to_string());
            }
        }
        VerdictStatus::Skip => {
            reasons.push(REASON_SKIPPED.to_string());
        }
    }

    reasons
}
