//! xtask - Development tasks for covguard
//!
//! This crate provides utilities for:
//! - Schema generation and validation
//! - Golden fixture management
//! - Report validation against JSON schemas
//! - Conformance testing for sensor.report.v1

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jsonschema::Validator;
use std::fs;
use std::path::{Path, PathBuf};

use covguard_types::{
    CODE_UNCOVERED_LINE, Finding, Inputs, REASON_BELOW_THRESHOLD, REASON_DIFF_COVERED,
    REASON_MISSING_DIFF, REASON_MISSING_LCOV, REASON_NO_CHANGED_LINES, REASON_SKIPPED,
    REASON_TOOL_ERROR, REASON_TRUNCATED, REASON_UNCOVERED_LINES, Report, ReportData, Run,
    SCHEMA_ID, Tool, Verdict, VerdictCounts, VerdictStatus, compute_fingerprint,
};

/// Exit code for validation failures (matches covguard convention)
const EXIT_VALIDATION_FAILURE: i32 = 2;

/// Development tasks for covguard
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development tasks for covguard", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate JSON schemas in the contracts/schemas/ directory
    Schema {
        /// Check schemas without writing (exits non-zero if invalid)
        #[arg(long)]
        check: bool,
    },

    /// Manage golden test fixtures
    Fixtures {
        /// Check fixtures match expected output (exits non-zero if different)
        #[arg(long, conflicts_with = "update")]
        check: bool,

        /// Update fixtures with current output
        #[arg(long, conflicts_with = "check")]
        update: bool,
    },

    /// Validate a report.json file against the schema
    Validate {
        /// Path to the report.json file to validate
        report_path: PathBuf,

        /// Path to custom schema file (defaults to schemas/covguard.report.v1.json)
        #[arg(long)]
        schema: Option<PathBuf>,
    },

    /// Run conformance tests for sensor.report.v1 compliance
    Conform {
        /// Run schema validation tests
        #[arg(long)]
        schema: bool,

        /// Run determinism tests (fixed inputs → identical output)
        #[arg(long)]
        determinism: bool,

        /// Run survivability tests (invalid input → valid receipt)
        #[arg(long)]
        survivability: bool,

        /// Run all conformance tests
        #[arg(long)]
        all: bool,

        /// Update golden fixtures for conformance tests
        #[arg(long)]
        update: bool,

        /// Directory containing JSON schemas (default: contracts/schemas/)
        #[arg(long, default_value = "contracts/schemas/")]
        schema_dir: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Schema { check } => cmd_schema(check),
        Commands::Fixtures { check, update } => cmd_fixtures(check, update),
        Commands::Validate {
            report_path,
            schema,
        } => cmd_validate(&report_path, schema.as_deref()),
        Commands::Conform {
            schema,
            determinism,
            survivability,
            all,
            update,
            schema_dir,
        } => cmd_conform(schema, determinism, survivability, all, update, &schema_dir),
    };

    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

// ============================================================================
// Schema Command
// ============================================================================

fn cmd_schema(check: bool) -> Result<()> {
    let project_root = find_project_root()?;
    let schemas_dir = project_root.join("contracts").join("schemas");

    if !schemas_dir.exists() {
        bail!("schemas directory not found at {}", schemas_dir.display());
    }

    let mut errors = Vec::new();
    let mut validated = 0;

    // Find all JSON files in schemas/
    for entry in fs::read_dir(&schemas_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|e| e == "json") {
            match validate_schema_file(&path, &schemas_dir) {
                Ok(()) => {
                    validated += 1;
                    if !check {
                        println!("  ok: {}", path.file_name().unwrap().to_string_lossy());
                    }
                }
                Err(e) => {
                    errors.push(format!("{}: {}", path.display(), e));
                }
            }
        }
    }

    if errors.is_empty() {
        println!("Validated {validated} schema(s) successfully.");
        Ok(())
    } else {
        for error in &errors {
            eprintln!("error: {error}");
        }
        std::process::exit(EXIT_VALIDATION_FAILURE);
    }
}

fn validate_schema_file(path: &Path, schemas_dir: &Path) -> Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    // First, validate it's valid JSON
    let value: serde_json::Value = serde_json::from_str(&content)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    // Check it has a $schema property (indicating it's a JSON Schema)
    let obj = value.as_object().context("schema must be a JSON object")?;

    if !obj.contains_key("$schema") {
        bail!("missing $schema property - not a valid JSON Schema");
    }

    // Check for local $ref references and validate they exist
    validate_refs(&value, schemas_dir)?;

    // Try to compile it as a JSON Schema to validate structure
    // Note: Schemas with local file $refs will fail to compile without a custom resolver,
    // so we only validate schemas that don't have allOf with $ref to local files
    if has_local_file_ref(&value) {
        // For schemas with local $refs, we verify the structure is valid JSON
        // and that all referenced files exist (done above in validate_refs)
        Ok(())
    } else {
        match Validator::new(&value) {
            Ok(_) => Ok(()),
            Err(e) => bail!("invalid JSON Schema: {e}"),
        }
    }
}

/// Check if the schema has any $ref pointing to local files
fn has_local_file_ref(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(ref_val) = obj.get("$ref")
                && let Some(ref_str) = ref_val.as_str()
            {
                // Local file refs start with "./" or are just filenames
                if ref_str.starts_with("./") || ref_str.ends_with(".json") {
                    return true;
                }
            }
            obj.values().any(has_local_file_ref)
        }
        serde_json::Value::Array(arr) => arr.iter().any(has_local_file_ref),
        _ => false,
    }
}

/// Validate that all $ref references point to existing files
fn validate_refs(value: &serde_json::Value, schemas_dir: &Path) -> Result<()> {
    match value {
        serde_json::Value::Object(obj) => {
            if let Some(ref_val) = obj.get("$ref")
                && let Some(ref_str) = ref_val.as_str()
            {
                // Check if it's a local file reference
                if let Some(stripped) = ref_str.strip_prefix("./") {
                    let ref_path = schemas_dir.join(stripped);
                    if !ref_path.exists() {
                        bail!("$ref points to non-existent file: {}", ref_str);
                    }
                } else if !ref_str.starts_with("http")
                    && !ref_str.starts_with("urn:")
                    && !ref_str.starts_with("#")
                {
                    // Might be a relative filename
                    let ref_path = schemas_dir.join(ref_str);
                    if ref_path.exists() {
                        // It's a valid local file reference
                    }
                }
            }
            for v in obj.values() {
                validate_refs(v, schemas_dir)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                validate_refs(v, schemas_dir)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ============================================================================
// Fixtures Command
// ============================================================================

fn cmd_fixtures(check: bool, update: bool) -> Result<()> {
    let project_root = find_project_root()?;
    let fixtures_dir = project_root.join("fixtures");
    let expected_dir = fixtures_dir.join("expected");

    if !fixtures_dir.exists() {
        bail!("fixtures directory not found at {}", fixtures_dir.display());
    }

    // Generate expected fixtures
    let fixtures = generate_fixtures()?;

    if check {
        // Compare with existing fixtures
        let mut has_differences = false;

        for (name, expected_content) in &fixtures {
            let fixture_path = expected_dir.join(name);

            if !fixture_path.exists() {
                eprintln!("missing: {name}");
                has_differences = true;
                continue;
            }

            let actual_content = fs::read_to_string(&fixture_path)
                .with_context(|| format!("failed to read {}", fixture_path.display()))?;

            // Normalize line endings for comparison
            let expected_normalized = expected_content.replace("\r\n", "\n");
            let actual_normalized = actual_content.replace("\r\n", "\n");

            if expected_normalized != actual_normalized {
                eprintln!("differs: {name}");
                has_differences = true;

                // Show a simple diff summary
                let expected_lines: Vec<&str> = expected_normalized.lines().collect();
                let actual_lines: Vec<&str> = actual_normalized.lines().collect();

                if expected_lines.len() != actual_lines.len() {
                    eprintln!(
                        "  line count: expected {}, got {}",
                        expected_lines.len(),
                        actual_lines.len()
                    );
                }
            }
        }

        if has_differences {
            eprintln!("\nRun 'cargo xtask fixtures --update' to update fixtures.");
            std::process::exit(EXIT_VALIDATION_FAILURE);
        } else {
            println!("All {} fixture(s) match.", fixtures.len());
        }
    } else if update {
        // Create expected directory if needed
        fs::create_dir_all(&expected_dir)?;

        for (name, content) in &fixtures {
            let fixture_path = expected_dir.join(name);
            fs::write(&fixture_path, content)
                .with_context(|| format!("failed to write {}", fixture_path.display()))?;
            println!("updated: {name}");
        }

        println!("\nUpdated {} fixture(s).", fixtures.len());
    } else {
        // Default: list fixtures that would be generated
        println!("Fixtures that would be generated:");
        for (name, _) in &fixtures {
            println!("  {name}");
        }
        println!("\nUse --check to verify or --update to regenerate.");
    }

    Ok(())
}

/// Generate all expected fixtures as (filename, content) pairs
fn generate_fixtures() -> Result<Vec<(String, String)>> {
    Ok(vec![
        // report_uncovered.json - Report with uncovered lines
        (
            "report_uncovered.json".to_string(),
            generate_report_uncovered()?,
        ),
        // report_covered.json - Report with all lines covered
        (
            "report_covered.json".to_string(),
            generate_report_covered()?,
        ),
    ])
}

fn generate_report_uncovered() -> Result<String> {
    let mut f1 = Finding::uncovered_line("src/lib.rs", 1, 0);
    f1.fingerprint = Some(compute_fingerprint(&[
        CODE_UNCOVERED_LINE,
        "src/lib.rs",
        "1",
    ]));
    let mut f2 = Finding::uncovered_line("src/lib.rs", 2, 0);
    f2.fingerprint = Some(compute_fingerprint(&[
        CODE_UNCOVERED_LINE,
        "src/lib.rs",
        "2",
    ]));
    let mut f3 = Finding::uncovered_line("src/lib.rs", 3, 0);
    f3.fingerprint = Some(compute_fingerprint(&[
        CODE_UNCOVERED_LINE,
        "src/lib.rs",
        "3",
    ]));

    let report = Report {
        schema: SCHEMA_ID.to_string(),
        tool: Tool {
            name: "covguard".to_string(),
            version: "0.2.0".to_string(),
            commit: None,
        },
        run: Run {
            started_at: "2026-02-02T00:00:00Z".to_string(),
            ended_at: None,
            duration_ms: None,
            capabilities: None,
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 3,
            },
            reasons: vec!["uncovered_lines".to_string()],
        },
        findings: vec![f1, f2, f3],
        data: ReportData {
            scope: "added".to_string(),
            threshold_pct: 80.0,
            changed_lines_total: 3,
            covered_lines: 0,
            uncovered_lines: 3,
            missing_lines: 0,
            ignored_lines_count: 0,
            excluded_files_count: 0,
            diff_coverage_pct: 0.0,
            inputs: Inputs {
                diff_source: "diff-file".to_string(),
                diff_file: Some("fixtures/diff/simple_added.patch".to_string()),
                base: None,
                head: None,
                lcov_paths: vec!["fixtures/lcov/uncovered.info".to_string()],
            },
            debug: None,
            truncation: None,
        },
    };

    serialize_report(&report)
}

fn generate_report_covered() -> Result<String> {
    let report = Report {
        schema: SCHEMA_ID.to_string(),
        tool: Tool {
            name: "covguard".to_string(),
            version: "0.2.0".to_string(),
            commit: None,
        },
        run: Run {
            started_at: "2026-02-02T00:00:00Z".to_string(),
            ended_at: None,
            duration_ms: None,
            capabilities: None,
        },
        verdict: Verdict {
            status: VerdictStatus::Pass,
            counts: VerdictCounts {
                info: 0,
                warn: 0,
                error: 0,
            },
            reasons: vec!["diff_covered".to_string()],
        },
        findings: vec![],
        data: ReportData {
            scope: "added".to_string(),
            threshold_pct: 80.0,
            changed_lines_total: 3,
            covered_lines: 3,
            uncovered_lines: 0,
            missing_lines: 0,
            ignored_lines_count: 0,
            excluded_files_count: 0,
            diff_coverage_pct: 100.0,
            inputs: Inputs {
                diff_source: "diff-file".to_string(),
                diff_file: Some("fixtures/diff/simple_added.patch".to_string()),
                base: None,
                head: None,
                lcov_paths: vec!["fixtures/lcov/covered.info".to_string()],
            },
            debug: None,
            truncation: None,
        },
    };

    serialize_report(&report)
}

/// Serialize a report to JSON with consistent formatting
fn serialize_report(report: &Report) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    // Ensure trailing newline for POSIX compliance
    Ok(json + "\n")
}

// ============================================================================
// Validate Command
// ============================================================================

fn cmd_validate(report_path: &Path, schema_path: Option<&Path>) -> Result<()> {
    let project_root = find_project_root()?;

    // Determine schema path
    let schema_path = match schema_path {
        Some(p) => p.to_path_buf(),
        None => project_root
            .join("contracts")
            .join("schemas")
            .join("covguard.report.v1.json"),
    };

    if !schema_path.exists() {
        bail!("schema not found at {}", schema_path.display());
    }

    if !report_path.exists() {
        bail!("report not found at {}", report_path.display());
    }

    // Load and compile the schema
    // We need to handle $ref to receipt.envelope.v1.json
    // For now, we'll use a simplified approach that validates the main structure
    let schema_content = fs::read_to_string(&schema_path)
        .with_context(|| format!("failed to read schema {}", schema_path.display()))?;

    let schema_value: serde_json::Value = serde_json::from_str(&schema_content)
        .with_context(|| format!("invalid JSON in schema {}", schema_path.display()))?;

    // Load the envelope schema for $ref resolution
    let envelope_path = schema_path
        .parent()
        .unwrap()
        .join("receipt.envelope.v1.json");
    let envelope_content = fs::read_to_string(&envelope_path).ok();

    // Build a combined schema that inlines the envelope
    // This is a workaround since jsonschema doesn't automatically resolve local $refs
    let validator = if let Some(envelope_str) = envelope_content {
        // Try to create validator with the schema as-is first
        // If that fails due to $ref, we'll use the envelope schema directly
        match Validator::new(&schema_value) {
            Ok(v) => v,
            Err(_) => {
                // Fall back to validating against envelope schema
                let envelope_value: serde_json::Value = serde_json::from_str(&envelope_str)?;
                Validator::new(&envelope_value).context("failed to compile envelope schema")?
            }
        }
    } else {
        Validator::new(&schema_value).context("failed to compile schema")?
    };

    // Load the report
    let report_content = fs::read_to_string(report_path)
        .with_context(|| format!("failed to read report {}", report_path.display()))?;

    let report_value: serde_json::Value = serde_json::from_str(&report_content)
        .with_context(|| format!("invalid JSON in report {}", report_path.display()))?;

    // Validate - collect all errors using iter()
    let errors: Vec<_> = validator.iter_errors(&report_value).collect();

    if errors.is_empty() {
        println!("Valid: {} conforms to schema", report_path.display());
        Ok(())
    } else {
        eprintln!("Validation errors in {}:", report_path.display());
        for error in &errors {
            eprintln!("  - {}: {}", error.instance_path(), error);
        }
        std::process::exit(EXIT_VALIDATION_FAILURE);
    }
}

// ============================================================================
// Conform Command
// ============================================================================

fn cmd_conform(
    schema: bool,
    determinism: bool,
    survivability: bool,
    all: bool,
    update: bool,
    schema_dir: &str,
) -> Result<()> {
    let run_all = all || (!schema && !determinism && !survivability);
    let project_root = find_project_root()?;
    let schemas_dir = if Path::new(schema_dir).is_absolute() {
        PathBuf::from(schema_dir)
    } else {
        project_root.join(schema_dir)
    };
    let mut passed = 0;
    let mut failed = 0;

    if run_all || schema {
        println!("=== Schema Validation Tests ===");
        match conform_schema(&project_root, &schemas_dir, update) {
            Ok(count) => {
                passed += count;
                println!("  {} schema tests passed", count);
            }
            Err(e) => {
                eprintln!("  Schema validation failed: {e}");
                failed += 1;
            }
        }
    }

    if run_all || determinism {
        println!("\n=== Determinism Tests ===");
        match conform_determinism(&project_root) {
            Ok(count) => {
                passed += count;
                println!("  {} determinism tests passed", count);
            }
            Err(e) => {
                eprintln!("  Determinism test failed: {e}");
                failed += 1;
            }
        }
    }

    if run_all || survivability {
        println!("\n=== Survivability Tests ===");
        match conform_survivability(&project_root, &schemas_dir, update) {
            Ok(count) => {
                passed += count;
                println!("  {} survivability tests passed", count);
            }
            Err(e) => {
                eprintln!("  Survivability test failed: {e}");
                failed += 1;
            }
        }
    }

    println!("\n=== Summary ===");
    println!("Passed: {passed}");
    println!("Failed: {failed}");

    if failed > 0 {
        std::process::exit(EXIT_VALIDATION_FAILURE);
    }

    Ok(())
}

/// Known reason tokens from the registry.
const KNOWN_REASON_TOKENS: &[&str] = &[
    REASON_MISSING_LCOV,
    REASON_MISSING_DIFF,
    REASON_NO_CHANGED_LINES,
    REASON_DIFF_COVERED,
    REASON_UNCOVERED_LINES,
    REASON_BELOW_THRESHOLD,
    REASON_TOOL_ERROR,
    REASON_SKIPPED,
    REASON_TRUNCATED,
];

/// Validate that all golden fixtures and contract fixtures conform to the envelope schema.
fn conform_schema(project_root: &Path, schemas_dir: &Path, _update: bool) -> Result<usize> {
    let expected_dir = project_root.join("fixtures").join("expected");
    let contracts_fixtures_dir = project_root.join("contracts").join("fixtures");

    // Load the envelope schema
    let envelope_path = schemas_dir.join("receipt.envelope.v1.json");
    let envelope_content = fs::read_to_string(&envelope_path)
        .with_context(|| format!("failed to read {}", envelope_path.display()))?;
    let envelope_schema: serde_json::Value = serde_json::from_str(&envelope_content)?;
    let validator =
        Validator::new(&envelope_schema).context("failed to compile envelope schema")?;

    let mut count = 0;

    // Validate all JSON files in fixtures/expected
    for entry in fs::read_dir(&expected_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|e| e == "json") {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("invalid JSON in {}", path.display()))?;

            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!(
                    "{} does not conform to schema: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            println!("  ok: {}", path.file_name().unwrap().to_string_lossy());
            count += 1;
        }
    }

    // Validate all JSON files in contracts/fixtures (excluding malformed.json)
    if contracts_fixtures_dir.exists() {
        for entry in fs::read_dir(&contracts_fixtures_dir)? {
            let entry = entry?;
            let path = entry.path();
            let filename = path.file_name().unwrap().to_string_lossy().to_string();

            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }

            // malformed.json is a negative test — it must fail to parse
            if filename == "malformed.json" {
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                if serde_json::from_str::<serde_json::Value>(&content).is_ok() {
                    bail!("malformed.json should fail JSON parse, but it parsed successfully");
                }
                println!("  ok: malformed.json fails to parse (negative test)");
                count += 1;
                continue;
            }

            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("invalid JSON in {}", path.display()))?;

            // Schema validation
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!(
                    "contracts/fixtures/{} does not conform to schema: {}",
                    filename,
                    errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Token lint: check reason values against known registry
            lint_reason_tokens(&value, &filename)?;

            // Sensor lint: check sensor.report.v1-specific constraints
            lint_sensor_constraints(&value, &filename)?;

            // Truncation lint: validate truncation metadata consistency
            lint_truncation_metadata(&value, &filename)?;

            println!("  ok: contracts/fixtures/{}", filename);
            count += 1;
        }
    }

    Ok(count)
}

/// Lint sensor.report.v1 constraints that can't be checked by the envelope schema alone.
fn lint_sensor_constraints(value: &serde_json::Value, filename: &str) -> Result<()> {
    // 1. Check if this is a sensor fixture
    let schema = value.get("schema").and_then(|v| v.as_str());
    if schema != Some("sensor.report.v1") {
        return Ok(()); // Not a sensor fixture, skip
    }

    // 2. run.capabilities must exist
    let capabilities = value.get("run").and_then(|r| r.get("capabilities"));
    anyhow::ensure!(
        capabilities.is_some(),
        "contracts/fixtures/{}: sensor.report.v1 requires run.capabilities",
        filename
    );

    // 3. capabilities.inputs must exist
    let inputs = capabilities.unwrap().get("inputs");
    anyhow::ensure!(
        inputs.is_some(),
        "contracts/fixtures/{}: sensor.report.v1 requires run.capabilities.inputs",
        filename
    );

    // 4. Each input must have valid status
    let valid_statuses = ["available", "unavailable", "skipped"];
    if let Some(inputs_obj) = inputs.unwrap().as_object() {
        for (key, input) in inputs_obj {
            let status = input.get("status").and_then(|s| s.as_str());
            anyhow::ensure!(
                status.is_some_and(|s| valid_statuses.contains(&s)),
                "contracts/fixtures/{}: input '{}' has invalid or missing status",
                filename,
                key
            );
            // If reason present, must match token pattern
            if let Some(reason) = input.get("reason").and_then(|r| r.as_str()) {
                anyhow::ensure!(
                    reason
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "contracts/fixtures/{}: input '{}' reason '{}' does not match ^[a-z0-9_]+$",
                    filename,
                    key,
                    reason
                );
            }
        }
    }

    println!("    sensor lint ok: {}", filename);
    Ok(())
}

/// Lint truncation metadata consistency in fixtures that have `data.truncation`.
///
/// When truncation is present, validates:
/// 1. `findings_truncated` must be `true`
/// 2. `shown` must equal `findings.len()`
/// 3. `total` must be >= `shown`
/// 4. `verdict.reasons` must contain `"truncated"`
fn lint_truncation_metadata(value: &serde_json::Value, filename: &str) -> Result<()> {
    let truncation = value.get("data").and_then(|d| d.get("truncation"));
    let truncation = match truncation {
        Some(t) if !t.is_null() => t,
        _ => return Ok(()), // No truncation metadata, skip
    };

    // 1. findings_truncated must be true
    let findings_truncated = truncation
        .get("findings_truncated")
        .and_then(|v| v.as_bool());
    anyhow::ensure!(
        findings_truncated == Some(true),
        "contracts/fixtures/{}: truncation.findings_truncated must be true, got {:?}",
        filename,
        findings_truncated
    );

    // 2. shown must equal findings.len()
    let shown = truncation.get("shown").and_then(|v| v.as_u64());
    let findings_len = value
        .get("findings")
        .and_then(|f| f.as_array())
        .map(|a| a.len() as u64);
    anyhow::ensure!(
        shown.is_some() && findings_len.is_some() && shown == findings_len,
        "contracts/fixtures/{}: truncation.shown ({:?}) must equal findings.len() ({:?})",
        filename,
        shown,
        findings_len
    );

    // 3. total must be >= shown
    let total = truncation.get("total").and_then(|v| v.as_u64());
    anyhow::ensure!(
        total.is_some() && shown.is_some() && total.unwrap() >= shown.unwrap(),
        "contracts/fixtures/{}: truncation.total ({:?}) must be >= shown ({:?})",
        filename,
        total,
        shown
    );

    // 4. verdict.reasons must contain "truncated"
    let has_truncated_reason = value
        .get("verdict")
        .and_then(|v| v.get("reasons"))
        .and_then(|r| r.as_array())
        .map(|reasons| reasons.iter().any(|r| r.as_str() == Some(REASON_TRUNCATED)))
        .unwrap_or(false);
    anyhow::ensure!(
        has_truncated_reason,
        "contracts/fixtures/{}: verdict.reasons must contain '{}' when truncation is present",
        filename,
        REASON_TRUNCATED
    );

    println!("    truncation lint ok: {}", filename);
    Ok(())
}

/// Lint that all reason tokens in a fixture match the known token registry.
fn lint_reason_tokens(value: &serde_json::Value, filename: &str) -> Result<()> {
    // Check verdict.reasons[]
    if let Some(reasons) = value
        .get("verdict")
        .and_then(|v| v.get("reasons"))
        .and_then(|r| r.as_array())
    {
        for reason in reasons {
            if let Some(token) = reason.as_str()
                && !KNOWN_REASON_TOKENS.contains(&token)
            {
                bail!("{}: unknown verdict reason token '{}'", filename, token);
            }
        }
    }

    // Check capabilities.inputs.*.reason
    if let Some(inputs) = value
        .get("run")
        .and_then(|r| r.get("capabilities"))
        .and_then(|c| c.get("inputs"))
        .and_then(|i| i.as_object())
    {
        for (key, cap) in inputs {
            if let Some(reason) = cap.get("reason").and_then(|r| r.as_str())
                && !KNOWN_REASON_TOKENS.contains(&reason)
            {
                bail!(
                    "{}: unknown capability reason token '{}' for input '{}'",
                    filename,
                    reason,
                    key
                );
            }
        }
    }

    Ok(())
}

/// Test that fixed inputs produce byte-identical output.
fn conform_determinism(project_root: &Path) -> Result<usize> {
    use std::process::Command;

    let fixtures_dir = project_root.join("fixtures");
    let diff_file = fixtures_dir.join("diff").join("simple_added.patch");
    let lcov_file = fixtures_dir.join("lcov").join("uncovered.info");

    if !diff_file.exists() || !lcov_file.exists() {
        bail!(
            "Required fixtures not found: {} or {}",
            diff_file.display(),
            lcov_file.display()
        );
    }

    // Run covguard twice with the same inputs
    let temp_dir = std::env::temp_dir().join("covguard-conform");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir)?;

    let run_covguard = |out_name: &str| -> Result<String> {
        let out_path = temp_dir.join(out_name);
        let output = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--diff-file",
                diff_file.to_str().unwrap(),
                "--lcov",
                lcov_file.to_str().unwrap(),
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()
            .context("failed to run covguard")?;

        // Read output file (may have exit code 2 for fail verdict, that's OK)
        if out_path.exists() {
            fs::read_to_string(&out_path).context("failed to read output")
        } else {
            bail!(
                "Output file not created. stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };

    let output1 = run_covguard("report1.json")?;
    let output2 = run_covguard("report2.json")?;

    // Parse both to normalize (ignore timing fields that vary)
    let mut json1: serde_json::Value = serde_json::from_str(&output1)?;
    let mut json2: serde_json::Value = serde_json::from_str(&output2)?;

    // Remove timing-sensitive fields for comparison
    if let Some(run) = json1.get_mut("run").and_then(|r| r.as_object_mut()) {
        run.remove("started_at");
        run.remove("ended_at");
        run.remove("duration_ms");
    }
    if let Some(run) = json2.get_mut("run").and_then(|r| r.as_object_mut()) {
        run.remove("started_at");
        run.remove("ended_at");
        run.remove("duration_ms");
    }

    if json1 != json2 {
        bail!(
            "Determinism check failed: outputs differ\nFirst:\n{}\nSecond:\n{}",
            serde_json::to_string_pretty(&json1)?,
            serde_json::to_string_pretty(&json2)?
        );
    }

    println!("  ok: identical outputs for same inputs");
    Ok(1)
}

/// Test that invalid inputs produce valid receipts instead of crashing.
fn conform_survivability(project_root: &Path, schemas_dir: &Path, update: bool) -> Result<usize> {
    use std::process::Command;

    let fixtures_dir = project_root.join("fixtures");
    let expected_dir = fixtures_dir.join("expected");

    // Load envelope schema for validation
    let envelope_path = schemas_dir.join("receipt.envelope.v1.json");
    let envelope_content = fs::read_to_string(&envelope_path)?;
    let envelope_schema: serde_json::Value = serde_json::from_str(&envelope_content)?;
    let validator = Validator::new(&envelope_schema)?;

    let temp_dir = std::env::temp_dir().join("covguard-survivability");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir)?;

    let mut count = 0;

    // Test 1: Invalid diff
    {
        let out_path = temp_dir.join("report_invalid_diff.json");
        let invalid_diff = temp_dir.join("invalid.patch");
        fs::write(&invalid_diff, "this is not a valid diff\njust random text")?;
        let valid_lcov = fixtures_dir.join("lcov").join("covered.info");

        let _ = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--diff-file",
                invalid_diff.to_str().unwrap(),
                "--lcov",
                valid_lcov.to_str().unwrap(),
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()?;

        if out_path.exists() {
            let content = fs::read_to_string(&out_path)?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            // Validate against schema
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!("Invalid diff test: output does not conform to schema");
            }

            // Should be fail verdict with error code
            if value["verdict"]["status"] != "fail" {
                bail!("Invalid diff test: expected fail verdict");
            }

            println!("  ok: invalid diff produces valid fail receipt");
            count += 1;

            if update {
                let golden_path = expected_dir.join("report_invalid_diff.json");
                let pretty = serde_json::to_string_pretty(&value)? + "\n";
                fs::write(&golden_path, pretty)?;
                println!("  updated: report_invalid_diff.json");
            }
        } else {
            bail!("Invalid diff test: no output file created");
        }
    }

    // Test 2: Invalid LCOV
    {
        let out_path = temp_dir.join("report_invalid_lcov.json");
        let valid_diff = fixtures_dir.join("diff").join("simple_added.patch");
        let invalid_lcov = temp_dir.join("invalid.info");
        fs::write(&invalid_lcov, "DA:1,1\nend_of_record\n")?; // DA without SF

        let _ = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--diff-file",
                valid_diff.to_str().unwrap(),
                "--lcov",
                invalid_lcov.to_str().unwrap(),
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()?;

        if out_path.exists() {
            let content = fs::read_to_string(&out_path)?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            // Validate against schema
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!("Invalid LCOV test: output does not conform to schema");
            }

            // Should be fail verdict with error code
            if value["verdict"]["status"] != "fail" {
                bail!("Invalid LCOV test: expected fail verdict");
            }

            println!("  ok: invalid LCOV produces valid fail receipt");
            count += 1;

            if update {
                let golden_path = expected_dir.join("report_invalid_lcov.json");
                let pretty = serde_json::to_string_pretty(&value)? + "\n";
                fs::write(&golden_path, pretty)?;
                println!("  updated: report_invalid_lcov.json");
            }
        } else {
            bail!("Invalid LCOV test: no output file created");
        }
    }

    // Test 3: Missing LCOV in cockpit mode (should skip, not error)
    {
        let out_path = temp_dir.join("report_skip_cockpit.json");
        let valid_diff = fixtures_dir.join("diff").join("simple_added.patch");

        let output = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--mode",
                "cockpit",
                "--diff-file",
                valid_diff.to_str().unwrap(),
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()?;

        if out_path.exists() {
            let content = fs::read_to_string(&out_path)?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            // Validate against schema
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!("Missing LCOV cockpit test: output does not conform to schema");
            }

            // Should be skip verdict
            if value["verdict"]["status"] != "skip" {
                bail!(
                    "Missing LCOV cockpit test: expected skip verdict, got {}",
                    value["verdict"]["status"]
                );
            }

            // Should have capabilities block
            if value["run"]["capabilities"].is_null() {
                bail!("Missing LCOV cockpit test: expected capabilities block");
            }

            // Exit code should be 0
            if !output.status.success() {
                bail!(
                    "Missing LCOV cockpit test: expected exit code 0, got {}",
                    output.status.code().unwrap_or(-1)
                );
            }

            println!("  ok: missing LCOV in cockpit mode produces valid skip receipt with exit 0");
            count += 1;

            if update {
                let golden_path = expected_dir.join("report_skip_no_coverage.json");
                let pretty = serde_json::to_string_pretty(&value)? + "\n";
                fs::write(&golden_path, pretty)?;
                println!("  updated: report_skip_no_coverage.json");
            }
        } else {
            bail!(
                "Missing LCOV cockpit test: no output file created. stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Test 4: Missing diff file in cockpit mode (should produce fallback receipt, exit 0)
    {
        let out_path = temp_dir.join("report_missing_diff_cockpit.json");

        let output = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--mode",
                "cockpit",
                "--diff-file",
                "/nonexistent/path/to/diff.patch",
                "--lcov",
                fixtures_dir
                    .join("lcov")
                    .join("covered.info")
                    .to_str()
                    .unwrap(),
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()?;

        if out_path.exists() {
            let content = fs::read_to_string(&out_path)?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            // Validate against schema
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!(
                    "Missing diff cockpit test: output does not conform to schema: {}",
                    errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Should be fail verdict
            if value["verdict"]["status"] != "fail" {
                bail!(
                    "Missing diff cockpit test: expected fail verdict, got {}",
                    value["verdict"]["status"]
                );
            }

            // Exit code should be 0 (cockpit mode wrote receipt)
            if !output.status.success() {
                bail!(
                    "Missing diff cockpit test: expected exit code 0, got {}",
                    output.status.code().unwrap_or(-1)
                );
            }

            println!(
                "  ok: missing diff file in cockpit mode produces fallback receipt with exit 0"
            );
            count += 1;
        } else {
            bail!(
                "Missing diff cockpit test: no output file created. stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Test 5: Missing LCOV file in cockpit mode (should produce fallback receipt, exit 0)
    {
        let out_path = temp_dir.join("report_missing_lcov_file_cockpit.json");
        let valid_diff = fixtures_dir.join("diff").join("simple_added.patch");

        let output = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--mode",
                "cockpit",
                "--diff-file",
                valid_diff.to_str().unwrap(),
                "--lcov",
                "/nonexistent/path/to/coverage.info",
                "--out",
                out_path.to_str().unwrap(),
            ])
            .output()?;

        if out_path.exists() {
            let content = fs::read_to_string(&out_path)?;
            let value: serde_json::Value = serde_json::from_str(&content)?;

            // Validate against schema
            let errors: Vec<_> = validator.iter_errors(&value).collect();
            if !errors.is_empty() {
                bail!(
                    "Missing LCOV file cockpit test: output does not conform to schema: {}",
                    errors
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Should be fail verdict
            if value["verdict"]["status"] != "fail" {
                bail!(
                    "Missing LCOV file cockpit test: expected fail verdict, got {}",
                    value["verdict"]["status"]
                );
            }

            // Exit code should be 0 (cockpit mode wrote receipt)
            if !output.status.success() {
                bail!(
                    "Missing LCOV file cockpit test: expected exit code 0, got {}",
                    output.status.code().unwrap_or(-1)
                );
            }

            println!(
                "  ok: missing LCOV file in cockpit mode produces fallback receipt with exit 0"
            );
            count += 1;
        } else {
            bail!(
                "Missing LCOV file cockpit test: no output file created. stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Test 6: Invalid output path in cockpit mode (can't write receipt, exit 1)
    {
        let valid_diff = fixtures_dir.join("diff").join("simple_added.patch");

        // Use a path that's guaranteed to fail on all platforms
        // (NUL is reserved on Windows, /dev/null/subdir is invalid on Unix)
        let invalid_out = if cfg!(windows) {
            "Z:\\nonexistent_drive_9999\\deeply\\nested\\report.json".to_string()
        } else {
            "/dev/null/impossible/path/report.json".to_string()
        };

        let output = Command::new("cargo")
            .current_dir(project_root)
            .args([
                "run",
                "--quiet",
                "--bin",
                "covguard",
                "--",
                "check",
                "--mode",
                "cockpit",
                "--diff-file",
                valid_diff.to_str().unwrap(),
                "--out",
                &invalid_out,
            ])
            .output()?;

        // This should fail with exit 1 because we can't write the receipt
        if output.status.success() {
            bail!("Invalid output path cockpit test: expected non-zero exit, got 0");
        }

        println!("  ok: invalid output path in cockpit mode exits non-zero");
        count += 1;
    }

    Ok(count)
}

// ============================================================================
// Utilities
// ============================================================================

/// Find the project root by looking for Cargo.toml with [workspace]
fn find_project_root() -> Result<PathBuf> {
    let mut current = std::env::current_dir()?;

    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            let content = fs::read_to_string(&cargo_toml)?;
            if content.contains("[workspace]") {
                return Ok(current);
            }
        }

        if !current.pop() {
            bail!("could not find workspace root (no Cargo.toml with [workspace] found)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_project_root() {
        // This test assumes we're running from within the project
        let root = find_project_root().unwrap();
        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("contracts").join("schemas").exists());
    }

    #[test]
    fn test_generate_fixtures() {
        let fixtures = generate_fixtures().unwrap();
        assert!(!fixtures.is_empty());

        // Check that we generate the expected fixtures
        let names: Vec<&str> = fixtures.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"report_uncovered.json"));
        assert!(names.contains(&"report_covered.json"));
    }

    #[test]
    fn test_report_uncovered_is_valid_json() {
        let content = generate_report_uncovered().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["schema"], "covguard.report.v1");
        assert_eq!(parsed["verdict"]["status"], "fail");
    }

    #[test]
    fn test_report_covered_is_valid_json() {
        let content = generate_report_covered().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["schema"], "covguard.report.v1");
        assert_eq!(parsed["verdict"]["status"], "pass");
    }
}
