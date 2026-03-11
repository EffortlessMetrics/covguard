//! Integration tests for generated crypto-shaped fixtures.
//!
//! These tests use `uselesskey` so we can exercise PEM-like diff content
//! without committing keys or certificates into the repository.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;
use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};

fn covguard() -> Command {
    Command::new(env!("CARGO_BIN_EXE_covguard"))
}

fn deterministic_private_key_pem(seed_input: &str, key_id: &str) -> String {
    let seed = Seed::from_env_value(seed_input).expect("seed should be valid");
    let fx = Factory::deterministic(seed);

    fx.rsa(key_id, RsaSpec::rs256())
        .private_key_pkcs8_pem()
        .to_string()
}

fn secret_shaped_source_lines(private_key_pem: &str) -> Vec<String> {
    let mut lines = vec!["pub const TEST_KEY_PEM: &str = r#\"".to_string()];
    lines.extend(private_key_pem.lines().map(str::to_owned));
    lines.push("\"#;".to_string());
    lines.push("pub fn fixture_len() -> usize { TEST_KEY_PEM.len() }".to_string());
    lines
}

fn added_file_diff(path: &str, lines: &[String]) -> String {
    let mut diff = format!(
        "diff --git a/{path} b/{path}\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{} @@\n",
        lines.len()
    );

    for line in lines {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }

    diff
}

fn fully_covered_lcov(path: &str, line_count: usize) -> String {
    let mut lcov = format!("TN:\nSF:{path}\n");

    for line in 1..=line_count {
        lcov.push_str(&format!("DA:{line},1\n"));
    }

    lcov.push_str("end_of_record\n");
    lcov
}

#[test]
fn generated_private_key_fixture_is_deterministic() {
    let pem_a = deterministic_private_key_pem(module_path!(), "covguard-cli-generated-key");
    let pem_b = deterministic_private_key_pem(module_path!(), "covguard-cli-generated-key");

    assert_eq!(pem_a, pem_b);
    assert!(pem_a.contains("BEGIN PRIVATE KEY"));
    assert!(pem_a.contains("END PRIVATE KEY"));
}

#[test]
fn check_accepts_generated_secret_shaped_diff_fixture() {
    let temp = TempDir::new().unwrap();
    let diff_path = temp.path().join("generated.patch");
    let lcov_path = temp.path().join("generated.info");
    let out_path = temp.path().join("report.json");
    let source_path = "src/generated_secret_fixture.rs";

    let private_key_pem =
        deterministic_private_key_pem(module_path!(), "covguard-cli-generated-key");
    let source_lines = secret_shaped_source_lines(&private_key_pem);
    let diff = added_file_diff(source_path, &source_lines);
    let lcov = fully_covered_lcov(source_path, source_lines.len());

    fs::write(&diff_path, diff).unwrap();
    fs::write(&lcov_path, lcov).unwrap();

    covguard()
        .args([
            "check",
            "--diff-file",
            &diff_path.display().to_string(),
            "--lcov",
            &lcov_path.display().to_string(),
            "--out",
            &out_path.display().to_string(),
        ])
        .assert()
        .code(0);

    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();

    assert_eq!(report["verdict"]["status"], "pass");
    assert_eq!(report["data"]["changed_lines_total"], source_lines.len());
    assert_eq!(report["data"]["covered_lines"], source_lines.len());
    assert_eq!(report["data"]["uncovered_lines"], 0);
    assert_eq!(report["data"]["inputs"]["diff_source"], "diff-file");
}
