//! covguard is a diff-scoped coverage gate that answers whether changed lines are covered by tests by consuming a diff (base<->head or patch) and LCOV coverage and emitting a canonical receipt plus optional PR outputs (markdown, annotations, SARIF).
//!
//! This is the entry point for the CLI tool.

use clap::Parser;
use covguard_cli_core::{EXIT_CODE_ERROR, run, write_fallback_receipt};
use covguard_cli_types::Commands;
use covguard_types::{EnhancedError, REASON_TOOL_ERROR};

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

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let exit_code = run_cli_with_args(args);
    std::process::ExitCode::from(u8::try_from(exit_code).unwrap_or(1))
}

fn run_cli_with_args(args: Vec<String>) -> i32 {
    match Cli::try_parse_from(&args) {
        Ok(cli) => match run(cli.command) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{}", e.format_enhanced());
                EXIT_CODE_ERROR
            }
        },
        Err(clap_err) => {
            // Check if cockpit mode was requested (scan args precisely)
            if is_cockpit_in_args(&args) {
                let out_path = extract_out_from_args(&args);
                let msg = format!("argument parsing failed: {}", clap_err);
                if write_fallback_receipt(&out_path, &msg, REASON_TOOL_ERROR, REASON_TOOL_ERROR)
                    .is_ok()
                {
                    eprintln!("warning: {}", msg);
                    eprintln!("wrote fallback receipt to {}", out_path);
                    0
                } else {
                    clap_exit(clap_err)
                }
            } else {
                clap_exit(clap_err)
            }
        }
    }
}

fn clap_exit(err: clap::Error) -> i32 {
    let _ = err.print();
    err.exit_code()
}

fn is_cockpit_in_args(args: &[String]) -> bool {
    // Check for --mode=cockpit
    if args.iter().any(|a| a == "--mode=cockpit") {
        return true;
    }
    // Check for --mode cockpit (two consecutive args)
    args.windows(2)
        .any(|pair| pair[0] == "--mode" && pair[1] == "cockpit")
}

fn extract_out_from_args(args: &[String]) -> String {
    // Check for --out=PATH
    for arg in args {
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
