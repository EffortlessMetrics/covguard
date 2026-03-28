//! Benchmarks for report generation performance.
//!
//! Run with: cargo bench --bench report_generation

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use serde_json::json;

/// Generate synthetic findings for benchmarking.
fn generate_findings(count: usize) -> Vec<(String, u32, String)> {
    (0..count)
        .map(|i| {
            let file_idx = i / 50;
            let line = (i % 50) as u32 + 1;
            (
                format!("src/module_{}/file_{}.rs", file_idx / 10, file_idx),
                line,
                "Uncovered changed line (hits=0).".to_string(),
            )
        })
        .collect()
}

/// Benchmark markdown rendering.
fn bench_markdown_rendering(c: &mut Criterion) {
    let mut group = c.benchmark_group("markdown_rendering");

    for count in [10, 50, 100, 500, 1000] {
        let findings = generate_findings(count);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("render_table", count),
            &findings,
            |b, findings| {
                b.iter(|| {
                    let mut output = String::new();
                    output.push_str("## covguard: Diff Coverage Report\n\n");
                    output.push_str("**Status**: ❌ fail\n\n");
                    output.push_str("### Summary\n");
                    output.push_str("- **Diff coverage**: 75.0%\n");
                    output.push_str("- **Changed lines**: 1000\n");
                    output.push_str("- **Covered**: 750\n");
                    output.push_str("- **Uncovered**: 250\n\n");

                    output.push_str("### Uncovered Lines\n\n");
                    output.push_str("| File | Line | Hits |\n");
                    output.push_str("|------|------|------|\n");

                    for (path, line, _msg) in findings.iter().take(10) {
                        output.push_str(&format!("| {} | {} | 0 |\n", path, line));
                    }

                    if findings.len() > 10 {
                        output.push_str(&format!(
                            "\n*Showing 10 of {} uncovered lines*\n",
                            findings.len()
                        ));
                    }

                    black_box(output)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark SARIF rendering.
fn bench_sarif_rendering(c: &mut Criterion) {
    let mut group = c.benchmark_group("sarif_rendering");

    for count in [10, 50, 100, 500, 1000] {
        let findings = generate_findings(count);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("render_sarif", count),
            &findings,
            |b, findings| {
                b.iter(|| {
                    let mut results = Vec::new();

                    for (path, line, msg) in findings {
                        results.push(json!({
                            "ruleId": "diff.uncovered_line",
                            "level": "error",
                            "message": {
                                "text": msg
                            },
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": path
                                    },
                                    "region": {
                                        "startLine": line
                                    }
                                }
                            }]
                        }));
                    }

                    let sarif = json!({
                        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                        "version": "2.1.0",
                        "runs": [{
                            "tool": {
                                "driver": {
                                    "name": "covguard",
                                    "version": "0.1.0",
                                    "informationUri": "https://github.com/EffortlessMetrics/covguard"
                                }
                            },
                            "results": results
                        }]
                    });

                    black_box(sarif)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark JSON serialization.
fn bench_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");

    let findings = generate_findings(100);

    let report = json!({
        "schema": "covguard.report.v1",
        "verdict": {
            "status": "fail",
            "reason": "Coverage below threshold"
        },
        "data": {
            "diff_coverage_pct": 75.0,
            "changed_lines_total": 1000,
            "covered_lines": 750,
            "uncovered_lines": 250,
            "findings_count": findings.len()
        },
        "findings": findings.iter().map(|(path, line, msg)| {
            json!({
                "severity": "error",
                "code": "covguard.diff.uncovered_line",
                "message": msg,
                "location": {
                    "path": path,
                    "line": line
                }
            })
        }).collect::<Vec<_>>()
    });

    group.throughput(Throughput::Bytes(
        serde_json::to_string(&report).unwrap().len() as u64,
    ));
    group.bench_function("serialize_report", |b| {
        b.iter(|| {
            let json = serde_json::to_string(&report).unwrap();
            black_box(json)
        });
    });

    let json_str = serde_json::to_string(&report).unwrap();
    group.bench_function("deserialize_report", |b| {
        b.iter(|| {
            let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
            black_box(parsed)
        });
    });

    group.finish();
}

/// Benchmark string formatting operations.
fn bench_string_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_formatting");

    group.bench_function("format_path_line", |b| {
        b.iter(|| {
            let mut output = String::new();
            for i in 0..100 {
                output.push_str(&format!("src/file_{}.rs:{}", i, i * 10));
            }
            black_box(output)
        });
    });

    group.bench_function("format_percentage", |b| {
        b.iter(|| {
            let mut output = String::new();
            for i in 0..100 {
                output.push_str(&format!("{:.1}%", i as f64));
            }
            black_box(output)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_markdown_rendering,
    bench_sarif_rendering,
    bench_json_serialization,
    bench_string_formatting,
);

criterion_main!(benches);
