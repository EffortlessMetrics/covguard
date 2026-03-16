//! Benchmarks for policy evaluation performance.
//!
//! Run with: cargo bench --bench policy_evaluation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

/// Generate synthetic changed ranges.
fn generate_changed_ranges(num_files: usize, lines_per_file: usize) -> BTreeMap<String, Vec<RangeInclusive<u32>>> {
    let mut ranges = BTreeMap::new();
    
    for file_idx in 0..num_files {
        let file_path = format!("src/module_{}/file_{}.rs", file_idx / 10, file_idx);
        let mut file_ranges = Vec::new();
        
        // Create ranges for changed lines
        let mut line = 1u32;
        while line <= lines_per_file as u32 {
            let end = (line + 10).min(lines_per_file as u32);
            file_ranges.push(line..=end);
            line = end + 20; // Gap between ranges
        }
        
        ranges.insert(file_path, file_ranges);
    }
    
    ranges
}

/// Generate synthetic coverage map.
fn generate_coverage_map(num_files: usize, lines_per_file: usize) -> BTreeMap<String, BTreeMap<u32, u32>> {
    let mut coverage = BTreeMap::new();
    
    for file_idx in 0..num_files {
        let file_path = format!("src/module_{}/file_{}.rs", file_idx / 10, file_idx);
        let mut file_coverage = BTreeMap::new();
        
        for line_idx in 1..=lines_per_file {
            // 80% coverage rate
            let hits = if line_idx % 5 == 0 { 0 } else { line_idx % 10 + 1 };
            file_coverage.insert(line_idx as u32, hits);
        }
        
        coverage.insert(file_path, file_coverage);
    }
    
    coverage
}

/// Simulated policy evaluation.
fn evaluate_policy(
    changed_ranges: &BTreeMap<String, Vec<RangeInclusive<u32>>>,
    coverage: &BTreeMap<String, BTreeMap<u32, u32>>,
    threshold_pct: f64,
) -> (u32, u32, u32) {
    let mut covered_lines = 0u32;
    let mut uncovered_lines = 0u32;
    let mut missing_lines = 0u32;
    
    for (path, ranges) in changed_ranges {
        let file_coverage = coverage.get(path);
        
        for range in ranges {
            for line in range.clone() {
                match file_coverage {
                    Some(coverage_map) => {
                        match coverage_map.get(&line) {
                            Some(&hits) if hits > 0 => covered_lines += 1,
                            Some(_) => uncovered_lines += 1,
                            None => missing_lines += 1,
                        }
                    }
                    None => missing_lines += 1,
                }
            }
        }
    }
    
    let total = covered_lines + uncovered_lines + missing_lines;
    let coverage_pct = if total > 0 {
        (covered_lines as f64 / total as f64) * 100.0
    } else {
        100.0
    };
    
    let passes = coverage_pct >= threshold_pct;
    black_box(passes);
    
    (covered_lines, uncovered_lines, missing_lines)
}

/// Benchmark policy evaluation with varying input sizes.
fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation");
    
    for (num_files, lines_per_file) in [
        (10, 100),
        (50, 200),
        (100, 500),
        (500, 200),
    ] {
        let changed_ranges = generate_changed_ranges(num_files, lines_per_file);
        let coverage = generate_coverage_map(num_files, lines_per_file);
        
        let total_lines: usize = changed_ranges.values()
            .map(|ranges| ranges.iter().map(|r| r.end() - r.start() + 1).sum::<u32>() as usize)
            .sum();
        
        group.throughput(Throughput::Elements(total_lines as u64));
        group.bench_with_input(
            BenchmarkId::new(
                &format!("{}files_{}lines", num_files, lines_per_file),
                total_lines,
            ),
            &(changed_ranges, coverage),
            |b, (changed_ranges, coverage)| {
                b.iter(|| {
                    evaluate_policy(changed_ranges, coverage, 80.0)
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark finding generation.
fn bench_finding_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("finding_generation");
    
    // Generate a large number of uncovered lines
    let num_uncovered = 1000;
    
    group.throughput(Throughput::Elements(num_uncovered));
    group.bench_function("generate_findings", |b| {
        b.iter(|| {
            let mut findings = Vec::new();
            for i in 0..num_uncovered {
                let file_idx = i / 100;
                let line = (i % 100) + 1;
                findings.push((
                    format!("src/file_{}.rs", file_idx),
                    line,
                    format!("Uncovered changed line (hits=0)."),
                ));
            }
            // Sort findings
            findings.sort();
            black_box(findings)
        });
    });
    
    group.finish();
}

/// Benchmark coverage percentage calculation.
fn bench_coverage_percentage(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_percentage");
    
    group.bench_function("calc_percentage", |b| {
        b.iter(|| {
            for covered in [0, 50, 80, 95, 100] {
                for total in [1, 10, 100, 1000, 10000] {
                    let covered_count = (total as f64 * covered as f64 / 100.0) as u32;
                    let pct = if total > 0 {
                        (covered_count as f64 / total as f64) * 100.0
                    } else {
                        100.0
                    };
                    black_box(pct);
                }
            }
        });
    });
    
    group.finish();
}

/// Benchmark ignored lines handling.
fn bench_ignored_lines(c: &mut Criterion) {
    let mut group = c.benchmark_group("ignored_lines");
    
    // Create ignored lines map
    let mut ignored: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    for file_idx in 0..50 {
        let file_path = format!("src/file_{}.rs", file_idx);
        let mut lines = BTreeSet::new();
        // Ignore ~10% of lines
        for line in (1..=200).step_by(10) {
            lines.insert(line);
        }
        ignored.insert(file_path, lines);
    }
    
    group.bench_function("check_ignored", |b| {
        b.iter(|| {
            let mut ignored_count = 0;
            for (file, lines) in &ignored {
                for line in 1..=200 {
                    if lines.contains(&line) {
                        ignored_count += 1;
                    }
                }
            }
            black_box(ignored_count)
        });
    });
    
    group.bench_function("batch_check_ignored", |b| {
        b.iter(|| {
            let mut ignored_count = 0;
            for (file, ignored_set) in &ignored {
                for line in ignored_set {
                    black_box(line);
                    ignored_count += 1;
                }
            }
            black_box(ignored_count)
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_policy_evaluation,
    bench_finding_generation,
    bench_coverage_percentage,
    bench_ignored_lines,
);

criterion_main!(benches);
