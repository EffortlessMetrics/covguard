//! Benchmarks for diff parsing performance.
//!
//! Run with: cargo bench --bench diff_parsing

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box as bb;

/// Generate a synthetic diff with the specified number of files and lines per file.
fn generate_synthetic_diff(num_files: usize, lines_per_file: usize) -> String {
    let mut diff = String::new();

    for file_idx in 0..num_files {
        let file_path = format!("src/module_{}/file_{}.rs", file_idx / 10, file_idx);
        let old_line = 1;
        let new_line = 1;

        // File header
        diff.push_str(&format!("diff --git a/{} b/{}\n", file_path, file_path));
        diff.push_str(&format!("--- a/{}\n", file_path));
        diff.push_str(&format!("+++ b/{}\n", file_path));

        // Hunk header
        let num_lines = lines_per_file;
        diff.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            old_line, num_lines, new_line, num_lines
        ));

        // Lines
        for line_idx in 0..lines_per_file {
            // Mix of added, removed, and context lines
            if line_idx % 3 == 0 {
                diff.push_str(&format!("+fn new_function_{}() {{\n", line_idx));
                diff.push_str(&format!("+    // Added line {}\n", line_idx));
                diff.push_str("+}\n");
            } else if line_idx % 3 == 1 {
                diff.push_str(&format!("-fn old_function_{}() {{\n", line_idx));
                diff.push_str(&format!("-    // Removed line {}\n", line_idx));
                diff.push_str("-}\n");
            } else {
                diff.push_str(&format!(" fn context_{}() {{\n", line_idx));
                diff.push_str(&format!("     // Context line {}\n", line_idx));
                diff.push_str(" }\n");
            }
        }
    }

    diff
}

/// Benchmark diff parsing with varying input sizes.
fn bench_diff_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_parsing");

    // Test different sizes
    for (num_files, lines_per_file) in [
        (10, 50),    // Small: 10 files, 50 lines each
        (50, 100),   // Medium: 50 files, 100 lines each
        (100, 200),  // Large: 100 files, 200 lines each
        (500, 100),  // Many files: 500 files, 100 lines each
    ] {
        let diff = generate_synthetic_diff(num_files, lines_per_file);
        let size_kb = diff.len() / 1024;

        group.throughput(Throughput::Bytes(diff.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(
                &format!("{}files_{}lines", num_files, lines_per_file),
                format!("{}KB", size_kb),
            ),
            &diff,
            |b, diff| {
                b.iter(|| {
                    // Simulate diff parsing - in real benchmark would call actual parser
                    let lines: Vec<&str> = black_box(diff.lines().collect());
                    let num_hunks = lines.iter().filter(|l| l.starts_with("@@")).count();
                    let num_added = lines.iter().filter(|l| l.starts_with('+')).count();
                    black_box((lines.len(), num_hunks, num_added))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark diff line iteration.
fn bench_diff_line_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_line_iteration");

    let large_diff = generate_synthetic_diff(100, 200);

    group.throughput(Throughput::Bytes(large_diff.len() as u64));
    group.bench_function("iterate_lines", |b| {
        b.iter(|| {
            for line in large_diff.lines() {
                black_box(line);
            }
        });
    });

    group.bench_function("filter_hunk_headers", |b| {
        b.iter(|| {
            let hunks: Vec<_> = large_diff
                .lines()
                .filter(|l| l.starts_with("@@"))
                .collect();
            black_box(hunks)
        });
    });

    group.finish();
}

/// Benchmark memory allocation patterns.
fn bench_diff_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("diff_allocation");

    let diff = generate_synthetic_diff(50, 100);

    group.bench_function("collect_lines", |b| {
        b.iter(|| black_box(diff.lines().collect::<Vec<_>>()));
    });

    group.bench_function("collect_chars", |b| {
        b.iter(|| black_box(diff.chars().collect::<Vec<_>>()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_diff_parsing,
    bench_diff_line_iteration,
    bench_diff_allocation,
);

criterion_main!(benches);
