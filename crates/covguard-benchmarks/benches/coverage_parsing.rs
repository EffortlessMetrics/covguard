//! Benchmarks for coverage parsing performance.
//!
//! Run with: cargo bench --bench coverage_parsing

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::collections::BTreeMap;

/// Generate a synthetic LCOV coverage file.
fn generate_synthetic_lcov(num_files: usize, lines_per_file: usize) -> String {
    let mut lcov = String::new();

    for file_idx in 0..num_files {
        let file_path = format!("src/module_{}/file_{}.rs", file_idx / 10, file_idx);

        // Source file record
        lcov.push_str(&format!("SF:{}\n", file_path));

        // Line coverage records
        for line_idx in 1..=lines_per_file {
            // Vary coverage: 80% covered
            let hits = if line_idx % 5 == 0 {
                0
            } else {
                line_idx % 10 + 1
            };
            lcov.push_str(&format!("DA:{},{}\n", line_idx, hits));
        }

        // End of file record
        lcov.push_str("end_of_record\n");
    }

    lcov
}

/// Benchmark LCOV parsing with varying input sizes.
fn bench_lcov_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("lcov_parsing");

    // Test different sizes
    for (num_files, lines_per_file) in [
        (10, 100),   // Small: 10 files, 100 lines each
        (50, 200),   // Medium: 50 files, 200 lines each
        (100, 500),  // Large: 100 files, 500 lines each
        (500, 200),  // Many files: 500 files, 200 lines each
        (1000, 100), // Very many files: 1000 files, 100 lines each
    ] {
        let lcov = generate_synthetic_lcov(num_files, lines_per_file);
        let size_kb = lcov.len() / 1024;

        group.throughput(Throughput::Bytes(lcov.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(
                format!("{}files_{}lines", num_files, lines_per_file),
                format!("{}KB", size_kb),
            ),
            &lcov,
            |b, lcov| {
                b.iter(|| {
                    // Simulate LCOV parsing
                    let mut current_file: Option<String> = None;
                    let mut coverage: BTreeMap<String, BTreeMap<u32, u32>> = BTreeMap::new();

                    for line in lcov.lines() {
                        if let Some(sf_path) = line.strip_prefix("SF:") {
                            current_file = Some(sf_path.to_string());
                            coverage.entry(sf_path.to_string()).or_default();
                        } else if let Some(da_data) = line.strip_prefix("DA:")
                            && let Some(file) = &current_file {
                                let parts: Vec<&str> = da_data.split(',').collect();
                                if parts.len() >= 2
                                    && let (Ok(line_num), Ok(hits)) =
                                        (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                                    {
                                        coverage.get_mut(file).unwrap().insert(line_num, hits);
                                    }
                            }
                    }

                    black_box(coverage)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark coverage map operations.
fn bench_coverage_map_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_map");

    // Create a large coverage map
    let mut coverage: BTreeMap<String, BTreeMap<u32, u32>> = BTreeMap::new();
    for file_idx in 0..100 {
        let file_path = format!("src/file_{}.rs", file_idx);
        let mut lines: BTreeMap<u32, u32> = BTreeMap::new();
        for line_idx in 1..=500 {
            lines.insert(
                line_idx,
                if line_idx % 5 == 0 {
                    0
                } else {
                    line_idx % 10 + 1
                },
            );
        }
        coverage.insert(file_path, lines);
    }

    group.bench_function("lookup_file", |b| {
        b.iter(|| {
            for i in 0..100 {
                let path = format!("src/file_{}.rs", i);
                black_box(coverage.get(&path));
            }
        });
    });

    group.bench_function("lookup_line", |b| {
        b.iter(|| {
            for i in 0..100 {
                let path = format!("src/file_{}.rs", i);
                if let Some(lines) = coverage.get(&path) {
                    for line in 1..=100 {
                        black_box(lines.get(&line));
                    }
                }
            }
        });
    });

    group.bench_function("count_covered", |b| {
        b.iter(|| {
            let covered = coverage
                .values()
                .flat_map(|lines| lines.values())
                .filter(|&&hits| hits > 0)
                .count();
            black_box(covered)
        });
    });

    group.finish();
}

/// Benchmark line hit counting.
fn bench_line_hit_counting(c: &mut Criterion) {
    let mut group = c.benchmark_group("line_hits");

    let lcov = generate_synthetic_lcov(100, 200);

    group.throughput(Throughput::Bytes(lcov.len() as u64));
    group.bench_function("parse_line_hits", |b| {
        b.iter(|| {
            let mut total_hits = 0u64;
            let mut total_lines = 0u64;

            for line in lcov.lines() {
                if let Some(da_data) = line.strip_prefix("DA:") {
                    let parts: Vec<&str> = da_data.split(',').collect();
                    if parts.len() >= 2
                        && let Ok(hits) = parts[1].parse::<u64>() {
                            total_hits += hits;
                            total_lines += 1;
                        }
                }
            }

            black_box((total_hits, total_lines))
        });
    });

    group.finish();
}

/// Benchmark coverage merging.
fn bench_coverage_merging(c: &mut Criterion) {
    let mut group = c.benchmark_group("coverage_merge");

    // Create two coverage maps
    let create_coverage_map = |offset: u32| -> BTreeMap<String, BTreeMap<u32, u32>> {
        let mut coverage = BTreeMap::new();
        for file_idx in 0..50 {
            let file_path = format!("src/file_{}.rs", file_idx);
            let mut lines = BTreeMap::new();
            for line_idx in 1..=200 {
                lines.insert(
                    line_idx,
                    if line_idx % 5 == 0 {
                        0
                    } else {
                        (line_idx + offset) % 10 + 1
                    },
                );
            }
            coverage.insert(file_path, lines);
        }
        coverage
    };

    let coverage1 = create_coverage_map(0);
    let coverage2 = create_coverage_map(5);

    group.bench_function("merge_maps", |b| {
        b.iter(|| {
            let mut merged = coverage1.clone();
            for (file, lines) in &coverage2 {
                let entry = merged.entry(file.clone()).or_default();
                for (line, hits) in lines {
                    *entry.entry(*line).or_insert(0) += hits;
                }
            }
            black_box(merged)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_lcov_parsing,
    bench_coverage_map_operations,
    bench_line_hit_counting,
    bench_coverage_merging,
);

criterion_main!(benches);
