# Performance Characteristics

This document describes the performance characteristics of covguard and provides guidance for optimizing large repositories.

## Overview

covguard is designed to be efficient for repositories of all sizes. The main operations are:

1. **Diff parsing** - Parse unified diff output to extract changed line ranges
2. **Coverage parsing** - Parse LCOV (and optionally JaCoCo/coverage.py) files
3. **Policy evaluation** - Compare changed lines against coverage data
4. **Report generation** - Generate JSON, Markdown, SARIF, and annotations

## Performance Targets

| Repository Size | Target Time | Memory |
|-----------------|-------------|--------|
| Small (<100 files, <10K lines changed) | <100ms | <10MB |
| Medium (<1000 files, <100K lines changed) | <500ms | <50MB |
| Large (<5000 files, <500K lines changed) | <2s | <200MB |
| Very Large (<10000 files, <1M lines changed) | <5s | <500MB |

## Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark suite
cargo bench --bench diff_parsing
cargo bench --bench coverage_parsing
cargo bench --bench policy_evaluation
cargo bench --bench report_generation
```

### Benchmark Categories

#### Diff Parsing Benchmarks

Tests parsing performance for various diff sizes:

- Small: 10 files, 50 lines each
- Medium: 50 files, 100 lines each
- Large: 100 files, 200 lines each
- Many files: 500 files, 100 lines each

#### Coverage Parsing Benchmarks

Tests LCOV parsing and coverage map operations:

- Small: 10 files, 100 lines each
- Medium: 50 files, 200 lines each
- Large: 100 files, 500 lines each
- Many files: 500 files, 200 lines each
- Very many files: 1000 files, 100 lines each

#### Policy Evaluation Benchmarks

Tests the core policy evaluation algorithm:

- Finding generation for 1000+ uncovered lines
- Coverage percentage calculation
- Ignored lines handling

#### Report Generation Benchmarks

Tests rendering performance:

- Markdown table rendering
- SARIF JSON generation
- JSON serialization/deserialization

## Profiling

### Enabling Profiling

Use the `--timing` flag to enable performance profiling:

```bash
covguard check \
  --diff-file large.patch \
  --lcov large-coverage.info \
  --timing \
  --out report.json
```

### Profiling Output

When `--timing` is enabled, covguard outputs timing information to stderr:

```
=== Timing Report ===
Total time: 234.56ms

=== Performance Profile ===
Operation                         Calls        Total          Avg          Min          Max
------------------------------------------------------------------------------------------
config_load                           1        2.34ms       2.34ms       2.34ms       2.34ms
diff_load                             1       45.67ms      45.67ms      45.67ms      45.67ms
coverage_load                         1       89.12ms      89.12ms      89.12ms      89.12ms
policy_evaluation                     1       78.90ms      78.90ms      78.90ms      78.90ms
report_generation                     1       18.53ms      18.53ms      18.53ms      18.53ms
------------------------------------------------------------------------------------------
```

### Memory Estimation

The profiling module provides utilities for estimating memory usage:

```rust
use covguard_profiling::memory::{
    estimate_coverage_map_memory,
    estimate_changed_ranges_memory,
    format_bytes
};

let coverage_bytes = estimate_coverage_map_memory(&coverage_map);
let ranges_bytes = estimate_changed_ranges_memory(&changed_ranges);

println!("Coverage map: {}", format_bytes(coverage_bytes));
println!("Changed ranges: {}", format_bytes(ranges_bytes));
```

## Optimization Strategies

### 1. Reduce Diff Size

Use targeted diffs to reduce parsing overhead:

```bash
# Only check specific paths
covguard check --base main --head feature --lcov coverage.info \
  --include "src/**/*.rs"
```

### 2. Optimize Coverage Files

- Use a single merged LCOV file instead of multiple files
- Exclude test files from coverage if not needed
- Use `lcov --remove` to strip unnecessary coverage data

### 3. Use Appropriate Thresholds

Higher thresholds mean more findings to process:

```bash
# Lower threshold = fewer findings = faster processing
covguard check --threshold 50 --lcov coverage.info
```

### 4. Limit Output

Truncate findings to reduce report generation time:

```bash
# Limit markdown output
covguard check --max-markdown-lines 10 --max-findings 100
```

### 5. Skip Ignore Directives

If not using `covguard: ignore` comments:

```bash
covguard check --no-ignore --lcov coverage.info
```

## Performance Tips for CI

### GitHub Actions

```yaml
- name: Check coverage
  run: |
    covguard check \
      --base ${{ github.base_ref }} \
      --head ${{ github.head_ref }} \
      --lcov coverage.info \
      --out artifacts/covguard/report.json \
      --max-annotations 25 \
      --max-sarif-results 500
```

### Caching

Cache the covguard binary to speed up CI:

```yaml
- name: Cache covguard
  uses: actions/cache@v4
  with:
    path: ~/.cargo/bin/covguard
    key: covguard-${{ hashFiles('Cargo.lock') }}
```

## Memory Profiling

### Using heap profiling (Linux)

```bash
# Install valgrind
sudo apt-get install valgrind

# Run with massif
valgrind --tool=massif --massif-out-file=massif.out \
  cargo run -- check --diff-file test.patch --lcov test.info

# Analyze
ms_print massif.out
```

### Using Instruments (macOS)

```bash
# Profile with Instruments
instruments -t "Allocations" \
  cargo run --release -- check --diff-file test.patch --lcov test.info
```

## Known Performance Issues

### Large Diffs (>1MB)

For very large diffs (e.g., initial commits, massive refactors):
- Parsing may take several seconds
- Consider splitting the diff or using incremental checks

### Many Findings (>1000)

With thousands of uncovered lines:
- Report generation may take 100ms+
- Use `--max-findings` to truncate

### Coverage Files with Many Files

LCOV files with 5000+ source files:
- Parsing may take 1-2 seconds
- Memory usage increases linearly with file count

## Performance Regressions

If you notice a performance regression:

1. Run benchmarks to identify the affected component
2. Enable `--timing` to see which operation is slow
3. Check memory usage with system tools
4. Report the issue with:
   - Repository size (files, lines)
   - Diff size (lines)
   - Coverage file size (files, lines)
   - Timing output

## Future Optimizations

Planned performance improvements:

1. **Parallel coverage parsing** - Parse multiple LCOV files concurrently
2. **Streaming diff parsing** - Handle very large diffs without loading entirely into memory
3. **Incremental evaluation** - Cache results for unchanged files
4. **SIMD optimizations** - Use vectorized operations for line matching

## Benchmark Results

### Reference Hardware

- CPU: AMD Ryzen 9 5900X
- RAM: 64GB DDR4-3200
- Storage: NVMe SSD
- OS: Ubuntu 22.04

### Sample Results

| Benchmark | Input Size | Time | Memory |
|-----------|------------|------|--------|
| diff_parsing/10files_50lines | 15KB | 0.12ms | 0.5MB |
| diff_parsing/100files_200lines | 300KB | 1.8ms | 2MB |
| diff_parsing/500files_100lines | 750KB | 8.5ms | 5MB |
| lcov_parsing/10files_100lines | 12KB | 0.3ms | 0.8MB |
| lcov_parsing/100files_500lines | 600KB | 12ms | 8MB |
| lcov_parsing/1000files_100lines | 1.2MB | 45ms | 25MB |
| policy_evaluation/100files_500lines | 5000 elements | 3.2ms | 1MB |
| report_generation/1000findings | 1000 elements | 5.1ms | 2MB |

*Note: Results are illustrative. Run benchmarks on your own hardware for accurate measurements.*
