# covguard-benchmarks

Performance benchmarks for covguard using Criterion.

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench -p covguard-benchmarks

# Run specific benchmark
cargo bench -p covguard-benchmarks --bench diff_parsing
cargo bench -p covguard-benchmarks --bench coverage_parsing
cargo bench -p covguard-benchmarks --bench policy_evaluation
cargo bench -p covguard-benchmarks --bench report_generation
```

## Benchmark Categories

- **diff_parsing**: Unified diff parsing performance
- **coverage_parsing**: LCOV file parsing and coverage map operations
- **policy_evaluation**: Policy evaluation and finding generation
- **report_generation**: JSON, Markdown, and SARIF rendering
