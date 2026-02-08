# Fuzzing covguard Parsers

This directory contains fuzz targets for testing parser robustness using `cargo-fuzz`.

## Prerequisites

Install cargo-fuzz (requires nightly Rust):

```bash
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Fuzz Targets

| Target | What it Tests |
|--------|---------------|
| `fuzz_diff_parser` | Tests `covguard-adapters-diff::parse_patch` with arbitrary byte input. The parser must never panic regardless of input. |
| `fuzz_lcov_parser` | Tests `covguard-adapters-coverage::parse_lcov` with arbitrary byte input. The parser must never panic regardless of input. |

Both targets convert raw bytes to UTF-8 strings (skipping invalid UTF-8) and feed them to the respective parsers. Errors are expected and acceptable; panics are not.

## Running Fuzz Tests

Run a specific fuzz target:

```bash
cd fuzz
cargo +nightly fuzz run fuzz_diff_parser
cargo +nightly fuzz run fuzz_lcov_parser
```

Run with a time limit (e.g., 60 seconds):

```bash
cargo +nightly fuzz run fuzz_diff_parser -- -max_total_time=60
```

Run with multiple jobs for faster coverage:

```bash
cargo +nightly fuzz run fuzz_diff_parser -- -jobs=4 -workers=4
```

List available targets:

```bash
cargo +nightly fuzz list
```

## Corpus

Seed files in `corpus/` provide starting inputs for the fuzzer. The fuzzer uses these as a foundation to generate mutations.

- `corpus/fuzz_diff_parser/` - Valid unified diff/patch files
- `corpus/fuzz_lcov_parser/` - Valid LCOV coverage report files

### Current Seed Files

| File | Description |
|------|-------------|
| `fuzz_diff_parser/simple_added.patch` | Minimal patch adding a new file |
| `fuzz_lcov_parser/covered.info` | LCOV file with covered lines (DA:n,1) |
| `fuzz_lcov_parser/uncovered.info` | LCOV file with uncovered lines (DA:n,0) |

### Adding New Corpus Entries

1. Add representative, minimal test cases that exercise different code paths
2. Keep files small (< 1KB ideal, < 10KB maximum)
3. Use descriptive filenames (not auto-generated hex names)
4. Ensure valid UTF-8 encoding

Example:

```bash
# Copy a fixture as a seed
cp ../fixtures/diff/renamed_file.patch corpus/fuzz_diff_parser/

# Or create a minimal reproducer for an edge case
echo 'SF:edge/case.rs
DA:1,1
end_of_record' > corpus/fuzz_lcov_parser/edge_case.info
```

Note: Auto-generated corpus entries (hex-named files created by libFuzzer) are ignored by `.gitignore`. Only commit hand-curated seed files.

## Crashes and Findings

When the fuzzer finds a crash:

1. A crash file is created at `fuzz/artifacts/<target>/crash-<hash>`
2. Reproduce with: `cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>`
3. Minimize with: `cargo +nightly fuzz tmin <target> artifacts/<target>/crash-<hash>`
4. Debug and fix the underlying bug
5. Delete the crash file (they are gitignored)

Do not commit crash files. Fix the bug and add a regression test instead.

## CI Integration

For CI pipelines, run each target with a time limit:

```bash
cargo +nightly fuzz run fuzz_diff_parser -- -max_total_time=30
cargo +nightly fuzz run fuzz_lcov_parser -- -max_total_time=30
```

Check for regressions against the corpus without fuzzing:

```bash
cargo +nightly fuzz run fuzz_diff_parser corpus/fuzz_diff_parser/ -- -runs=0
cargo +nightly fuzz run fuzz_lcov_parser corpus/fuzz_lcov_parser/ -- -runs=0
```

## Troubleshooting

**"error: could not find `fuzz` in registry"**
Ensure you have cargo-fuzz installed: `cargo +nightly install cargo-fuzz`

**Slow startup**
The first run compiles with instrumentation. Subsequent runs are faster.

**Out of memory**
Limit input size: `cargo +nightly fuzz run <target> -- -max_len=4096`
