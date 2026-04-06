# covguard-profiling

Performance profiling utilities for covguard.

## Features

- `profiling` - Enable profiling instrumentation. When disabled, all profiling macros become no-ops with zero overhead.

## Usage

```rust
use covguard_profiling::{profile_scope, ProfileStats, set_profiling_enabled};

// Enable profiling
set_profiling_enabled(true);

let stats = ProfileStats::new();

{
    let _guard = profile_scope!("diff_parsing", &stats);
    // ... diff parsing code ...
}

// Print stats at the end
stats.print_report();
```

## Memory Estimation

```rust
use covguard_profiling::memory::{estimate_coverage_map_memory, format_bytes};

let coverage_map = /* ... */;
let bytes = estimate_coverage_map_memory(&coverage_map);
println!("Memory usage: {}", format_bytes(bytes));
```
