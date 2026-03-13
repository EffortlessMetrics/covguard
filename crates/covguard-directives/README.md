# covguard-directives

[![crates.io](https://img.shields.io/crates/v/covguard-directives.svg)](https://crates.io/crates/covguard-directives)
[![docs.rs](https://docs.rs/covguard-directives/badge.svg)](https://docs.rs/covguard-directives)
[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/License-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE)

Directive utilities for parsing and detecting `covguard: ignore` comments in source code.

## Overview

This crate provides reusable, pure logic for ignore directive parsing and changed-range scanning that is shared across app and domain adapters:

- **`has_ignore_directive`**: Check if a line contains a `covguard: ignore` directive
- **`detect_ignored_lines`**: Scan changed ranges for lines with ignore directives

Supported comment styles:
- `// covguard: ignore` (Rust, C, C++, JavaScript, TypeScript, etc.)
- `# covguard: ignore` (Python, Shell, YAML, Ruby, etc.)
- `-- covguard: ignore` (SQL, Haskell, Lua)
- `/* covguard: ignore */` (Block comments)
- `covguard-ignore` (Alternative form)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
covguard-directives = "0.1"
```

### Example

```rust
use covguard_directives::{has_ignore_directive, detect_ignored_lines};
use covguard_ports::{ChangedRanges, RepoReader};
use std::collections::{BTreeMap, BTreeSet};

// Check a single line for an ignore directive
let line = "let x = expensive_call(); // covguard: ignore";
if has_ignore_directive(line) {
    println!("Line has coverage ignore directive");
}

// Detect all ignored lines in changed ranges
let changed_ranges: ChangedRanges = BTreeMap::from([
    ("src/main.rs".to_string(), vec![10..=15]),
]);

let ignored = detect_ignored_lines(&changed_ranges, &my_repo_reader);
for (path, lines) in ignored {
    println!("{}: ignored lines {:?}", path, lines);
}
```

## Documentation

- [API Documentation](https://docs.rs/covguard-directives)
- [Main Repository](https://github.com/EffortlessMetrics/covguard)

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
