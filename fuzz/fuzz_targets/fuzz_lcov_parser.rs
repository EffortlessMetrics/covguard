#![no_main]

use libfuzzer_sys::fuzz_target;
use covguard_adapters_coverage::parse_lcov;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, lossy is fine for fuzzing
    if let Ok(text) = std::str::from_utf8(data) {
        // The parser should never panic, regardless of input
        // Errors are expected and acceptable; panics are not
        let _ = parse_lcov(text);
    }
});
