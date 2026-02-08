#![no_main]

use libfuzzer_sys::fuzz_target;
use covguard_adapters_diff::parse_patch;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, lossy is fine for fuzzing
    if let Ok(text) = std::str::from_utf8(data) {
        // The parser should never panic, regardless of input
        let _ = parse_patch(text);
    }
});
