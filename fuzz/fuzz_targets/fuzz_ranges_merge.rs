#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    ranges: Vec<(u32, u32)>,
}

fuzz_target!(|input: Input| {
    let ranges = input
        .ranges
        .into_iter()
        .map(|(a, b)| {
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            start..=end
        })
        .collect();

    let _ = covguard_ranges::merge_ranges(ranges);
});
