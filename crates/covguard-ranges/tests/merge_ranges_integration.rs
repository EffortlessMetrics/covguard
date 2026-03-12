use covguard_ranges::merge_ranges;

#[test]
fn merge_ranges_collapses_overlaps_and_adjacency() {
    let ranges = vec![1..=2, 2..=4, 6..=7, 5..=5];
    let merged = merge_ranges(ranges);
    assert_eq!(merged, vec![1..=7]);
}
