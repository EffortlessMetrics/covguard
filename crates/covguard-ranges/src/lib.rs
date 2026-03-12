//! Range merging utilities for covguard.

use std::ops::RangeInclusive;

/// Merge overlapping or adjacent ranges into a minimal set.
///
/// Input ranges do not need to be sorted; output will be sorted and
/// contain no overlapping or adjacent ranges.
///
/// # Examples
///
/// ```
/// use covguard_ranges::merge_ranges;
///
/// // These ranges are all adjacent/overlapping: 1..=4 (from 1..=3, 2..=4),
/// // then 5..=7 is adjacent to 1..=4, and 8..=10 is adjacent to 5..=7,
/// // so everything merges into one range.
/// let ranges = vec![1..=3, 5..=7, 2..=4, 8..=10];
/// let merged = merge_ranges(ranges);
/// assert_eq!(merged, vec![1..=10]);
///
/// // Non-adjacent ranges stay separate
/// let ranges = vec![1..=3, 10..=15];
/// let merged = merge_ranges(ranges);
/// assert_eq!(merged, vec![1..=3, 10..=15]);
/// ```
pub fn merge_ranges(mut ranges: Vec<RangeInclusive<u32>>) -> Vec<RangeInclusive<u32>> {
    if ranges.is_empty() {
        return Vec::new();
    }

    // Sort by start, then by end
    ranges.sort_by(|a, b| a.start().cmp(b.start()).then(a.end().cmp(b.end())));

    let mut merged: Vec<RangeInclusive<u32>> = Vec::with_capacity(ranges.len());

    for range in ranges {
        if let Some(last) = merged.last_mut() {
            // Check if ranges overlap or are adjacent
            // Adjacent: last.end + 1 == range.start
            // Overlapping: range.start <= last.end
            if *range.start() <= last.end().saturating_add(1) {
                // Extend the last range if needed
                if *range.end() > *last.end() {
                    *last = *last.start()..=*range.end();
                }
            } else {
                merged.push(range);
            }
        } else {
            merged.push(range);
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_ranges_empty() {
        let result = merge_ranges(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_merge_ranges_single() {
        let result = merge_ranges(vec![1..=5]);
        assert_eq!(result, vec![1..=5]);
    }

    #[test]
    fn test_merge_ranges_non_overlapping() {
        let result = merge_ranges(vec![1..=3, 7..=10]);
        assert_eq!(result, vec![1..=3, 7..=10]);
    }

    #[test]
    fn test_merge_ranges_overlapping() {
        let result = merge_ranges(vec![1..=5, 3..=8]);
        assert_eq!(result, vec![1..=8]);
    }

    #[test]
    fn test_merge_ranges_adjacent() {
        let result = merge_ranges(vec![1..=3, 4..=6]);
        assert_eq!(result, vec![1..=6]);
    }

    #[test]
    fn test_merge_ranges_unsorted() {
        // After sorting and merging: 1..=3, 2..=4 -> 1..=4
        // 5..=7, 8..=10 are adjacent (7+1=8), so merge to 5..=10
        // 1..=4 and 5..=10 are adjacent (4+1=5), so merge to 1..=10
        let result = merge_ranges(vec![5..=7, 1..=3, 2..=4, 8..=10]);
        assert_eq!(result, vec![1..=10]);
    }

    #[test]
    fn test_merge_ranges_contained() {
        let result = merge_ranges(vec![1..=10, 3..=5]);
        assert_eq!(result, vec![1..=10]);
    }
}

// ============================================================================
// Property Tests
// ============================================================================

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn merge_ranges_produces_sorted_output(ranges in prop::collection::vec(1u32..1000, 0..50)) {
            let input: Vec<RangeInclusive<u32>> = ranges.iter().map(|&x| x..=x).collect();
            let merged = merge_ranges(input);

            // Check sorted
            for window in merged.windows(2) {
                prop_assert!(window[0].end() < window[1].start());
            }
        }

        #[test]
        fn merge_ranges_produces_non_overlapping_output(ranges in prop::collection::vec((1u32..500, 1u32..500), 0..30)) {
            let input: Vec<RangeInclusive<u32>> = ranges
                .into_iter()
                .map(|(start, len)| start..=(start + len))
                .collect();
            let merged = merge_ranges(input);

            // Check non-overlapping and non-adjacent
            for window in merged.windows(2) {
                let gap = *window[1].start() as i64 - *window[0].end() as i64;
                prop_assert!(gap >= 2, "Ranges should not be adjacent or overlapping: gap={}", gap);
            }
        }

        #[test]
        fn merge_ranges_is_idempotent(ranges in prop::collection::vec((1u32..500, 1u32..100), 0..20)) {
            let input: Vec<RangeInclusive<u32>> = ranges
                .into_iter()
                .map(|(start, len)| start..=(start + len))
                .collect();

            let merged_once = merge_ranges(input.clone());
            let merged_twice = merge_ranges(merged_once.clone());

            prop_assert_eq!(merged_once, merged_twice, "merge_ranges should be idempotent");
        }

        #[test]
        fn merge_ranges_preserves_all_values(values in prop::collection::vec(1u32..1000, 1..50)) {
            let input: Vec<RangeInclusive<u32>> = values.iter().map(|&x| x..=x).collect();
            let merged = merge_ranges(input);

            // Every input value should be contained in some output range
            for val in &values {
                let contained = merged.iter().any(|r| r.contains(val));
                prop_assert!(contained, "Value {} should be in merged ranges", val);
            }
        }
    }
}
