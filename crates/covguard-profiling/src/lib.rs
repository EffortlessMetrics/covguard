//! Performance profiling utilities for covguard.
//!
//! This crate provides lightweight timing and memory estimation utilities
//! for profiling covguard operations. It's designed to have minimal overhead
//! when profiling is disabled.
//!
//! # Features
//!
//! - `profiling` - Enable profiling instrumentation. When disabled, all
//!   profiling macros become no-ops with zero overhead.
//!
//! # Usage
//!
//! ```rust,ignore
//! use covguard_profiling::{profile_scope, ProfileStats};
//!
//! // Enable profiling via feature flag
//! let stats = ProfileStats::new();
//!
//! {
//!     let _guard = profile_scope!("diff_parsing");
//!     // ... diff parsing code ...
//! }
//!
//! // Print stats at the end
//! stats.print_report();
//! ```

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Global flag indicating whether profiling is enabled.
static PROFILING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable profiling globally.
pub fn set_profiling_enabled(enabled: bool) {
    PROFILING_ENABLED.store(enabled, Ordering::SeqCst);
}

/// Check if profiling is currently enabled.
pub fn is_profiling_enabled() -> bool {
    PROFILING_ENABLED.load(Ordering::SeqCst)
}

/// Timing statistics for a single operation.
#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    /// Number of times this operation was called.
    pub call_count: u64,
    /// Total time spent in this operation.
    pub total_duration: Duration,
    /// Minimum duration (if called at least once).
    pub min_duration: Option<Duration>,
    /// Maximum duration (if called at least once).
    pub max_duration: Option<Duration>,
}

impl TimingStats {
    /// Create new empty timing stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single timing measurement.
    pub fn record(&mut self, duration: Duration) {
        self.call_count += 1;
        self.total_duration += duration;

        self.min_duration = Some(match self.min_duration {
            Some(min) => min.min(duration),
            None => duration,
        });

        self.max_duration = Some(match self.max_duration {
            Some(max) => max.max(duration),
            None => duration,
        });
    }

    /// Get the average duration per call.
    pub fn average_duration(&self) -> Option<Duration> {
        if self.call_count == 0 {
            None
        } else {
            Some(self.total_duration / self.call_count as u32)
        }
    }
}

/// Global profiling statistics collector.
pub struct ProfileStats {
    timings: Mutex<BTreeMap<String, TimingStats>>,
}

impl ProfileStats {
    /// Create a new profile stats collector.
    pub fn new() -> Self {
        Self {
            timings: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record a timing for a named operation.
    pub fn record(&self, name: &str, duration: Duration) {
        if !is_profiling_enabled() {
            return;
        }

        let mut timings = self.timings.lock().unwrap();
        timings.entry(name.to_string()).or_default().record(duration);
    }

    /// Get all recorded timings.
    pub fn get_timings(&self) -> BTreeMap<String, TimingStats> {
        let timings = self.timings.lock().unwrap();
        timings.clone()
    }

    /// Print a formatted report to stderr.
    pub fn print_report(&self) {
        if !is_profiling_enabled() {
            return;
        }

        let timings = self.get_timings();
        if timings.is_empty() {
            return;
        }

        eprintln!("\n=== Performance Profile ===");
        eprintln!(
            "{:<30} {:>8} {:>12} {:>12} {:>12} {:>12}",
            "Operation", "Calls", "Total", "Avg", "Min", "Max"
        );
        eprintln!("{}", "-".repeat(90));

        for (name, stats) in &timings {
            let avg = stats
                .average_duration()
                .map(|d| format!("{:.2}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".to_string());

            let min = stats
                .min_duration
                .map(|d| format!("{:.2}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".to_string());

            let max = stats
                .max_duration
                .map(|d| format!("{:.2}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".to_string());

            eprintln!(
                "{:<30} {:>8} {:>12.2}ms {:>12} {:>12} {:>12}",
                name,
                stats.call_count,
                stats.total_duration.as_secs_f64() * 1000.0,
                avg,
                min,
                max
            );
        }

        eprintln!("{}", "-".repeat(90));
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        let mut timings = self.timings.lock().unwrap();
        timings.clear();
    }
}

impl Default for ProfileStats {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard for timing a scope.
pub struct ScopeGuard<'a> {
    name: &'a str,
    start: Instant,
    stats: &'a ProfileStats,
}

impl<'a> ScopeGuard<'a> {
    /// Create a new scope guard.
    pub fn new(name: &'a str, stats: &'a ProfileStats) -> Self {
        Self {
            name,
            start: Instant::now(),
            stats,
        }
    }
}

impl Drop for ScopeGuard<'_> {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        self.stats.record(self.name, duration);
    }
}

/// Macro to create a profile scope guard.
///
/// When the `profiling` feature is enabled, this creates a `ScopeGuard`
/// that records the time from creation to drop.
///
/// # Example
///
/// ```rust,ignore
/// use covguard_profiling::{profile_scope, ProfileStats};
///
/// let stats = ProfileStats::new();
/// {
///     let _guard = profile_scope!("my_operation", &stats);
///     // ... code to profile ...
/// }
/// ```
#[macro_export]
macro_rules! profile_scope {
    ($name:expr, $stats:expr) => {{
        if $crate::is_profiling_enabled() {
            Some($crate::ScopeGuard::new($name, $stats))
        } else {
            None
        }
    }};
}

/// Memory estimation utilities.
pub mod memory {
    /// Estimate memory usage of a string in bytes.
    pub fn estimate_string_memory(s: &str) -> usize {
        s.len() + std::mem::size_of::<String>()
    }

    /// Estimate memory usage of a BTreeMap with string keys.
    pub fn estimate_btree_map_memory<K, V>(map: &std::collections::BTreeMap<K, V>) -> usize
    where
        K: std::hash::Hash + Eq + AsRef<str>,
    {
        // Rough estimate: key + value overhead + tree node overhead
        let entry_overhead = std::mem::size_of::<(K, V)>() + 48; // tree node overhead
        map.len() * entry_overhead
    }

    /// Estimate memory for a coverage map (file -> line -> hits).
    pub fn estimate_coverage_map_memory(
        map: &std::collections::BTreeMap<String, std::collections::BTreeMap<u32, u32>>,
    ) -> usize {
        let mut total = 0usize;

        for (file, lines) in map {
            // File path string
            total += estimate_string_memory(file);
            // Inner BTreeMap overhead
            total += std::mem::size_of::<std::collections::BTreeMap<u32, u32>>();
            // Each line entry: (line_number, hit_count) + tree node overhead
            total += lines.len() * (std::mem::size_of::<(u32, u32)>() + 48);
        }

        // Outer BTreeMap overhead
        total += std::mem::size_of::<std::collections::BTreeMap<String, std::collections::BTreeMap<u32, u32>>>();

        total
    }

    /// Estimate memory for changed ranges (file -> ranges).
    pub fn estimate_changed_ranges_memory(
        map: &std::collections::BTreeMap<String, Vec<std::ops::RangeInclusive<u32>>>,
    ) -> usize {
        let mut total = 0usize;

        for (file, ranges) in map {
            // File path string
            total += estimate_string_memory(file);
            // Vec overhead
            total += ranges.capacity() * std::mem::size_of::<std::ops::RangeInclusive<u32>>();
        }

        // Outer BTreeMap overhead
        total += std::mem::size_of::<std::collections::BTreeMap<String, Vec<std::ops::RangeInclusive<u32>>>>();

        total
    }

    /// Format bytes as a human-readable string.
    pub fn format_bytes(bytes: usize) -> String {
        const KB: usize = 1024;
        const MB: usize = KB * 1024;
        const GB: usize = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

/// Profile result containing timing and memory information.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ProfileResult {
    /// Timing measurements for each operation.
    pub timings: BTreeMap<String, TimingInfo>,
    /// Memory estimates for major data structures.
    pub memory: MemoryInfo,
    /// Total elapsed time.
    pub total_duration_ms: f64,
}

/// Timing information for a single operation.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TimingInfo {
    /// Number of calls.
    pub call_count: u64,
    /// Total duration in milliseconds.
    pub total_ms: f64,
    /// Average duration in milliseconds.
    pub avg_ms: f64,
    /// Minimum duration in milliseconds.
    pub min_ms: f64,
    /// Maximum duration in milliseconds.
    pub max_ms: f64,
}

impl From<&TimingStats> for TimingInfo {
    fn from(stats: &TimingStats) -> Self {
        Self {
            call_count: stats.call_count,
            total_ms: stats.total_duration.as_secs_f64() * 1000.0,
            avg_ms: stats
                .average_duration()
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0),
            min_ms: stats
                .min_duration
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0),
            max_ms: stats
                .max_duration
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(0.0),
        }
    }
}

/// Memory usage information.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MemoryInfo {
    /// Estimated coverage map memory.
    pub coverage_map_bytes: usize,
    /// Estimated changed ranges memory.
    pub changed_ranges_bytes: usize,
    /// Total estimated memory.
    pub total_bytes: usize,
}

impl ProfileResult {
    /// Create a profile result from stats and memory estimates.
    pub fn from_stats(
        stats: &ProfileStats,
        coverage_map_bytes: usize,
        changed_ranges_bytes: usize,
        total_duration: Duration,
    ) -> Self {
        let timings = stats
            .get_timings()
            .iter()
            .map(|(k, v)| (k.clone(), TimingInfo::from(v)))
            .collect();

        Self {
            timings,
            memory: MemoryInfo {
                coverage_map_bytes,
                changed_ranges_bytes,
                total_bytes: coverage_map_bytes + changed_ranges_bytes,
            },
            total_duration_ms: total_duration.as_secs_f64() * 1000.0,
        }
    }

    /// Format as a human-readable string.
    pub fn format_report(&self) -> String {
        let mut output = String::new();

        output.push_str("\n=== Performance Profile ===\n");
        output.push_str(&format!(
            "{:<30} {:>8} {:>12} {:>12} {:>12} {:>12}\n",
            "Operation", "Calls", "Total", "Avg", "Min", "Max"
        ));
        output.push_str(&format!("{}\n", "-".repeat(90)));

        for (name, info) in &self.timings {
            output.push_str(&format!(
                "{:<30} {:>8} {:>12.2}ms {:>12.2}ms {:>12.2}ms {:>12.2}ms\n",
                name,
                info.call_count,
                info.total_ms,
                info.avg_ms,
                info.min_ms,
                info.max_ms
            ));
        }

        output.push_str(&format!("{}\n", "-".repeat(90)));
        output.push_str(&format!(
            "Total time: {:.2}ms\n",
            self.total_duration_ms
        ));
        output.push_str(&format!(
            "Memory: coverage={} ranges={} total={}\n",
            memory::format_bytes(self.memory.coverage_map_bytes),
            memory::format_bytes(self.memory.changed_ranges_bytes),
            memory::format_bytes(self.memory.total_bytes)
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::thread;
    use std::time::Duration;

    /// Serializes tests that mutate the global `PROFILING_ENABLED` flag.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn test_timing_stats() {
        let mut stats = TimingStats::new();

        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));

        assert_eq!(stats.call_count, 3);
        assert_eq!(stats.total_duration, Duration::from_millis(60));
        assert_eq!(stats.min_duration, Some(Duration::from_millis(10)));
        assert_eq!(stats.max_duration, Some(Duration::from_millis(30)));
        assert_eq!(stats.average_duration(), Some(Duration::from_millis(20)));
    }

    #[test]
    fn test_profile_stats() {
        let _lock = TEST_LOCK.lock().unwrap();
        set_profiling_enabled(true);

        let stats = ProfileStats::new();

        {
            let _guard = ScopeGuard::new("test_op", &stats);
            thread::sleep(Duration::from_millis(10));
        }

        let timings = stats.get_timings();
        assert!(timings.contains_key("test_op"));
        assert_eq!(timings["test_op"].call_count, 1);

        set_profiling_enabled(false);
    }

    #[test]
    fn test_profiling_disabled() {
        let _lock = TEST_LOCK.lock().unwrap();
        set_profiling_enabled(false);

        let stats = ProfileStats::new();

        {
            let _guard = ScopeGuard::new("test_op_disabled", &stats);
            thread::sleep(Duration::from_millis(10));
        }

        let timings = stats.get_timings();
        assert!(!timings.contains_key("test_op_disabled"));
    }

    #[test]
    fn test_memory_formatting() {
        assert_eq!(memory::format_bytes(500), "500 B");
        assert_eq!(memory::format_bytes(1024), "1.00 KB");
        assert_eq!(memory::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(memory::format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_profile_result() {
        let mut timings = BTreeMap::new();
        timings.insert(
            "test".to_string(),
            TimingInfo {
                call_count: 1,
                total_ms: 10.0,
                avg_ms: 10.0,
                min_ms: 10.0,
                max_ms: 10.0,
            },
        );

        let result = ProfileResult {
            timings,
            memory: MemoryInfo {
                coverage_map_bytes: 1024,
                changed_ranges_bytes: 512,
                total_bytes: 1536,
            },
            total_duration_ms: 50.0,
        };

        let report = result.format_report();
        assert!(report.contains("test"));
        assert!(report.contains("1.00 KB"));
    }
}
