use serde::Serialize;
use std::{collections::HashMap, sync::Mutex};

pub const CAPACITY: usize = 512;
pub const BUCKETS: usize = 900;
pub const DEFAULT_WINDOW_SECONDS: u64 = 900;
const MAX_PATH_BYTES: usize = 2048;

#[derive(Default)]
struct Entry {
    buckets: Box<[(u64, u64)]>,
}
impl Entry {
    fn new() -> Self {
        Self {
            buckets: vec![(0, 0); BUCKETS].into_boxed_slice(),
        }
    }
    fn add(&mut self, second: u64) {
        let bucket = &mut self.buckets[second as usize % BUCKETS];
        if bucket.0 != second {
            *bucket = (second, 0);
        }
        bucket.1 = bucket.1.saturating_add(1);
    }
    fn count(&self, start: u64, end: u64) -> u64 {
        self.buckets
            .iter()
            .filter(|(second, _)| *second >= start && *second < end)
            .map(|(_, count)| *count)
            .sum()
    }
}
#[derive(Default)]
struct State {
    entries: HashMap<(String, String), Entry>,
    overflow: u64,
    coverage_start_unix_ms: Option<u64>,
}
#[derive(Default)]
pub struct Registry {
    state: Mutex<State>,
    skipped: std::sync::atomic::AtomicU64,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub source: &'static str,
    pub count: u64,
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub window_seconds: u64,
    pub start_unix_ms: u64,
    pub end_unix_ms: u64,
    pub coverage_start_unix_ms: u64,
    pub observed_at_unix_ms: u64,
    pub capacity: usize,
    pub tracked_keys: usize,
    pub overflow_requests: u64,
    pub complete: bool,
    pub reset: &'static str,
    pub path_semantics: &'static str,
}

impl Registry {
    /// Nonblocking hot-path observation. No raw path labels leave this bounded in-memory registry.
    pub fn observe(&self, host: &str, path: &str, now_ms: u64) {
        if path.len() > MAX_PATH_BYTES
            || path.chars().any(|c| c.is_control() || c == '?' || c == '#')
        {
            if let Ok(mut state) = self.state.try_lock() {
                state.coverage_start_unix_ms.get_or_insert(now_ms);
                state.overflow = state.overflow.saturating_add(1);
            } else {
                self.skipped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
        let Ok(mut state) = self.state.try_lock() else {
            self.skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        state.coverage_start_unix_ms.get_or_insert(now_ms);
        let key = (host.to_ascii_lowercase(), path.to_owned());
        if !state.entries.contains_key(&key) {
            if state.entries.len() >= CAPACITY {
                state.overflow = state.overflow.saturating_add(1);
                return;
            }
            state.entries.insert(key.clone(), Entry::new());
        }
        state
            .entries
            .get_mut(&key)
            .expect("entry inserted")
            .add(now_ms / 1000);
    }
    pub fn validate(
        host: Option<&str>,
        path: Option<&str>,
        window: u64,
    ) -> Result<(), &'static str> {
        if !(1..=DEFAULT_WINDOW_SECONDS).contains(&window) {
            return Err("invalid window");
        }
        if host.is_some_and(|host| {
            host.is_empty()
                || host.len() > 253
                || host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '?' | '#'))
        }) {
            return Err("invalid host");
        }
        if path.is_some_and(|path| {
            path.len() > MAX_PATH_BYTES
                || path.chars().any(|c| c.is_control() || c == '?' || c == '#')
        }) {
            return Err("invalid prefix");
        }
        Ok(())
    }
    pub fn snapshot(
        &self,
        host: Option<&str>,
        prefix: Option<&str>,
        window: u64,
        now_ms: u64,
    ) -> Snapshot {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let end = now_ms / 1000;
        let start = end.saturating_add(1).saturating_sub(window);
        let retained_start = end.saturating_add(1).saturating_sub(DEFAULT_WINDOW_SECONDS);
        state.entries.retain(|_, entry| {
            entry
                .buckets
                .iter()
                .any(|(second, count)| *count > 0 && *second >= retained_start && *second <= end)
        });
        let count = state
            .entries
            .iter()
            .filter(|((h, p), _)| {
                host.is_none_or(|v| h == &v.to_ascii_lowercase())
                    && prefix.is_none_or(|v| p.starts_with(v))
            })
            .map(|(_, e)| e.count(start, end + 1))
            .sum();
        let overflow = state
            .overflow
            .saturating_add(self.skipped.load(std::sync::atomic::Ordering::Relaxed));
        let coverage_start = state.coverage_start_unix_ms.unwrap_or(now_ms);
        let coverage_complete = coverage_start <= start * 1000;
        Snapshot {
            schema_version: 1,
            source: "gateway_request_starts",
            count,
            host: host.map(str::to_owned),
            path_prefix: prefix.map(str::to_owned),
            window_seconds: window,
            start_unix_ms: start * 1000,
            end_unix_ms: now_ms,
            coverage_start_unix_ms: coverage_start,
            observed_at_unix_ms: now_ms,
            capacity: CAPACITY,
            tracked_keys: state.entries.len(),
            overflow_requests: overflow,
            complete: overflow == 0 && coverage_complete,
            reset: "process_restart",
            path_semantics: "case_sensitive_raw_path_prefix_excludes_query",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_reclaims_expired_keys() {
        let registry = Registry::default();
        for i in 0..CAPACITY {
            registry.observe("example.test", &format!("/old/{i}"), 1_000);
        }
        registry.snapshot(None, None, 900, 902_000);
        registry.observe("example.test", "/new", 902_000);
        let snapshot = registry.snapshot(None, Some("/new"), 900, 902_000);
        assert_eq!(snapshot.count, 1);
        assert_eq!(snapshot.tracked_keys, 1);
        assert_eq!(snapshot.overflow_requests, 0);
    }

    #[test]
    fn observes_started_counts_by_normalized_host_raw_path_and_window() {
        let registry = Registry::default();
        registry.observe("EXAMPLE.test", "/api/orders", 10_000);
        registry.observe("example.test", "/api/orderly", 10_500);
        registry.observe("other.test", "/api/orders", 10_500);
        let result = registry.snapshot(Some("example.test"), Some("/api/order"), 15, 11_000);
        assert_eq!(result.count, 2);
        assert_eq!(result.source, "gateway_request_starts");
    }
    #[test]
    fn expires_old_buckets_and_reports_bounded_key_overflow() {
        let registry = Registry::default();
        registry.observe("h", "/old", 1_000);
        assert_eq!(registry.snapshot(None, None, 1, 3_000).count, 0);
        let registry = Registry::default();
        for i in 0..=CAPACITY {
            registry.observe("h", &format!("/{i}"), 4_000);
        }
        let result = registry.snapshot(None, None, 15, 4_000);
        assert_eq!(result.tracked_keys, CAPACITY);
        assert_eq!(result.overflow_requests, 1);
        assert!(!result.complete);
    }
    #[test]
    fn startup_window_is_marked_partial_until_full_window_coverage() {
        let registry = Registry::default();
        let cold = registry.snapshot(None, None, 15, 20_000);
        assert!(!cold.complete);
        assert_eq!(cold.coverage_start_unix_ms, 20_000);
        registry.observe("h", "/", 20_000);
        assert!(!registry.snapshot(None, None, 15, 30_000).complete);
        assert!(registry.snapshot(None, None, 15, 35_000).complete);
    }

    #[test]
    fn validates_filter_bounds() {
        assert!(Registry::validate(Some("example.test"), Some("/api"), 900).is_ok());
        assert!(Registry::validate(None, Some("/api?q"), 15).is_err());
        assert!(Registry::validate(None, None, 901).is_err());
    }
}
