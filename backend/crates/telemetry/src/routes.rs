//! Process-local stable route slots. No I/O, eviction or log dependency on requests.
//! Retired IDs keep their slot until restart; in-flight requests retain their Arc.
use super::*;
use std::sync::OnceLock;
pub const CAPACITY: usize = 128;
pub const SCOPES: [&str; 5] = [
    "full",
    "headers_query_only",
    "skipped_multipart",
    "off",
    "not_inspected",
];
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Security {
    pub coverage: [u64; 5],
    pub would_block: u64,
    pub rule_matches: u64,
    pub truncated_reports: u64,
}
#[derive(Default)]
struct SecurityCounters {
    coverage: [AtomicU64; 5],
    would_block: AtomicU64,
    rule_matches: AtomicU64,
    truncated_reports: AtomicU64,
}
pub struct Route {
    id: String,
    started_at: u64,
    pub(super) counters: Counters,
    security: SecurityCounters,
    previous: std::sync::Mutex<Option<Totals>>,
    window: watch::Sender<Option<Window>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Window {
    pub observed_at_unix_ms: u64,
    pub window_ms: u64,
    pub incoming_rps: f64,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub route_id: Option<String>,
    pub started_at_unix_ms: u64,
    pub totals: Totals,
    pub security: Security,
    #[serde(default)]
    pub window: Option<Window>,
}
impl Route {
    pub fn security(&self, scope: &str, would_block: bool, matches: usize, truncated: bool) {
        let index = SCOPES.iter().position(|s| *s == scope).unwrap_or(4);
        self.security.coverage[index].fetch_add(1, Relaxed);
        self.security
            .would_block
            .fetch_add(u64::from(would_block), Relaxed);
        self.security
            .rule_matches
            .fetch_add(matches.min(64) as u64, Relaxed);
        self.security
            .truncated_reports
            .fetch_add(u64::from(truncated), Relaxed);
    }
    pub fn sample(&self) -> Sample {
        Sample {
            window: self.window.borrow().clone(),
            route_id: Some(self.id.clone()),
            started_at_unix_ms: self.started_at,
            totals: self.counters.totals(),
            security: Security {
                coverage: std::array::from_fn(|i| self.security.coverage[i].load(Relaxed)),
                would_block: self.security.would_block.load(Relaxed),
                rule_matches: self.security.rule_matches.load(Relaxed),
                truncated_reports: self.security.truncated_reports.load(Relaxed),
            },
        }
    }
}
pub struct Registry {
    slots: [OnceLock<Arc<Route>>; CAPACITY],
    pub overflow_requests: AtomicU64,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| OnceLock::new()),
            overflow_requests: AtomicU64::new(0),
        }
    }
}
impl Registry {
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Route>> {
        self.slots.iter().filter_map(OnceLock::get)
    }
    pub fn register(&self, id: &str) -> Option<Arc<Route>> {
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return None;
        }
        for slot in &self.slots {
            let route = slot.get_or_init(|| {
                Arc::new(Route {
                    id: id.to_owned(),
                    started_at: now_ms(),
                    counters: Counters::default(),
                    security: SecurityCounters::default(),
                    previous: std::sync::Mutex::new(None),
                    window: watch::channel(None).0,
                })
            });
            if route.id == id {
                return Some(route.clone());
            }
        }
        self.overflow_requests.fetch_add(1, Relaxed);
        None
    }
    pub fn publish(&self, gateway: &Metrics) {
        for route in self.iter() {
            let totals = route.counters.totals();
            let mut previous = route.previous.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old) = previous.as_ref() {
                let delta = delta(&totals, old);
                route.window.send_replace(Some(Window {
                    observed_at_unix_ms: gateway.observed_at_unix_ms,
                    window_ms: gateway.window_ms,
                    incoming_rps: delta.incoming as f64 * 1000.0 / gateway.window_ms.max(1) as f64,
                    p95_ms: quantile(&delta.latency_buckets, 95),
                    p99_ms: quantile(&delta.latency_buckets, 99),
                }));
            }
            *previous = Some(totals);
        }
    }
    pub fn samples(&self) -> Vec<Sample> {
        self.iter().map(|r| r.sample()).collect()
    }
}
impl Request {
    /// Once, immediately after routing and before any route-level decision.
    pub fn route(&mut self, id: &str) {
        if self.route_selected {
            return;
        }
        self.route_selected = true;
        if let Some(route) = self.hub.routes.register(id) {
            route.counters.incoming.fetch_add(1, Relaxed);
            route.counters.active.fetch_add(1, Relaxed);
            self.route = Some(route);
        }
    }
    /// Exactly once at request finalization, including cancellation. Does not inspect payloads.
    pub fn security(&self, scope: &str, would_block: bool, matches: usize, truncated: bool) {
        if let Some(route) = &self.route {
            route.security(scope, would_block, matches, truncated);
        }
    }
}
/// Difference of cumulative counters, never subtract runtime gauges.
pub fn delta(new: &Totals, old: &Totals) -> Totals {
    let mut result = Totals::default();
    macro_rules! fields { ($($f:ident),*) => { $(result.$f = new.$f.saturating_sub(old.$f);)* }; }
    fields!(
        incoming,
        forwarded,
        blocked,
        completed,
        cancelled,
        upstream_errors,
        dropped_logs,
        received_bytes,
        sent_bytes,
        response_bytes_observed,
        latency_sum_ms
    );
    result.status_classes =
        std::array::from_fn(|i| new.status_classes[i].saturating_sub(old.status_classes[i]));
    result.latency_buckets =
        std::array::from_fn(|i| new.latency_buckets[i].saturating_sub(old.latency_buckets[i]));
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_totals_survive_log_overflow_and_count_cancellation_once() {
        let (hub, rx) = Hub::new();
        for _ in 0..LOG_CAPACITY + 3 {
            let mut r = hub.start("GET");
            r.route("stable");
            r.route("wrong");
            r.blocked();
            r.blocked();
            r.security("full", true, 3, false);
            r.finish(403, 1, Some(0), false, 4, 2);
        }
        let mut cancelled = hub.start("GET");
        cancelled.route("stable");
        drop(cancelled);
        let sample = hub.routes.samples().remove(0);
        assert_eq!(sample.totals.incoming, (LOG_CAPACITY + 4) as u64);
        assert_eq!(sample.totals.cancelled, 1);
        assert_eq!(sample.totals.active_requests, 0);
        assert_eq!(sample.totals.dropped_logs, 3);
        assert_eq!(rx.len(), LOG_CAPACITY);
        assert_eq!(sample.security.rule_matches, 3 * (LOG_CAPACITY + 3) as u64);
        assert_eq!(sample.security.would_block, (LOG_CAPACITY + 3) as u64);
    }
    #[test]
    fn slots_never_evict_or_mix_ids_and_histograms_merge_before_quantiles() {
        let registry = Registry::default();
        for i in 0..CAPACITY {
            assert!(registry.register(&format!("r{i}")).is_some());
        }
        assert!(registry.register("overflow").is_none());
        assert_eq!(registry.overflow_requests.load(Relaxed), 1);
        assert!(registry.register("r0").is_some());
        let mut new = Totals::default();
        new.latency_buckets[0] = 99;
        new.latency_buckets[9] = 1;
        assert_eq!(
            quantile(&delta(&new, &Totals::default()).latency_buckets, 99),
            Some(1)
        );
        assert_eq!(quantile(&[0; 16], 95), None);
    }
}
