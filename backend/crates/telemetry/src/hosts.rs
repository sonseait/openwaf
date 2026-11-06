//! Stable bounded host slots. Registration performs no I/O; established slots
//! use atomic counters. Initialization is serialized only once per slot.
use super::*;
use std::sync::OnceLock;

pub const CAPACITY: usize = 32;

pub fn valid_name(name: &str) -> bool {
    name.parse::<std::net::IpAddr>().is_ok()
        || (!name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }))
}

pub struct Host {
    pub name: String,
    started_at: u64,
    pub(super) counters: Counters,
    pub(super) dimensions: dimensions::Counters,
    pub metrics: watch::Sender<Arc<Metrics>>,
}
impl Host {
    fn new(name: &str, epoch: &str, started_at: u64) -> Self {
        Self {
            name: name.to_owned(),
            started_at,
            counters: Counters::default(),
            dimensions: dimensions::Counters::default(),
            metrics: watch::channel(Arc::new(Metrics {
                schema_version: 1,
                epoch: epoch.to_owned(),
                host: Some(name.to_owned()),
                statistics_started_at_unix_ms: Some(started_at),
                ..Default::default()
            }))
            .0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCheckpoint {
    pub name: String,
    pub started_at_unix_ms: u64,
    pub totals: Totals,
    pub dimensions: Dimensions,
}

pub struct Registry {
    slots: [OnceLock<Arc<Host>>; CAPACITY],
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
    pub fn iter(&self) -> impl Iterator<Item = &Arc<Host>> {
        self.slots.iter().filter_map(OnceLock::get)
    }
    pub fn get(&self, name: &str) -> Option<Arc<Host>> {
        self.iter().find(|host| host.name == name).cloned()
    }
    fn insert(&self, name: &str, epoch: &str, started_at: u64) -> Option<Arc<Host>> {
        // Every caller traverses in the same order. Concurrent first requests
        // for a name cannot claim duplicate slots. No eviction during requests.
        for (index, slot) in self.slots.iter().enumerate() {
            let host = slot.get_or_init(|| {
                Arc::new(Host::new(
                    name,
                    &format!("{epoch}:host:{index}"),
                    started_at,
                ))
            });
            if host.name == name {
                return Some(host.clone());
            }
        }
        None
    }
    pub fn register(&self, name: &str, epoch: &str) -> Option<Arc<Host>> {
        if !valid_name(name) {
            return None;
        }
        let result = self.insert(name, epoch, now_ms());
        if result.is_none() {
            self.overflow_requests.fetch_add(1, Relaxed);
        }
        result
    }
    pub fn checkpoint(&self) -> Vec<HostCheckpoint> {
        self.iter()
            .map(|host| {
                let mut totals = host.counters.totals();
                totals.active_requests = 0;
                totals.active_connections = 0;
                HostCheckpoint {
                    name: host.name.clone(),
                    started_at_unix_ms: host.started_at,
                    totals,
                    dimensions: host.dimensions.snapshot(),
                }
            })
            .collect()
    }
    pub fn validate(&self, checkpoints: &[HostCheckpoint]) -> Result<(), &'static str> {
        let mut seen = std::collections::BTreeSet::new();
        if checkpoints.len() > CAPACITY || self.iter().next().is_some() {
            return Err("invalid host statistics capacity or already started");
        }
        for checkpoint in checkpoints {
            if !valid_name(&checkpoint.name) || !seen.insert(&checkpoint.name) {
                return Err("invalid or duplicate statistics host");
            }
            dimensions::Counters::default().restore(&checkpoint.dimensions)?;
        }
        Ok(())
    }
    pub fn restore(&self, checkpoints: &[HostCheckpoint], epoch: &str) -> Result<(), &'static str> {
        // Hub validates the entire checkpoint before any mutation.
        for checkpoint in checkpoints {
            let host = self
                .insert(&checkpoint.name, epoch, checkpoint.started_at_unix_ms)
                .ok_or("host statistics capacity exceeded during restore")?;
            host.dimensions.restore(&checkpoint.dimensions)?;
            host.counters.restore(&checkpoint.totals);
            let mut metrics = host.metrics.borrow().as_ref().clone();
            metrics.totals = host.counters.totals();
            metrics.dimensions = host.dimensions.snapshot();
            host.metrics.send_replace(Arc::new(metrics));
        }
        Ok(())
    }
    pub fn publish(&self, gateway: &Metrics) {
        for host in self.iter() {
            let previous = host.metrics.borrow().clone();
            let totals = host.counters.totals();
            let rate =
                |a: u64, b: u64| a.saturating_sub(b) as f64 * 1000.0 / gateway.window_ms as f64;
            let buckets = std::array::from_fn(|i| {
                totals.latency_buckets[i].saturating_sub(previous.totals.latency_buckets[i])
            });
            host.metrics.send_replace(Arc::new(Metrics {
                host: Some(host.name.clone()),
                statistics_started_at_unix_ms: Some(host.started_at),
                epoch: previous.epoch.clone(),
                incoming_rps: rate(totals.incoming, previous.totals.incoming),
                forwarded_rps: rate(totals.forwarded, previous.totals.forwarded),
                blocked_rps: rate(totals.blocked, previous.totals.blocked),
                received_bytes_per_second: rate(
                    totals.received_bytes,
                    previous.totals.received_bytes,
                ),
                response_bytes_per_second: rate(
                    totals.response_bytes_observed,
                    previous.totals.response_bytes_observed,
                ),
                latency_p50_ms: quantile(&buckets, 50),
                latency_p95_ms: quantile(&buckets, 95),
                latency_p99_ms: quantile(&buckets, 99),
                totals,
                dimensions: host.dimensions.snapshot(),
                ..gateway.clone()
            }));
        }
    }
    pub fn prometheus(&self, output: &mut String) {
        use std::fmt::Write;
        output.push_str("# TYPE openwaf_host_incoming_total counter\n");
        for host in self.iter() {
            let _ = writeln!(
                output,
                "openwaf_host_incoming_total{{host=\"{}\"}} {}",
                host.name,
                host.counters.incoming.load(Relaxed)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_filters_all_counters_dimensions_and_windows_without_using_logs() {
        let (hub, receiver) = Hub::new();
        let mut first = hub.start_with_agent("POST", Some(b"Firefox/1"));
        first.host("one.test");
        first.country(dimensions::Country::Code("GB"));
        first.blocked();
        first.blocked();
        first.received_total(12);
        first.received_total(12);
        first.finish(403, 1, None, false, 12, 7);
        let mut second = hub.start("GET");
        second.host("two.test");
        second.forwarded();
        second.response_bytes(37);
        second.finish(502, 1, None, true, 4, 37);
        let mut cancelled = hub.start("GET");
        cancelled.host("two.test");
        drop(cancelled);
        hub.hosts.publish(&Metrics {
            window_ms: 1000,
            sequence: 1,
            ..Default::default()
        });
        let one = hub.hosts.get("one.test").expect("one");
        let two = hub.hosts.get("two.test").expect("two");
        let metrics = one.metrics.borrow().clone();
        assert_eq!(metrics.host.as_deref(), Some("one.test"));
        assert_eq!(metrics.totals.incoming, 1);
        assert_eq!(metrics.totals.blocked, 1);
        assert_eq!(metrics.totals.completed, 1);
        assert_eq!(metrics.totals.forwarded, 0);
        assert_eq!(metrics.totals.status_classes[4], 1);
        assert_eq!(metrics.totals.received_bytes, 12);
        assert_eq!(metrics.totals.sent_bytes, 7);
        assert_eq!(metrics.incoming_rps, 1.0);
        assert_eq!(metrics.received_bytes_per_second, 12.0);
        assert!(metrics.latency_p95_ms.is_some());
        assert_eq!(metrics.dimensions.countries[0].label, "GB");
        assert_eq!(metrics.dimensions.countries[0].blocked, 1);
        assert_eq!(
            metrics
                .dimensions
                .user_agents
                .iter()
                .find(|v| v.label == "Firefox")
                .expect("Firefox")
                .received,
            1
        );
        let other = two.metrics.borrow().clone();
        assert_eq!(other.totals.incoming, 2);
        assert_eq!(other.totals.cancelled, 1);
        assert_eq!(other.totals.active_requests, 0);
        assert_eq!(other.totals.upstream_errors, 1);
        assert_eq!(other.totals.status_classes[5], 1);
        assert_eq!(other.response_bytes_per_second, 37.0);
        assert_eq!(hub.totals().incoming, 3);
        assert_eq!(receiver.len(), 2, "host accounting must not duplicate logs");
        hub.hosts.publish(&Metrics {
            window_ms: 1000,
            sequence: 2,
            ..Default::default()
        });
        assert_eq!(one.metrics.borrow().incoming_rps, 0.0);
        assert!(one.metrics.borrow().latency_p95_ms.is_none());
    }

    #[test]
    fn checkpoint_roundtrip_and_legacy_restore_preserve_baselines_and_reject_partial_restore() {
        let (hub, _receiver) = Hub::new();
        let mut request = hub.start("GET");
        request.host("app.test");
        request.blocked();
        request.finish(403, 1, None, false, 9, 3);
        let checkpoint = hub.checkpoint();
        let (restored, _) = Hub::new();
        restored.restore(&checkpoint).expect("restore host");
        let host = restored.hosts.get("app.test").expect("restored host");
        assert_eq!(host.counters.totals().blocked, 1);
        restored.hosts.publish(&Metrics {
            window_ms: 1000,
            sequence: 1,
            ..Default::default()
        });
        assert_eq!(
            host.metrics.borrow().incoming_rps,
            0.0,
            "restored counts are not new traffic"
        );
        assert_eq!(host.counters.totals().received_bytes, 9);
        let mut legacy = serde_json::to_value(&checkpoint).expect("JSON");
        legacy.as_object_mut().expect("object").remove("hosts");
        legacy
            .as_object_mut()
            .expect("object")
            .remove("host_overflow_requests");
        let legacy: Checkpoint = serde_json::from_value(legacy).expect("legacy checkpoint");
        let (old, _) = Hub::new();
        old.restore(&legacy).expect("legacy restore");
        assert_eq!(old.totals().incoming, 1);
        assert_eq!(old.hosts.iter().count(), 0, "never invent host attribution");
        let mut invalid = checkpoint;
        invalid.hosts.push(invalid.hosts[0].clone());
        let (empty, _) = Hub::new();
        assert!(empty.restore(&invalid).is_err());
        assert_eq!(empty.totals().incoming, 0);
        assert_eq!(empty.hosts.iter().count(), 0);
    }

    #[test]
    fn concurrent_registration_and_overflow_keep_memory_and_prometheus_bounded() {
        let (hub, _receiver) = Hub::new();
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    let mut request = hub.start("GET");
                    request.host("shared.test");
                });
            }
        });
        assert_eq!(hub.hosts.iter().count(), 1);
        assert_eq!(
            hub.hosts
                .get("shared.test")
                .expect("host")
                .counters
                .totals()
                .incoming,
            16
        );
        for index in 1..=CAPACITY {
            let mut request = hub.start("GET");
            request.host(&format!("host{index}.test"));
        }
        assert_eq!(hub.hosts.iter().count(), CAPACITY);
        assert_eq!(hub.hosts.overflow_requests.load(Relaxed), 1);
        assert_eq!(hub.totals().incoming, 16 + CAPACITY as u64);
        assert_eq!(
            hub.prometheus()
                .matches("openwaf_host_incoming_total{host=")
                .count(),
            CAPACITY
        );
        assert!(hub.hosts.get("host32.test").is_none());
        assert!(hub.hosts.register("bad\"host", "epoch").is_none());
    }

    #[test]
    fn worst_case_host_checkpoint_fits_database_and_each_stream_fits_sse_limit() {
        let (hub, _) = Hub::new();
        for index in 0..CAPACITY {
            let host = hub
                .hosts
                .register(&format!("host{index}.test"), &hub.epoch)
                .expect("capacity");
            for bucket in host
                .dimensions
                .countries
                .iter()
                .chain(&host.dimensions.agents)
                .chain(&host.dimensions.methods)
            {
                bucket.received.store(u64::MAX, Relaxed);
                bucket.blocked.store(u64::MAX, Relaxed);
            }
        }
        // JSONB adds whitespace; reserve twice the compact JSON size.
        assert!(
            serde_json::to_vec(&hub.checkpoint())
                .expect("checkpoint")
                .len()
                * 2
                < 4 * 1024 * 1024
        );
        hub.hosts.publish(&Metrics {
            window_ms: 1000,
            ..Default::default()
        });
        for host in hub.hosts.iter() {
            assert!(
                serde_json::to_vec(host.metrics.borrow().as_ref())
                    .expect("metrics")
                    .len()
                    < 65536 - 4096
            );
        }
    }
}
