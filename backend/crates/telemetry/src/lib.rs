//! Bounded, best-effort telemetry. Producers use local counters and try_send.
//! Request details carry bounded, redacted metadata prepared by the gateway;
//! body contents, credentials and native matched data never enter this contract.
#![forbid(unsafe_code)]
pub mod dimensions;
pub mod hosts;
pub mod request_id;
pub mod routes;
pub mod window;
use dimensions::{Country, Dimensions};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc, watch};

pub const LOG_CAPACITY: usize = 1024;
pub const LIVE_CAPACITY: usize = 256;
pub const LATENCY_MS: [u64; 16] = [
    1,
    2,
    5,
    10,
    20,
    50,
    100,
    200,
    500,
    1000,
    2000,
    5000,
    10000,
    30000,
    60000,
    u64::MAX,
];

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, Serialize)]
pub struct Log {
    pub request_id: String,
    pub details: String,
    pub observed_at_unix_ms: u64,
    pub method: &'static str,
    pub status: u16,
    pub latency_ms: u64,
    pub config_version: i64,
    pub route_index: Option<usize>,
    pub forwarded: bool,
    pub blocked: bool,
    pub upstream_error: bool,
}

#[derive(Default)]
struct Counters {
    incoming: AtomicU64,
    forwarded: AtomicU64,
    blocked: AtomicU64,
    completed: AtomicU64,
    cancelled: AtomicU64,
    active: AtomicU64,
    active_connections: AtomicU64,
    upstream_errors: AtomicU64,
    dropped_logs: AtomicU64,
    received_bytes: AtomicU64,
    sent_bytes: AtomicU64,
    response_bytes_observed: AtomicU64,
    statuses: [AtomicU64; 6],
    latency: [AtomicU64; 16],
    latency_sum_ms: AtomicU64,
}

impl Counters {
    pub fn totals(&self) -> Totals {
        let c = self;
        Totals {
            incoming: c.incoming.load(Relaxed),
            forwarded: c.forwarded.load(Relaxed),
            blocked: c.blocked.load(Relaxed),
            completed: c.completed.load(Relaxed),
            cancelled: c.cancelled.load(Relaxed),
            active_requests: c.active.load(Relaxed),
            active_connections: c.active_connections.load(Relaxed),
            upstream_errors: c.upstream_errors.load(Relaxed),
            dropped_logs: c.dropped_logs.load(Relaxed),
            received_bytes: c.received_bytes.load(Relaxed),
            sent_bytes: c.sent_bytes.load(Relaxed),
            response_bytes_observed: c.response_bytes_observed.load(Relaxed),
            status_classes: std::array::from_fn(|i| c.statuses[i].load(Relaxed)),
            latency_buckets: std::array::from_fn(|i| c.latency[i].load(Relaxed)),
            latency_sum_ms: c.latency_sum_ms.load(Relaxed),
        }
    }
    fn restore(&self, t: &Totals) {
        let c = self;
        for (counter, value) in [
            (&c.incoming, t.incoming),
            (&c.forwarded, t.forwarded),
            (&c.blocked, t.blocked),
            (&c.completed, t.completed),
            (&c.cancelled, t.cancelled),
            (&c.upstream_errors, t.upstream_errors),
            (&c.dropped_logs, t.dropped_logs),
            (&c.received_bytes, t.received_bytes),
            (&c.sent_bytes, t.sent_bytes),
            (&c.response_bytes_observed, t.response_bytes_observed),
            (&c.latency_sum_ms, t.latency_sum_ms),
        ] {
            counter.store(value, Relaxed);
        }
        for (counter, value) in c.statuses.iter().zip(t.status_classes) {
            counter.store(value, Relaxed);
        }
        for (counter, value) in c.latency.iter().zip(t.latency_buckets) {
            counter.store(value, Relaxed);
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    pub incoming: u64,
    pub forwarded: u64,
    pub blocked: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub active_requests: u64,
    pub active_connections: u64,
    pub upstream_errors: u64,
    pub dropped_logs: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub response_bytes_observed: u64,
    /// Index 0 = no final HTTP response or other class, then 1xx through 5xx.
    pub status_classes: [u64; 6],
    /// Non-cumulative bins matching LATENCY_MS, last bin = +Inf.
    pub latency_buckets: [u64; 16],
    pub latency_sum_ms: u64,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Metrics {
    pub host: Option<String>,
    pub statistics_started_at_unix_ms: Option<u64>,
    pub schema_version: u8,
    pub epoch: String,
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub window_ms: u64,
    pub incoming_rps: f64,
    pub forwarded_rps: f64,
    pub blocked_rps: f64,
    pub received_bytes_per_second: f64,
    pub response_bytes_per_second: f64,
    /// Upper bounds for completed-request latency in this window, not averaged percentiles.
    pub latency_p50_ms: Option<u64>,
    pub latency_p95_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
    pub log_queue_depth: usize,
    pub log_queue_capacity: usize,
    pub totals: Totals,
    pub resources: Resources,
    pub dimensions: Dimensions,
    pub persistence: Persistence,
}

/// Versioned bounded checkpoint; runtime gauges and event cursors are never resumed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    #[serde(default)]
    pub hosts: Vec<hosts::HostCheckpoint>,
    #[serde(default)]
    pub host_overflow_requests: u64,
    pub generation: u64,
    pub schema_version: u8,
    pub saved_at_unix_ms: u64,
    pub totals: Totals,
    pub dimensions: Dimensions,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Persistence {
    pub configured: bool,
    pub degraded: bool,
    pub last_success_unix_ms: u64,
    pub interval_ms: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Resources {
    pub available: bool,
    /// Linux USER_HZ ticks for all process threads, cumulative since start.
    pub process_cpu_ticks: Option<u64>,
    pub resident_bytes: Option<u64>,
    pub unavailable_reason: Option<&'static str>,
}
async fn resource_file(path: &str) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).await.ok()?;
    if bytes.len() > 65536 {
        return None;
    }
    String::from_utf8(bytes).ok()
}
async fn resources() -> Resources {
    let read = async {
        let stat = resource_file("/proc/self/stat").await?;
        // comm can contain spaces/parentheses: fields after the final ')' start at field 3.
        let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        let cpu = fields
            .get(11)?
            .parse::<u64>()
            .ok()?
            .checked_add(fields.get(12)?.parse::<u64>().ok()?)?;
        let status = resource_file("/proc/self/status").await?;
        let rss = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)?;
        Some((cpu, rss))
    };
    match tokio::time::timeout(Duration::from_millis(100), read).await {
        Ok(Some((cpu, rss))) => Resources {
            available: true,
            process_cpu_ticks: Some(cpu),
            resident_bytes: Some(rss),
            unavailable_reason: None,
        },
        _ => Resources {
            unavailable_reason: Some("process_resources_unavailable"),
            ..Default::default()
        },
    }
}

pub struct Connection(Arc<Hub>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.counters.active_connections.fetch_sub(1, Relaxed);
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct LiveLog {
    pub epoch: String,
    pub sequence: u64,
    #[serde(flatten)]
    pub log: Log,
}

pub struct Hub {
    pub hosts: hosts::Registry,
    pub window: window::Registry,
    pub routes: routes::Registry,
    checkpoint_generation: AtomicU64,
    persistence_configured: std::sync::atomic::AtomicBool,
    persistence_degraded: std::sync::atomic::AtomicBool,
    persistence_saved_at: AtomicU64,
    recent: std::sync::Mutex<std::collections::VecDeque<Log>>,
    counters: Counters,
    dimensions: dimensions::Counters,
    sender: mpsc::Sender<Log>,
    pub epoch: String,
    pub metrics: watch::Sender<Arc<Metrics>>,
    pub logs: broadcast::Sender<Arc<LiveLog>>,
    pub log_sequence: AtomicU64,
}

impl Hub {
    /// Receiver has exactly one owner; dropping run() cancels all aggregation work.
    pub fn new() -> (Arc<Self>, mpsc::Receiver<Log>) {
        let (sender, receiver) = mpsc::channel(LOG_CAPACITY);
        let epoch = format!(
            "{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            std::process::id()
        );
        let (metrics, _) = watch::channel(Arc::new(Metrics {
            schema_version: 1,
            epoch: epoch.clone(),
            ..Default::default()
        }));
        let (logs, _) = broadcast::channel(LIVE_CAPACITY);
        (
            Arc::new(Self {
                hosts: hosts::Registry::default(),
                window: window::Registry::default(),
                routes: routes::Registry::default(),
                checkpoint_generation: Default::default(),
                persistence_configured: Default::default(),
                persistence_degraded: Default::default(),
                persistence_saved_at: Default::default(),
                recent: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(1000)),
                counters: Counters::default(),
                dimensions: dimensions::Counters::default(),
                sender,
                epoch,
                metrics,
                logs,
                log_sequence: AtomicU64::new(0),
            }),
            receiver,
        )
    }

    pub fn persistence_result(&self, saved_at: Option<u64>) {
        self.persistence_configured.store(true, Relaxed);
        self.persistence_degraded.store(saved_at.is_none(), Relaxed);
        if let Some(time) = saved_at {
            self.persistence_saved_at.store(time, Relaxed);
        }
    }
    pub fn persistence(&self) -> Persistence {
        Persistence {
            configured: self.persistence_configured.load(Relaxed),
            degraded: self.persistence_degraded.load(Relaxed),
            last_success_unix_ms: self.persistence_saved_at.load(Relaxed),
            interval_ms: 5000,
        }
    }
    pub fn checkpoint(&self) -> Checkpoint {
        let mut totals = self.totals();
        totals.active_requests = 0;
        totals.active_connections = 0;
        Checkpoint {
            hosts: self.hosts.checkpoint(),
            host_overflow_requests: self.hosts.overflow_requests.load(Relaxed),
            generation: self.checkpoint_generation.fetch_add(1, Relaxed) + 1,
            schema_version: 1,
            saved_at_unix_ms: now_ms(),
            totals,
            dimensions: self.dimensions.snapshot(),
        }
    }
    /// Only called during startup before publishing the gateway. Refuse malformed
    /// checkpoints before touching any counter; a corrupt baseline must not be overwritten.
    pub fn restore(&self, checkpoint: &Checkpoint) -> Result<(), &'static str> {
        if checkpoint.schema_version != 1
            || checkpoint.generation == u64::MAX
            || self.totals().incoming != 0
        {
            return Err("invalid statistics checkpoint or hub already started");
        }
        self.hosts.validate(&checkpoint.hosts)?;
        self.dimensions.restore(&checkpoint.dimensions)?;
        self.hosts.restore(&checkpoint.hosts, &self.epoch)?;
        self.hosts
            .overflow_requests
            .store(checkpoint.host_overflow_requests, Relaxed);
        self.counters.restore(&checkpoint.totals);
        self.checkpoint_generation
            .store(checkpoint.generation, Relaxed);
        self.persistence_result(Some(checkpoint.saved_at_unix_ms));
        self.metrics.send_replace(Arc::new(Metrics {
            schema_version: 1,
            epoch: self.epoch.clone(),
            observed_at_unix_ms: now_ms(),
            totals: self.totals(),
            dimensions: self.dimensions.snapshot(),
            persistence: self.persistence(),
            ..Default::default()
        }));
        Ok(())
    }
    pub fn lookup(&self, id: &str) -> Option<Log> {
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .find(|l| l.request_id == id)
            .cloned()
    }
    pub fn start(self: &Arc<Self>, method: &str) -> Request {
        self.start_with_agent(method, None)
    }
    pub fn start_with_agent(self: &Arc<Self>, method: &str, agent: Option<&[u8]>) -> Request {
        let agent = dimensions::agent(agent);
        let method_index = dimensions::METHODS
            .iter()
            .position(|m| *m == method)
            .unwrap_or(9);
        self.dimensions.countries[dimensions::UNATTRIBUTED]
            .received
            .fetch_add(1, Relaxed);
        self.dimensions.agents[agent].received.fetch_add(1, Relaxed);
        self.dimensions.methods[method_index]
            .received
            .fetch_add(1, Relaxed);
        self.counters.incoming.fetch_add(1, Relaxed);
        self.counters.active.fetch_add(1, Relaxed);
        Request {
            hub: self.clone(),
            host: None,
            route: None,
            route_selected: false,
            started: Instant::now(),
            method: method_name(method),
            forwarded: false,
            blocked: false,
            finished: false,
            received_seen: 0,
            country: dimensions::UNATTRIBUTED,
            agent,
            method_index,
            config_version: 0,
            route_index: None,
            request_id: String::new(),
            details: String::from("{}"),
        }
    }
    pub fn connection(self: &Arc<Self>) -> Connection {
        self.counters.active_connections.fetch_add(1, Relaxed);
        Connection(self.clone())
    }
    pub fn totals(&self) -> Totals {
        self.counters.totals()
    }
    pub async fn run(self: Arc<Self>, receiver: mpsc::Receiver<Log>) {
        let (_owner, stop) = watch::channel(false);
        self.run_until(receiver, stop).await;
    }
    /// Close admission to the log queue, then publish every already queued log.
    /// The proxy owner must drain requests before signalling this owner.
    pub async fn run_until(
        self: Arc<Self>,
        mut receiver: mpsc::Receiver<Log>,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        let mut previous = self.totals();
        let mut last = Instant::now();
        let mut sequence = 0;
        let mut draining = *stop.borrow();
        if draining {
            receiver.close();
        }
        loop {
            tokio::select! {
                biased;
                _ = stop.changed(), if !draining => {
                    draining = true;
                    receiver.close();
                }
                _ = tick.tick(), if !draining => {
                    let totals = self.totals();
                    let window_ms = last.elapsed().as_millis().max(1) as u64;
                    last = Instant::now();
                    sequence += 1;
                    let buckets = std::array::from_fn(|i| totals.latency_buckets[i].saturating_sub(previous.latency_buckets[i]));
                    let rate = |a: u64, b: u64| a.saturating_sub(b) as f64 * 1000.0 / window_ms as f64;
                    let metrics = Metrics { host: None, statistics_started_at_unix_ms: None, schema_version: 1, epoch: self.epoch.clone(), sequence, observed_at_unix_ms: now_ms(), window_ms, incoming_rps: rate(totals.incoming, previous.incoming), forwarded_rps: rate(totals.forwarded, previous.forwarded), blocked_rps: rate(totals.blocked, previous.blocked), received_bytes_per_second: rate(totals.received_bytes, previous.received_bytes), response_bytes_per_second: rate(totals.response_bytes_observed, previous.response_bytes_observed), latency_p50_ms: quantile(&buckets, 50), latency_p95_ms: quantile(&buckets, 95), latency_p99_ms: quantile(&buckets, 99), log_queue_depth: self.sender.max_capacity() - self.sender.capacity(), log_queue_capacity: LOG_CAPACITY, totals: totals.clone(), resources: resources().await, dimensions: self.dimensions.snapshot(), persistence: self.persistence() };
                    previous = totals;
                    self.hosts.publish(&metrics);
                    self.routes.publish(&metrics);
                    self.metrics.send_replace(Arc::new(metrics));
                }
                log = receiver.recv() => {
                    let Some(log) = log else { break };
                    {let mut recent=self.recent.lock().unwrap_or_else(|e|e.into_inner());if recent.len()==1000 {recent.pop_front();}recent.push_back(log.clone());}
                    let sequence = self.log_sequence.fetch_add(1, Relaxed) + 1;
                    // No subscribers is normal; broadcast never waits for a slow consumer.
                    let _ = self.logs.send(Arc::new(LiveLog { epoch: self.epoch.clone(), sequence, log }));
                }
            }
        }
    }
    pub fn prometheus(&self) -> String {
        let t = self.totals();
        let mut out = String::new();
        use std::fmt::Write;
        for (name, kind, value) in [
            ("incoming_total", "counter", t.incoming),
            ("forwarded_total", "counter", t.forwarded),
            ("blocked_total", "counter", t.blocked),
            ("completed_total", "counter", t.completed),
            ("cancelled_total", "counter", t.cancelled),
            ("active_requests", "gauge", t.active_requests),
            ("active_connections", "gauge", t.active_connections),
            ("upstream_errors_total", "counter", t.upstream_errors),
            ("dropped_logs_total", "counter", t.dropped_logs),
            ("received_bytes_total", "counter", t.received_bytes),
            ("sent_bytes_total", "counter", t.sent_bytes),
        ] {
            let _ = writeln!(out, "# TYPE openwaf_{name} {kind}\nopenwaf_{name} {value}");
        }
        out.push_str("# TYPE openwaf_request_duration_seconds histogram\n");
        let mut cumulative = 0;
        for (i, count) in t.latency_buckets.iter().enumerate() {
            cumulative += count;
            let bound = if i == LATENCY_MS.len() - 1 {
                "+Inf".into()
            } else {
                format!("{}", LATENCY_MS[i] as f64 / 1000.0)
            };
            let _ = writeln!(
                out,
                "openwaf_request_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}"
            );
        }
        let _ = writeln!(
            out,
            "openwaf_request_duration_seconds_count {}\nopenwaf_request_duration_seconds_sum {}",
            t.latency_buckets.iter().sum::<u64>(),
            t.latency_sum_ms as f64 / 1000.0
        );
        out.push_str("# TYPE openwaf_responses_total counter\n");
        for (i, count) in t.status_classes.iter().enumerate() {
            let _ = writeln!(out, "openwaf_responses_total{{class=\"{i}xx\"}} {count}");
        }
        let _ = writeln!(
            out,
            "# TYPE openwaf_log_queue_depth gauge\nopenwaf_log_queue_depth {}",
            self.sender.max_capacity() - self.sender.capacity()
        );
        let resources = self.metrics.borrow().resources.clone();
        if let Some(rss) = resources.resident_bytes {
            let _ = writeln!(
                out,
                "# TYPE openwaf_resident_bytes gauge\nopenwaf_resident_bytes {rss}"
            );
        }
        if let Some(ticks) = resources.process_cpu_ticks {
            let _ = writeln!(
                out,
                "# TYPE openwaf_process_cpu_ticks_total counter\nopenwaf_process_cpu_ticks_total {ticks}"
            );
        }
        self.hosts.prometheus(&mut out);
        out
    }
}

/// A request owns its accounting even when Pingora cancels without calling logging().
pub struct Request {
    pub config_version: i64,
    pub route_index: Option<usize>,
    pub request_id: String,
    pub details: String,
    hub: Arc<Hub>,
    host: Option<Arc<hosts::Host>>,
    route: Option<Arc<routes::Route>>,
    route_selected: bool,
    started: Instant,
    method: &'static str,
    forwarded: bool,
    blocked: bool,
    finished: bool,
    received_seen: u64,
    country: usize,
    agent: usize,
    method_index: usize,
}
impl Request {
    /// Called once with the validated, normalized authority before security decisions.
    pub fn host(&mut self, name: &str) {
        if self.host.is_some() {
            return;
        }
        if let Some(host) = self.hub.hosts.register(name, &self.hub.epoch) {
            host.counters.incoming.fetch_add(1, Relaxed);
            host.counters.active.fetch_add(1, Relaxed);
            host.dimensions.countries[self.country]
                .received
                .fetch_add(1, Relaxed);
            host.dimensions.agents[self.agent]
                .received
                .fetch_add(1, Relaxed);
            host.dimensions.methods[self.method_index]
                .received
                .fetch_add(1, Relaxed);
            self.host = Some(host);
        }
    }
    fn counters(&self) -> impl Iterator<Item = &Counters> {
        std::iter::once(&self.hub.counters)
            .chain(self.host.as_ref().map(|host| &host.counters))
            .chain(self.route.as_ref().map(|route| &route.counters))
    }
    fn dimensions(&self) -> impl Iterator<Item = &dimensions::Counters> {
        std::iter::once(&self.hub.dimensions).chain(self.host.as_ref().map(|host| &host.dimensions))
    }

    /// Classify exactly once after resolving the client through trusted-proxy rules.
    /// Snapshots are best-effort atomic reads, not a transaction across counters.
    pub fn country(&mut self, country: Country<'_>) {
        if self.country != dimensions::UNATTRIBUTED || self.blocked {
            return;
        }
        let index = country.index();
        for dimensions in self.dimensions() {
            dimensions.countries[self.country]
                .received
                .fetch_sub(1, Relaxed);
            dimensions.countries[index].received.fetch_add(1, Relaxed);
        }
        self.country = index;
    }

    pub fn received_total(&mut self, total: u64) {
        for counters in self.counters() {
            counters
                .received_bytes
                .fetch_add(total.saturating_sub(self.received_seen), Relaxed);
        }
        self.received_seen = self.received_seen.max(total);
    }
    pub fn response_bytes(&self, bytes: u64) {
        for counters in self.counters() {
            counters.response_bytes_observed.fetch_add(bytes, Relaxed);
        }
    }
    pub fn forwarded(&mut self) {
        if !self.forwarded {
            self.forwarded = true;
            for counters in self.counters() {
                counters.forwarded.fetch_add(1, Relaxed);
            }
        }
    }
    pub fn blocked(&mut self) {
        if !self.blocked {
            self.blocked = true;
            for counters in self.counters() {
                counters.blocked.fetch_add(1, Relaxed);
            }
            for dimensions in self.dimensions() {
                dimensions.countries[self.country]
                    .blocked
                    .fetch_add(1, Relaxed);
                dimensions.agents[self.agent].blocked.fetch_add(1, Relaxed);
                dimensions.methods[self.method_index]
                    .blocked
                    .fetch_add(1, Relaxed);
            }
        }
    }
    pub fn finish(
        mut self,
        status: u16,
        version: i64,
        route: Option<usize>,
        upstream_error: bool,
        received_bytes: u64,
        sent_bytes: u64,
    ) {
        let latency_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.received_total(received_bytes);
        for c in self.counters() {
            c.completed.fetch_add(1, Relaxed);
            let class = usize::from(status / 100);
            c.statuses[if (1..=5).contains(&class) { class } else { 0 }].fetch_add(1, Relaxed);
            c.latency[LATENCY_MS
                .iter()
                .position(|bound| latency_ms <= *bound)
                .unwrap_or(15)]
            .fetch_add(1, Relaxed);
            c.latency_sum_ms.fetch_add(latency_ms, Relaxed);
            c.upstream_errors
                .fetch_add(u64::from(upstream_error), Relaxed);
            c.sent_bytes.fetch_add(sent_bytes, Relaxed);
        }
        let log = Log {
            request_id: std::mem::take(&mut self.request_id),
            details: std::mem::take(&mut self.details),
            observed_at_unix_ms: now_ms(),
            method: self.method,
            status,
            latency_ms,
            config_version: version,
            route_index: route,
            forwarded: self.forwarded,
            blocked: self.blocked,
            upstream_error,
        };
        if self.hub.sender.try_send(log).is_err() {
            for c in self.counters() {
                c.dropped_logs.fetch_add(1, Relaxed);
            }
        }
        self.finished = true;
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        for c in self.counters() {
            c.active.fetch_sub(1, Relaxed);
        }
        if !self.finished {
            for c in self.counters() {
                c.cancelled.fetch_add(1, Relaxed);
            }
            if !self.request_id.is_empty() {
                let log = Log {
                    request_id: std::mem::take(&mut self.request_id),
                    details: std::mem::take(&mut self.details),
                    observed_at_unix_ms: now_ms(),
                    method: self.method,
                    status: 0,
                    latency_ms: self.started.elapsed().as_millis() as u64,
                    config_version: self.config_version,
                    route_index: self.route_index,
                    forwarded: self.forwarded,
                    blocked: self.blocked,
                    upstream_error: false,
                };
                if self.hub.sender.try_send(log).is_err() {
                    for c in self.counters() {
                        c.dropped_logs.fetch_add(1, Relaxed);
                    }
                }
            }
        }
    }
}
fn method_name(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "OTHER",
    }
}
pub fn quantile(buckets: &[u64; 16], percentile: u64) -> Option<u64> {
    let total: u128 = buckets.iter().map(|v| u128::from(*v)).sum();
    if total == 0 {
        return None;
    }
    let rank = (total * u128::from(percentile)).div_ceil(100);
    let mut count = 0;
    for (i, value) in buckets.iter().enumerate() {
        count += u128::from(*value);
        if count >= rank {
            return (LATENCY_MS[i] != u64::MAX).then_some(LATENCY_MS[i]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dimensions_count_starts_and_block_decisions_without_retaining_headers() {
        let (hub, _receiver) = Hub::new();
        let mut request =
            hub.start_with_agent("GET", Some(b"Chrome/140 Safari/537 Edg/140 private-value"));
        request.country(Country::Code("GB"));
        request.country(Country::Code("US")); // Identity cannot change after classification.
        request.blocked();
        request.blocked();
        let snapshot = hub.dimensions.snapshot();
        assert_eq!(hub.totals().incoming, 1);
        assert_eq!(hub.totals().completed, 0);
        assert_eq!(snapshot.countries.len(), 1);
        assert_eq!(snapshot.countries[0].label, "GB");
        assert_eq!(
            (
                snapshot.countries[0].received,
                snapshot.countries[0].blocked
            ),
            (1, 1)
        );
        assert_eq!(
            (
                snapshot.user_agents[0].received,
                snapshot.user_agents[0].blocked
            ),
            (1, 1)
        );
        drop(request);
        hub.start("SECRET-METHOD").finish(400, 0, None, false, 0, 0);
        let encoded = serde_json::to_string(&hub.dimensions.snapshot()).expect("serialize");
        assert!(!encoded.contains("private-value"));
        assert!(!encoded.contains("SECRET-METHOD"));
        assert!(encoded.contains("Unattributed"));
        assert_eq!(hub.dimensions.snapshot().methods[9].received, 1);
    }
    #[test]
    fn replay_does_not_double_count_received_body_and_other_status_is_explicit() {
        let (hub, mut receiver) = Hub::new();
        let mut request = hub.start("CUSTOM-SENSITIVE-METHOD");
        request.received_total(1024);
        request.received_total(1024);
        request.received_total(128);
        request.response_bytes(5);
        request.response_bytes(7);
        assert_eq!(hub.totals().completed, 0);
        assert_eq!(hub.totals().received_bytes, 1024);
        assert_eq!(hub.totals().response_bytes_observed, 12);
        request.finish(999, 7, Some(1), false, 1024, 12);
        assert_eq!(hub.totals().received_bytes, 1024);
        assert_eq!(hub.totals().sent_bytes, 12);
        assert_eq!(hub.totals().status_classes, [1, 0, 0, 0, 0, 0]);
        let log = receiver.try_recv().expect("completion metadata");
        assert_eq!(log.method, "OTHER");
        assert_eq!(log.config_version, 7);
        assert_eq!(log.route_index, Some(1));
    }
    #[test]
    fn admission_is_distinct_from_completion_and_drop_is_bounded() {
        let (hub, receiver) = Hub::new();
        let mut held = hub.start("secret-method");
        held.forwarded();
        held.forwarded();
        assert_eq!(hub.totals().incoming, 1);
        assert_eq!(hub.totals().completed, 0);
        assert_eq!(hub.totals().forwarded, 1);
        drop(held);
        assert_eq!(hub.totals().active_requests, 0);
        assert_eq!(hub.totals().cancelled, 1);
        for _ in 0..LOG_CAPACITY + 7 {
            let mut r = hub.start("GET");
            r.blocked();
            r.blocked();
            r.finish(403, 1, Some(0), false, 0, 0);
        }
        assert_eq!(receiver.len(), LOG_CAPACITY);
        assert_eq!(hub.totals().dropped_logs, 7);
        assert_eq!(hub.totals().blocked, (LOG_CAPACITY + 7) as u64);
        assert_eq!(hub.totals().active_requests, 0);
    }
    #[tokio::test]
    async fn shutdown_publishes_queued_logs_and_closes_admission() {
        let (hub, receiver) = Hub::new();
        let mut logs = hub.logs.subscribe();
        for _ in 0..17 {
            hub.start("GET").finish(200, 1, None, false, 1, 2);
        }
        let (_owner, stop) = watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            hub.clone().run_until(receiver, stop),
        )
        .await
        .expect("bounded drain");
        for sequence in 1..=17 {
            assert_eq!(logs.try_recv().expect("queued log").sequence, sequence);
        }
        hub.start("GET").finish(200, 1, None, false, 1, 2);
        assert_eq!(hub.totals().dropped_logs, 1);
    }
    #[tokio::test]
    async fn slow_subscriber_loses_logs_without_blocking_aggregation() {
        let (hub, receiver) = Hub::new();
        let mut logs = hub.logs.subscribe();
        let owner = tokio::spawn(hub.clone().run(receiver));
        let details = serde_json::json!({"schema":9,"security_signals":{"status":"collected","coverage":"full","truncated":false,"entries":[{"source":"crs","action":"would_block","rule_id":942100}]}}).to_string();
        for _ in 0..LIVE_CAPACITY + 10 {
            let mut request = hub.start("GET");
            request.details = details.clone();
            request.finish(200, 1, None, false, 1, 2);
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while hub.log_sequence.load(Relaxed) < (LIVE_CAPACITY + 10) as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aggregator stalled");
        assert!(matches!(
            logs.recv().await,
            Err(broadcast::error::RecvError::Lagged(10))
        ));
        let retained = logs.recv().await.expect("retained log after explicit gap");
        assert_eq!(retained.sequence, 11);
        assert_eq!(retained.log.details, details);
        assert_eq!(hub.totals().dropped_logs, 0);
        let mut metrics = hub.metrics.subscribe();
        tokio::time::timeout(Duration::from_secs(3), metrics.changed())
            .await
            .expect("tick stalled")
            .expect("owner gone");
        assert_eq!(
            metrics.borrow().totals.completed,
            (LIVE_CAPACITY + 10) as u64
        );
        assert_eq!(
            metrics.borrow().totals.received_bytes,
            (LIVE_CAPACITY + 10) as u64
        );
        assert!(
            hub.prometheus()
                .contains("openwaf_request_duration_seconds_bucket{le=\"+Inf\"} 266")
        );
        owner.abort();
        assert!(owner.await.expect_err("owner should cancel").is_cancelled());
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;
    #[tokio::test]
    async fn restart_restores_totals_dimensions_but_never_runtime_gauges_or_rates() {
        let (hub, _receiver) = Hub::new();
        let mut request = hub.start_with_agent("POST", Some(b"Firefox/140"));
        request.country(Country::Code("GB"));
        request.blocked();
        request.finish(403, 1, Some(0), false, 42, 13);
        let _connection = hub.connection();
        let _inflight = hub.start("GET");
        let checkpoint: Checkpoint =
            serde_json::from_slice(&serde_json::to_vec(&hub.checkpoint()).expect("encode"))
                .expect("decode");
        let (restored, receiver) = Hub::new();
        restored.restore(&checkpoint).expect("restore");
        assert_ne!(restored.epoch, hub.epoch);
        assert_eq!(restored.totals().incoming, 2);
        assert_eq!(restored.totals().completed, 1);
        assert_eq!(restored.totals().blocked, 1);
        assert_eq!(restored.totals().active_requests, 0);
        assert_eq!(restored.totals().active_connections, 0);
        assert_eq!(restored.totals().received_bytes, 42);
        assert_eq!(restored.metrics.borrow().incoming_rps, 0.0);
        assert_eq!(
            restored
                .metrics
                .borrow()
                .dimensions
                .countries
                .iter()
                .find(|v| v.label == "GB")
                .expect("GB")
                .blocked,
            1
        );
        let (stop, stopped) = watch::channel(false);
        let owner = tokio::spawn(restored.clone().run_until(receiver, stopped));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            restored.metrics.borrow().incoming_rps,
            0.0,
            "restored totals must not inflate first-window RPS"
        );
        restored.start("GET").finish(200, 1, None, false, 0, 0);
        assert_eq!(restored.totals().incoming, 3);
        assert_eq!(restored.totals().completed, 2);
        stop.send_replace(true);
        owner.await.expect("owner");
    }
    #[test]
    fn invalid_checkpoint_does_not_partially_restore() {
        let (hub, _receiver) = Hub::new();
        let mut checkpoint = hub.checkpoint();
        checkpoint.totals.incoming = 123;
        checkpoint.dimensions.methods[0].label = "unbounded-input".into();
        assert!(hub.restore(&checkpoint).is_err());
        assert_eq!(hub.totals().incoming, 0);
        assert_eq!(hub.dimensions.snapshot().methods[0].received, 0);
        checkpoint = hub.checkpoint();
        checkpoint.schema_version = 99;
        assert!(hub.restore(&checkpoint).is_err());
    }
}
