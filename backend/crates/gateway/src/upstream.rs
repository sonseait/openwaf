//! Owned, bounded DNS/active health scheduler. Never invoked from proxy requests.
use crate::probe::{Endpoint as ProbeEndpoint, ErrorCode, ProbeService, Protocol as ProbeProtocol};
use hickory_resolver::{TokioAsyncResolver, system_conf::read_system_conf};
use openwaf_config::{
    Context, Endpoint, Protocol, Snapshot, Store, requests::Requests, validate_address,
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinSet;

pub struct Service {
    resolver: TokioAsyncResolver,
    probe: Arc<ProbeService>,
    context: Context,
    requests: Arc<Requests>,
}

enum Outcome {
    Observed(ResultState),
    Deferred,
}
struct ResultState {
    addresses: Vec<SocketAddr>,
    expires: Instant,
    reason: &'static str,
    diagnostic: openwaf_config::health::Diagnostic,
}
type Key = (
    openwaf_config::Address,
    bool,
    bool,
    Option<String>,
    openwaf_config::health::Settings,
);
struct Target {
    snapshot: Weak<Snapshot>,
    upstream: usize,
    endpoint: usize,
}
impl Target {
    fn same(&self, other: &Self) -> bool {
        self.snapshot.ptr_eq(&other.snapshot)
            && self.upstream == other.upstream
            && self.endpoint == other.endpoint
    }
}
struct Check {
    endpoint: Endpoint,
    targets: Vec<Target>,
    due: Instant,
    busy: bool,
    failures: u8,
}
impl Check {
    fn complete(
        &mut self,
        outcome: Outcome,
        settings: &openwaf_config::health::Settings,
        now: Instant,
        checked_at: u64,
    ) {
        self.busy = false;
        let Outcome::Observed(state) = outcome else {
            // Local admission pressure is not evidence about the backend. Keep
            // the original expiry, passive failures and health streaks intact.
            self.due = now + Duration::from_millis(100);
            return;
        };
        self.failures = if state.addresses.is_empty() {
            self.failures.saturating_add(1).min(6)
        } else {
            0
        };
        self.due = if state.addresses.is_empty() {
            now + Duration::from_millis(recovery_delay(settings.interval_ms, self.failures))
        } else {
            state
                .expires
                .min(now + Duration::from_millis(settings.interval_ms))
                .max(now + Duration::from_millis(100))
        };
        for target in &self.targets {
            if let Some(snapshot) = target.snapshot.upgrade() {
                snapshot.health.observe(
                    target.upstream,
                    target.endpoint,
                    openwaf_config::health::Observation {
                        addresses: state.addresses.clone(),
                        expires: state.expires,
                        checked_at_ms: checked_at,
                        reason: state.reason,
                        diagnostic: Some(state.diagnostic.clone()),
                    },
                );
            }
        }
    }
}

/// At most 1,024 active endpoints + 256 request upstreams × 16 endpoints.
/// Source annotations do not affect DNS/TLS/probe identity. Each unique endpoint
/// is checked once and its result is published to the interested generations.
fn reconcile(schedule: &mut BTreeMap<Key, Check>, active: &Arc<Snapshot>, requests: &Requests) {
    let mut desired: BTreeMap<Key, (Endpoint, Vec<Target>)> = BTreeMap::new();
    let active_targets = (0..active.document.upstreams.len()).map(|u| (active.clone(), u));
    let retired_targets = requests
        .targets()
        .into_iter()
        .filter(|(s, _)| !Arc::ptr_eq(s, active));
    for (snapshot, u) in active_targets.chain(retired_targets) {
        for (e, endpoint) in snapshot.document.upstreams[u].endpoints.iter().enumerate() {
            let key = (
                endpoint.address.clone(),
                endpoint.protocol == Protocol::Https,
                endpoint.tls_verify,
                endpoint.tls_server_name.clone(),
                snapshot.document.upstreams[u].health.clone(),
            );
            let (_, targets) = desired
                .entry(key)
                .or_insert_with(|| (endpoint.clone(), Vec::new()));
            targets.push(Target {
                snapshot: Arc::downgrade(&snapshot),
                upstream: u,
                endpoint: e,
            });
        }
    }
    // Preserve busy entries until their bounded job returns, preventing duplicate
    // jobs if an endpoint disappears and is reintroduced during the same probe.
    schedule.retain(|key, entry| {
        if desired.contains_key(key) {
            return true;
        }
        entry.targets.clear();
        entry.busy
    });
    for (key, (endpoint, targets)) in desired {
        let entry = schedule.entry(key).or_insert_with(|| Check {
            endpoint,
            targets: Vec::new(),
            due: Instant::now(),
            busy: false,
            failures: 0,
        });
        if targets
            .iter()
            .any(|new| !entry.targets.iter().any(|old| old.same(new)))
        {
            entry.due = entry.due.min(Instant::now());
        }
        entry.targets = targets;
    }
}
fn recovery_delay(interval_ms: u64, failures: u8) -> u64 {
    interval_ms
        .saturating_mul(1u64 << failures.saturating_sub(1).min(5))
        .min(30000)
}
// Hash only topology, never observation timestamps; retain no raw inventory.
fn discovery_changed(
    previous: &mut Option<[u8; 32]>,
    inventory: &openwaf_admin::discovery::Inventory,
) -> bool {
    if !inventory.collector_available || inventory.stale {
        return false;
    }
    let Ok(bytes) = serde_json::to_vec(&inventory.items) else {
        return false;
    };
    let current = openssl::sha::sha256(&bytes);
    previous.replace(current).is_some_and(|old| old != current)
}

fn upstream_dns_options(opts: &mut hickory_resolver::config::ResolverOpts) {
    opts.cache_size = 128;
    opts.attempts = 1;
    opts.timeout = Duration::from_secs(2);
    // Container replacements may invalidate a long Docker DNS TTL. Keep short
    // authoritative TTLs, but bound both successful and negative cache entries.
    opts.positive_min_ttl = Some(Duration::ZERO);
    opts.positive_max_ttl = Some(Duration::from_secs(5));
    opts.negative_min_ttl = Some(Duration::ZERO);
    opts.negative_max_ttl = Some(Duration::from_secs(1));
}
impl Service {
    pub fn new(
        context: Context,
        ca: Option<&Path>,
        requests: Arc<Requests>,
    ) -> anyhow::Result<Self> {
        let (config, mut opts) = read_system_conf()?;
        upstream_dns_options(&mut opts);
        // Hosts inventory is loaded at startup; health eligibility is still bounded.
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Self::with_resolver(context, resolver, ca, requests)
    }
    pub fn with_resolver(
        context: Context,
        resolver: TokioAsyncResolver,
        ca: Option<&Path>,
        requests: Arc<Requests>,
    ) -> anyhow::Result<Self> {
        // Context performs precise wildcard/local-IP loop validation before every probe.
        let probe =
            ProbeService::with_capacity(resolver.clone(), vec![], ca, requests.health_jobs)?;
        Ok(Self {
            context,
            resolver,
            probe: Arc::new(probe),
            requests,
        })
    }
    async fn check(
        &self,
        endpoint: Endpoint,
        settings: openwaf_config::health::Settings,
    ) -> Outcome {
        let start = Instant::now();
        let mut diagnostic = openwaf_config::health::Diagnostic::default();
        let result = tokio::time::timeout(
            Duration::from_millis(settings.timeout_ms),
            self.resolve_check(endpoint, &settings, &mut diagnostic),
        )
        .await;
        diagnostic.latency_ms = start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        diagnostic.complete = result.is_ok();
        if matches!(result, Ok(Err("probe_busy"))) {
            return Outcome::Deferred;
        }
        Outcome::Observed(match result {
            Ok(Ok((addresses, expires))) => ResultState {
                reason: if addresses.is_empty() {
                    "health_failed"
                } else {
                    "healthy"
                },
                addresses,
                expires,
                diagnostic,
            },
            Ok(Err(reason)) => ResultState {
                addresses: vec![],
                expires: Instant::now(),
                reason,
                diagnostic,
            },
            Err(_) => ResultState {
                addresses: vec![],
                expires: Instant::now(),
                reason: "deadline_exceeded",
                diagnostic,
            },
        })
    }
    async fn resolve_check(
        &self,
        endpoint: Endpoint,
        settings: &openwaf_config::health::Settings,
        diagnostic: &mut openwaf_config::health::Diagnostic,
    ) -> Result<(Vec<SocketAddr>, Instant), &'static str> {
        let mut expires =
            Instant::now() + Duration::from_millis(settings.interval_ms + settings.timeout_ms);
        let addresses = if let Some(address) = endpoint.address.socket() {
            vec![address]
        } else {
            let response = self
                .resolver
                .lookup_ip(endpoint.address.host())
                .await
                .map_err(|_| "dns_failed")?;
            expires = expires.min(response.valid_until());
            let mut addresses = Vec::new();
            for ip in response.iter() {
                let address =
                    SocketAddr::new(openwaf_config::normalized_ip(ip), endpoint.address.port());
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
                if addresses.len() > 16 {
                    return Err("too_many_addresses");
                }
            }
            addresses
        };
        if addresses.is_empty() {
            return Err("dns_empty");
        }
        diagnostic.resolved_addresses = addresses.len();
        // Reject the entire answer, even when a different address could be reached.
        if addresses
            .iter()
            .any(|address| validate_address(*address, &self.context).is_err())
        {
            return Err("forbidden_address");
        }
        let mut healthy = Vec::new();
        for address in addresses {
            let report = self
                .probe
                .health_at(
                    ProbeEndpoint {
                        host: endpoint.address.host(),
                        port: endpoint.address.port(),
                        protocol: if endpoint.protocol == Protocol::Https {
                            ProbeProtocol::Https
                        } else {
                            ProbeProtocol::Http
                        },
                        tls_server_name: endpoint.tls_server_name.clone(),
                        tls_verify: endpoint.tls_verify,
                    },
                    address,
                    settings,
                )
                .await;
            if report.error == Some(ErrorCode::Busy) {
                // Preserve prior health unless there is evidence of a real
                // failure. A later Busy must never hide that failure; in that
                // case only the already verified subset can be published.
                if diagnostic.addresses.iter().all(|check| check.accepted) {
                    return Err("probe_busy");
                }
                break;
            }
            let accepted = report.available
                && report
                    .http_status
                    .is_some_and(|s| (settings.status_min..=settings.status_max).contains(&s));
            if accepted {
                healthy.push(address);
            }
            diagnostic
                .addresses
                .push(openwaf_config::health::AddressCheck {
                    address,
                    accepted,
                    tcp: report.tcp.state.as_str(),
                    tls: report.tls.state.as_str(),
                    http: report.http.state.as_str(),
                    http_status: report.http_status,
                    error: report.error.map(|error| error.as_str()).or_else(|| {
                        (!accepted && report.http_status.is_some())
                            .then_some("unexpected_http_status")
                    }),
                    latency_ms: report.latency_ms,
                });
        }
        Ok((healthy, expires))
    }
    /// Collector changes are hints only. The scoped monitor is cancelled with
    /// the scheduler; collector failure leaves ordinary TTL refresh working.
    pub async fn run_with_discovery(
        self: Arc<Self>,
        store: Arc<Store>,
        discovery: Option<Arc<dyn openwaf_admin::discovery::Backend>>,
    ) -> anyhow::Result<()> {
        let Some(discovery) = discovery else {
            return self.run(store).await;
        };
        let (changed, updates) = tokio::sync::watch::channel(());
        let monitor = async move {
            let mut previous = None;
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if let Ok(Ok(inventory)) = tokio::time::timeout(
                    Duration::from_secs(2),
                    discovery.inventory(openwaf_admin::discovery::Kind::Docker),
                )
                .await
                    && discovery_changed(&mut previous, &inventory)
                {
                    changed.send_replace(());
                }
            }
        };
        tokio::select! {
            result = self.run_inner(store, Some(updates)) => result,
            _ = monitor => Err(anyhow::anyhow!("discovery DNS monitor stopped")),
        }
    }
    /// Drop cancels at most health_jobs (1..=16) in-flight jobs. No detached workers.
    pub async fn run(self: Arc<Self>, store: Arc<Store>) -> anyhow::Result<()> {
        self.run_inner(store, None).await
    }
    async fn run_inner(
        self: Arc<Self>,
        store: Arc<Store>,
        mut updates: Option<tokio::sync::watch::Receiver<()>>,
    ) -> anyhow::Result<()> {
        let requests = &self.requests;
        let mut schedule: BTreeMap<Key, Check> = BTreeMap::new();
        let mut jobs = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut generation = 0_u64;
        loop {
            tokio::select! {
                _ = async {
                    match &mut updates {
                        Some(receiver) => {
                            if receiver.changed().await.is_err() {
                                std::future::pending::<()>().await;
                            }
                        },
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    self.resolver.clear_cache();
                    generation = generation.wrapping_add(1);
                    for entry in schedule.values_mut() {
                        if entry.endpoint.address.socket().is_none() {
                            entry.due = Instant::now();
                            entry.failures = 0;
                        }
                    }
                }
                _ = tick.tick() => {
                    let snapshot = store.load();
                    reconcile(&mut schedule, &snapshot, requests);
                    // Earliest due first: a rapidly expiring DNS name cannot starve others.
                    let mut due: Vec<_> = schedule.iter()
                        .filter(|(_, entry)| !entry.busy && !entry.targets.is_empty() && entry.due <= Instant::now())
                        .map(|(key, entry)| (entry.due, key.clone())).collect();
                    due.sort();
                    use std::sync::atomic::Ordering::Relaxed;
                    requests.health_active.store(jobs.len(),Relaxed);
                    requests.health_backlog.store(due.len(),Relaxed);
                    requests.health_peak_backlog.fetch_max(due.len(),Relaxed);
                    if let Some((oldest,_))=due.first() { requests.health_delay_ms.fetch_max(Instant::now().saturating_duration_since(*oldest).as_millis().min(u64::MAX as u128) as u64,Relaxed); }

                    for (_, key) in due {
                        if jobs.len() >= requests.health_jobs { break; }
                        let entry = schedule.get_mut(&key).ok_or_else(|| anyhow::anyhow!("health schedule entry disappeared"))?;
                        entry.busy = true;
                        let service = self.clone();
                        let endpoint = entry.endpoint.clone();
                        let settings = key.4.clone();
                        jobs.spawn(async move { (key,generation,service.check(endpoint, settings).await) });
                    }
                }
                result = jobs.join_next(), if !jobs.is_empty() => {
                    let (key,started_generation,state) = result.ok_or_else(|| anyhow::anyhow!("health worker disappeared"))??;
                    let now = Instant::now();
                    let entry = schedule.get_mut(&key).ok_or_else(|| anyhow::anyhow!("health result without schedule entry"))?;
                    if started_generation != generation && entry.endpoint.address.socket().is_none() {
                        entry.busy = false;
                        entry.due = now;
                        // A lookup already in flight may repopulate the shared cache.
                        self.resolver.clear_cache();
                        continue;
                    }
                    if matches!(state, Outcome::Deferred) {
                        requests.health_deferred.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let checked_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?;
                    entry.complete(state, &key.4, now, checked_at);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn dns_refreshes_changed_address_despite_long_server_ttl() {
        use hickory_resolver::{
            config::{NameServerConfig, Protocol as DnsProtocol, ResolverConfig, ResolverOpts},
            proto::{
                op::{Message, MessageType},
                rr::{RData, Record, RecordType, rdata::A},
            },
        };
        use std::sync::atomic::{AtomicBool, Ordering};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = ResolverConfig::new();
        config.add_name_server(NameServerConfig::new(
            socket.local_addr().unwrap(),
            DnsProtocol::Udp,
        ));
        let changed = Arc::new(AtomicBool::new(false));
        let state = changed.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[..n]).unwrap();
                let mut response = Message::new();
                response
                    .set_id(request.id())
                    .set_message_type(MessageType::Response)
                    .set_recursion_desired(true)
                    .set_recursion_available(true);
                for query in request.queries() {
                    response.add_query(query.clone());
                    if query.query_type() == RecordType::A {
                        let last = if state.load(Ordering::Relaxed) { 2 } else { 1 };
                        response.add_answer(Record::from_rdata(
                            query.name().clone(),
                            600,
                            RData::A(A::new(127, 0, 0, last)),
                        ));
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let mut opts = ResolverOpts::default();
        upstream_dns_options(&mut opts);
        let resolver = TokioAsyncResolver::tokio(config, opts);
        assert_eq!(
            resolver
                .lookup_ip("app.test.")
                .await
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .to_string(),
            "127.0.0.1"
        );
        changed.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert_eq!(
            resolver
                .lookup_ip("app.test.")
                .await
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .to_string(),
            "127.0.0.2"
        );
        // Exercise the scheduler's discovery invalidation before the new cache
        // entry expires, and verify the peer consumed by real proxy selection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tasks.spawn(async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut buffer = [0; 4096];
                assert!(connection.read(&mut buffer).await.unwrap() > 0);
                connection
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let service = Arc::new(
            Service::with_resolver(
                Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
                resolver,
                None,
                Arc::new(Requests::new(1)),
            )
            .unwrap(),
        );
        let active = snapshot(1, &[&format!("app.test.:{port}")]);
        let store = Arc::new(Store::new(Arc::try_unwrap(active).ok().unwrap()));
        let active = store.load();
        let (sender, receiver) = tokio::sync::watch::channel(());
        changed.store(false, Ordering::Relaxed);
        sender.send_replace(());
        tasks.spawn(service.run_inner(store, Some(receiver)));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some((_, _, peer)) =
                    active.endpoint_with_load(0, |_, _| true, |_, _| (0, 1000))
                {
                    assert_eq!(peer.address, SocketAddr::from(([127, 0, 0, 1], port)));
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect(
            "discovery hint refreshes cached DNS and publishes a routable peer before TTL expiry",
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    fn service(capacity: usize) -> Arc<Service> {
        Arc::new(
            Service::with_resolver(
                Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
                TokioAsyncResolver::tokio(Default::default(), Default::default()),
                None,
                Arc::new(Requests::new(capacity)),
            )
            .expect("health service"),
        )
    }

    #[test]
    fn discovery_change_ignores_stale_inventory_and_observation_time() {
        let mut inventory = openwaf_admin::discovery::Inventory {
            schema_version: 1,
            source: openwaf_admin::discovery::Kind::Docker,
            collection_scope: "collector_network_namespace",
            collector_available: true,
            docker_events_connected: Some(true),
            stale: false,
            error: None,
            observed_at_unix_ms: Some(1),
            items: serde_json::json!([{"id":"old"}]),
            candidates: vec![],
            candidates_truncated: false,
        };
        let mut previous = None;
        assert!(!discovery_changed(&mut previous, &inventory));
        inventory.observed_at_unix_ms = Some(2);
        assert!(!discovery_changed(&mut previous, &inventory));
        inventory.items[0]["id"] = serde_json::json!("new");
        inventory.stale = true;
        assert!(!discovery_changed(&mut previous, &inventory));
        inventory.stale = false;
        assert!(discovery_changed(&mut previous, &inventory));
        assert!(!discovery_changed(&mut previous, &inventory));
    }

    #[tokio::test]
    async fn scheduler_uses_full_budget_without_false_health_failures() {
        for (capacity, count) in [(8, 27), (16, 16)] {
            let service = service(capacity);
            let mut servers = JoinSet::new();
            let mut upstreams = Vec::new();
            let (accepted, mut connections) = tokio::sync::mpsc::channel(count);
            let (release, gate) = tokio::sync::watch::channel(false);
            for index in 0..count {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind");
                let address = listener.local_addr().expect("address");
                upstreams.push(serde_json::json!({"id":format!("app-{index}"),
                    "endpoints":[{"address":address.to_string(),"protocol":"http"}]}));
                let accepted = accepted.clone();
                let mut gate = gate.clone();
                servers.spawn(async move {
                    let (mut socket, _) = listener.accept().await.expect("accept");
                    let mut request = [0; 4096];
                    let n = socket.read(&mut request).await.expect("HTTP request");
                    assert!(n > 0);
                    accepted.send(()).await.expect("accepted");
                    gate.wait_for(|released| *released).await.expect("release");
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("response");
                });
            }
            let document = serde_json::from_value(serde_json::json!({"upstreams":upstreams,
                "routes":[{"id":"app","hostname":"app.test","path":"/","path_match":"prefix","upstream":"app-0"}]
            })).expect("document");
            let store = Arc::new(Store::new(
                Snapshot::prepare(1, document, &service.context).expect("snapshot"),
            ));
            let active = store.load();
            let mut scheduler = JoinSet::new();
            scheduler.spawn(service.clone().run(store));
            tokio::time::timeout(Duration::from_secs(2), async {
                for _ in 0..capacity {
                    connections
                        .recv()
                        .await
                        .expect("health job must reach HTTP");
                }
            })
            .await
            .expect("all configured probe slots must be usable concurrently");
            if count > capacity {
                assert!(
                    tokio::time::timeout(Duration::from_millis(75), connections.recv())
                        .await
                        .is_err(),
                    "scheduler must not exceed its job budget"
                );
            }
            assert!(
                active
                    .health
                    .status()
                    .iter()
                    .all(|s| s.consecutive_failures == 0)
            );
            release.send_replace(true);
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if active.health.status().iter().all(|s| s.available) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("every healthy endpoint must become selectable");
            assert_eq!(service.requests.stats()["deferred_total"], 0);
            assert!(
                active
                    .health
                    .status()
                    .iter()
                    .all(|s| s.consecutive_failures == 0)
            );
            scheduler.abort_all();
            while let Some(result) = scheduler.join_next().await {
                assert!(result.expect_err("scheduler cancelled").is_cancelled());
            }
            while let Some(result) = servers.join_next().await {
                result.expect("server task");
            }
        }
    }

    #[tokio::test]
    async fn scheduler_reports_deferral_and_recovers_after_local_admission_returns() {
        let service = service(1);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let active = snapshot(1, &[&address.to_string()]);
        let store = Arc::new(Store::new(
            Arc::try_unwrap(active).ok().expect("unique snapshot"),
        ));
        let active = store.load();
        active.health.publish(
            0,
            0,
            vec![address],
            Instant::now() + Duration::from_secs(3),
            1,
            "healthy",
        );
        let mut tasks = JoinSet::new();
        let probe = service.probe.clone();
        tasks.spawn(async move {
            let report = probe
                .test(ProbeEndpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                    protocol: ProbeProtocol::Http,
                    tls_server_name: None,
                    tls_verify: true,
                })
                .await;
            assert!(report.available);
        });
        let (mut blocker, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("blocker connects")
            .expect("accept");
        let mut scheduler = JoinSet::new();
        scheduler.spawn(service.clone().run(store));
        tokio::time::timeout(Duration::from_secs(1), async {
            while service.requests.stats()["deferred_total"]
                .as_u64()
                .expect("counter")
                < 2
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("scheduler counts deferred jobs and retries");
        let status = active.health.status().remove(0);
        assert!(status.available);
        assert_eq!(status.checked_at_ms, Some(1));
        assert_eq!(status.consecutive_failures, 0);
        blocker
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("release probe");
        tasks
            .join_next()
            .await
            .expect("blocker task")
            .expect("blocker complete");
        tasks.spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("retry connects");
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.expect("HTTP request") > 0);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("health response");
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.health.status()[0].checked_at_ms == Some(1) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("deferral retries recover after admission returns");
        let status = active.health.status().remove(0);
        assert!(status.available);
        assert_eq!(status.consecutive_successes, 2);
        assert_eq!(status.consecutive_failures, 0);
        tasks
            .join_next()
            .await
            .expect("server task")
            .expect("server complete");
        scheduler.abort_all();
        while let Some(result) = scheduler.join_next().await {
            assert!(result.expect_err("scheduler cancelled").is_cancelled());
        }
    }

    #[tokio::test]
    async fn busy_defers_without_changing_observation_expiry_or_passive_failure() {
        let service = service(1);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let active = snapshot(1, &[&address.to_string()]);
        let settings = active.document.upstreams[0].health.clone();
        let endpoint = active.document.upstreams[0].endpoints[0].clone();
        let mut held = JoinSet::new();
        let probe = service.probe.clone();
        held.spawn(async move {
            probe
                .test(ProbeEndpoint {
                    host: address.ip().to_string(),
                    port: address.port(),
                    protocol: ProbeProtocol::Http,
                    tls_server_name: None,
                    tls_verify: true,
                })
                .await
        });
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("probe connects")
            .expect("accept");
        let expires = Instant::now() + Duration::from_millis(300);
        active
            .health
            .publish(0, 0, vec![address], expires, 42, "healthy");
        let mut schedule = BTreeMap::new();
        reconcile(&mut schedule, &active, &service.requests);
        let entry = schedule.values_mut().next().expect("entry");
        entry.failures = 2;
        for passive_failure in [false, true] {
            if passive_failure {
                active.health.select(0, 0, 0).expect("peer").fail();
            }
            let outcome = service.check(endpoint.clone(), settings.clone()).await;
            assert!(matches!(outcome, Outcome::Deferred));
            entry.busy = true;
            let now = Instant::now();
            entry.complete(outcome, &settings, now, 99);
            assert!(!entry.busy);
            assert_eq!(entry.due, now + Duration::from_millis(100));
            assert_eq!(entry.failures, 2, "deferral must not alter failure backoff");
            let status = active.health.status().remove(0);
            assert_eq!(status.checked_at_ms, Some(42));
            assert_eq!(status.consecutive_successes, 1);
            assert_eq!(status.consecutive_failures, 0);
            assert_eq!(active.health.select(0, 0, 0).is_none(), passive_failure);
        }
        // An unexpired observation survives, but deferral cannot renew it.
        active
            .health
            .publish(0, 0, vec![address], expires, 42, "healthy");
        assert!(active.health.select(0, 0, 0).is_some());
        tokio::time::sleep(
            expires.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
        )
        .await;
        entry.complete(Outcome::Deferred, &settings, Instant::now(), 100);
        assert_eq!(active.health.status()[0].valid_for_ms, 0);
        assert!(active.health.select(0, 0, 0).is_none());
        held.abort_all();
        while let Some(result) = held.join_next().await {
            assert!(result.is_err_and(|error| error.is_cancelled()));
        }
        // Drain the already sent request, then see EOF after cancellation.
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), socket.read_to_end(&mut bytes))
            .await
            .expect("socket closes")
            .expect("read EOF");
        drop(socket);
        drop(listener);
        // Freed admission now permits a real probe; refusal must quarantine the peer.
        active.health.publish(
            0,
            0,
            vec![address],
            Instant::now() + Duration::from_secs(1),
            101,
            "healthy",
        );
        let outcome = service.check(endpoint, settings.clone()).await;
        assert!(
            matches!(&outcome, Outcome::Observed(s) if s.addresses.is_empty() && s.diagnostic.addresses[0].error == Some("tcp_refused"))
        );
        entry.complete(outcome, &settings, Instant::now(), 102);
        assert!(active.health.select(0, 0, 0).is_none());
        assert_eq!(active.health.status()[0].consecutive_failures, 1);
    }

    #[tokio::test]
    async fn health_capacity_rejects_unbounded_or_zero_budgets() {
        for capacity in [0, 17, usize::MAX] {
            assert!(
                Service::with_resolver(
                    Context {
                        listeners: vec![],
                        local_ips: vec![]
                    },
                    TokioAsyncResolver::tokio(Default::default(), Default::default()),
                    None,
                    Arc::new(Requests::new(capacity))
                )
                .is_err()
            );
        }
    }

    #[test]
    fn failure_backoff_is_finite_and_success_resets_schedule() {
        assert_eq!(recovery_delay(250, 1), 250);
        assert_eq!(recovery_delay(250, 2), 500);
        assert_eq!(recovery_delay(30000, 255), 30000);
        assert_eq!(recovery_delay(250, 0), 250);
    }
    fn snapshot(version: i64, addresses: &[&str]) -> Arc<Snapshot> {
        let endpoints: Vec<_> = addresses
            .iter()
            .map(|a| serde_json::json!({"address":a,"protocol":"http"}))
            .collect();
        let document = serde_json::from_value(serde_json::json!({
            "upstreams":[{"id":"app","endpoints":endpoints}],
            "routes":[{"id":"app","hostname":"app.test","path":"/","path_match":"prefix","upstream":"app"}]
        })).expect("document");
        Arc::new(
            Snapshot::prepare(
                version,
                document,
                &Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
            )
            .expect("snapshot"),
        )
    }

    #[test]
    fn retired_snapshots_refresh_only_requested_upstreams_and_share_probes() {
        let mut document = snapshot(1, &["127.0.0.1:9001", "127.0.0.1:9002"])
            .document
            .clone();
        let mut unused = document.upstreams[0].clone();
        unused.id = "unused".into();
        unused.endpoints.truncate(1);
        unused.endpoints[0].address = "127.0.0.1:9099".parse().expect("unused address");
        document.upstreams.push(unused);
        let old = Arc::new(
            Snapshot::prepare(
                1,
                document,
                &Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
            )
            .expect("old snapshot"),
        );
        let same = snapshot(2, &["127.0.0.1:9001", "127.0.0.1:9002"]);
        let active = snapshot(3, &["127.0.0.1:9003"]);
        let requests = Arc::new(Requests::default());
        let lease = requests.track(&old, 0).expect("register");
        let duplicate = requests.track(&old, 0).expect("duplicate request");
        let other = requests.track(&same, 0).expect("another generation");
        let mut schedule = BTreeMap::new();
        reconcile(&mut schedule, &active, &requests);
        assert_eq!(schedule.len(), 3, "endpoint probes must be deduplicated");
        assert_eq!(schedule.values().map(|e| e.targets.len()).sum::<usize>(), 5);
        assert_eq!(
            Arc::strong_count(&old),
            1,
            "scheduler cannot retain snapshot"
        );
        let weak = Arc::downgrade(&old);
        drop(old);
        drop(lease);
        drop(duplicate);
        assert!(weak.upgrade().is_none());
        reconcile(&mut schedule, &active, &requests);
        assert_eq!(schedule.values().map(|e| e.targets.len()).sum::<usize>(), 3);
        drop(other);
        reconcile(&mut schedule, &active, &requests);
        assert_eq!(schedule.len(), 1, "retired checks must be removed");
    }

    #[test]
    fn disappearing_busy_check_is_retained_without_targets_until_result() {
        let old = snapshot(1, &["127.0.0.1:9001"]);
        let active = snapshot(2, &["127.0.0.1:9002"]);
        let requests = Arc::new(Requests::default());
        let lease = requests.track(&old, 0).expect("register");
        let mut schedule = BTreeMap::new();
        reconcile(&mut schedule, &old, &requests);
        let key = schedule.keys().next().expect("key").clone();
        schedule.get_mut(&key).expect("entry").busy = true;
        drop(lease);
        reconcile(&mut schedule, &active, &requests);
        assert!(schedule[&key].busy && schedule[&key].targets.is_empty());
        let lease = requests.track(&old, 0).expect("re-register");
        reconcile(&mut schedule, &active, &requests);
        assert!(schedule[&key].busy, "cannot launch duplicate work");
        assert_eq!(schedule[&key].targets.len(), 1);
        drop(lease);
        schedule.get_mut(&key).expect("entry").busy = false;
        reconcile(&mut schedule, &active, &requests);
        assert!(!schedule.contains_key(&key));
    }
}
