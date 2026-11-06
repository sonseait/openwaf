//! Local observation only: no access decision, payload, remote I/O or task.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recent_events_are_bounded_ordered_and_query_private() {
        let s = Service::default();
        let p = Policy::default();
        for i in (0..40).rev() {
            record(&s, &p, 1000 + i, "/private?token=secret", 200, true);
        }
        let state = s.state.lock().unwrap();
        let e = &state
            .windows
            .values()
            .find(|w| w.event.detector == "endpoint_probing")
            .unwrap()
            .event;
        assert_eq!(e.recent_events.len(), 32);
        assert!(
            e.recent_events
                .windows(2)
                .all(|v| v[0].started_ms <= v[1].started_ms)
        );
        assert!(e.sequence_truncated);
        assert!(!serde_json::to_string(e).unwrap().contains("secret"));
    }
    fn record(s: &Service, p: &Policy, time: u64, path: &str, status: u16, upstream: bool) {
        s.observe(
            Observation {
                route: "r",
                version: 1,
                client: "192.0.2.1",
                path,
                status,
                upstream,
                layer: "allow",
                request_id: "01234567890123456789012345678901",
                started_ms: time,
                completed_ms: time,
            },
            p,
        );
    }
    #[test]
    fn gateway_404_is_not_endpoint_probing_and_gap_prevents_recovery() {
        let s = Service::default();
        let p = Policy {
            window_seconds: 10,
            min_samples: 2,
            requests_per_second: 1,
            distinct_paths: 2,
            upstream_404_percent: 50,
        };
        for i in 0..12 {
            record(&s, &p, 1000, &format!("/{i}"), 404, false);
        }
        assert!(s.pending().iter().all(|e| e.detector != "endpoint_probing"));
        for i in 0..12 {
            record(&s, &p, 11000, &format!("/{i}"), 404, true);
        }
        assert!(
            s.pending()
                .iter()
                .any(|e| e.detector == "endpoint_probing" && !e.recovered)
        );
        s.dropped.fetch_add(1, Ordering::Relaxed);
        for _ in 0..12 {
            record(&s, &p, 21000, "/ok", 200, true);
        }
        assert!(s.pending().iter().all(|e| !e.recovered));
        assert!(s.diagnostics(21000).to_string().contains("gap"));
    }
    #[test]
    fn clean_window_recovers_and_events_are_idempotently_acknowledged() {
        let s = Service::default();
        let p = Policy {
            window_seconds: 10,
            min_samples: 2,
            requests_per_second: 1,
            distinct_paths: 2,
            upstream_404_percent: 50,
        };
        for i in 0..12 {
            record(&s, &p, 1000, &format!("/{i}"), 404, true);
        }
        let pending = s.pending();
        assert!(!pending.is_empty());
        for e in pending {
            s.ack(&e.key, e.revision);
        }
        for _ in 0..3 {
            record(&s, &p, 11000, "/ok", 200, true);
        }
        record(&s, &p, 21000, "/ok", 200, true);
        assert!(s.pending().iter().any(|e| e.recovered));
        assert!(s.diagnostics(100000).to_string().contains("stale"));
    }
    #[test]
    fn churn_ttl_contention_and_evidence_are_hard_bounded() {
        let service = Service::default();
        let policy = Policy::default();
        for i in 0..200 {
            let client = format!("192.0.2.{i}");
            service.observe(
                Observation {
                    route: "r",
                    version: 1,
                    client: &client,
                    path: "/sensitive-path?token=never-retain",
                    status: 404,
                    upstream: true,
                    layer: "allow",
                    request_id: "aabbccddeeff00112233445566778899",
                    started_ms: 1000,
                    completed_ms: 1000,
                },
                &policy,
            );
        }
        assert_eq!(service.state.lock().unwrap().windows.len(), 128);
        assert!(service.dropped.load(Ordering::Relaxed) > 0);
        let guard = service.state.lock().unwrap();
        let dropped = service.dropped.load(Ordering::Relaxed);
        record(&service, &policy, 1000, "/", 200, true);
        assert_eq!(service.dropped.load(Ordering::Relaxed), dropped + 1);
        drop(guard);
        record(&service, &policy, 200000, "/", 200, true);
        assert!(service.state.lock().unwrap().windows.len() <= 2);
        let diagnostic = service.diagnostics(200000).to_string();
        assert!(!diagnostic.contains("sensitive-path"));
        assert!(!diagnostic.contains("192.0.2."));
    }
}
use openwaf_config::abuse::Policy;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet, hash_map::RandomState},
    hash::{BuildHasher, Hash},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
const MAX_KEYS: usize = 1024;
const MAX_EVENTS: usize = 256;
#[derive(Clone, Serialize)]
pub struct RecentEvent {
    pub started_ms: u64,
    pub completed_ms: u64,
    pub path_hash: String,
    pub status: u16,
    pub upstream: bool,
}
#[derive(Clone, Serialize)]
pub struct Event {
    pub recent_events: Vec<RecentEvent>,
    pub sequence_truncated: bool,
    pub correlation_source: &'static str,
    pub key: String,
    pub revision: u64,
    pub detector: &'static str,
    pub scope: String,
    pub route: String,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub first_ms: u64,
    pub last_ms: u64,
    pub config_version: i64,
    pub samples: u64,
    pub earliest_request_started_ms: u64,
    pub max_duration_ms: u64,
    pub upstream_404: u64,
    pub gateway_404: u64,
    pub denials: u64,
    pub errors: u64,
    pub capacity_errors: u64,
    pub denial_error_sources: BTreeMap<&'static str, u64>,
    pub distinct_paths: usize,
    pub paths_saturated: bool,
    pub gap_epoch: u64,
    pub quality: &'static str,
    pub recovered: bool,
    pub request_ids: Vec<String>,
}
struct Window {
    event: Event,
    paths: HashSet<u64>,
    window_ms: u64,
    last_seen: u64,
    firing: bool,
    previous_firing: bool,
    gap_epoch: u64,
}
#[derive(Default)]
struct State {
    windows: HashMap<String, Window>,
    pending: HashMap<String, Event>,
}
pub struct Service {
    state: Mutex<State>,
    hash: RandomState,
    pub dropped: AtomicU64,
    persisted: AtomicU64,
    persistence_errors: AtomicU64,
}
impl Default for Service {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            hash: RandomState::new(),
            dropped: AtomicU64::new(0),
            persisted: AtomicU64::new(0),
            persistence_errors: AtomicU64::new(0),
        }
    }
}
pub struct Observation<'a> {
    pub route: &'a str,
    pub version: i64,
    pub client: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub upstream: bool,
    pub layer: &'a str,
    pub request_id: &'a str,
    pub started_ms: u64,
    pub completed_ms: u64,
}
impl Service {
    fn hash(&self, value: impl Hash) -> u64 {
        self.hash.hash_one(value)
    }
    fn publish(&self, state: &mut State, event: Event) {
        if state.pending.contains_key(&event.key) || state.pending.len() < MAX_EVENTS {
            state.pending.insert(event.key.clone(), event);
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn observe(&self, o: Observation<'_>, p: &Policy) {
        if o.route.len() > 64 || o.path.len() > 8192 || o.client.len() > 80 || p.validate().is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(mut state) = self.state.try_lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let now = o.completed_ms;
        let window_ms = p.window_seconds * 1000;
        let start = now / window_ms * window_ms;
        state
            .windows
            .retain(|_, w| now.saturating_sub(w.last_seen) <= w.window_ms * 2);
        let path = self.hash(o.path.split('?').next().unwrap_or("/"));
        let config_key = self.hash((
            o.version,
            p.window_seconds,
            p.min_samples,
            p.requests_per_second,
            p.distinct_paths,
            p.upstream_404_percent,
        ));
        for detector in ["endpoint_probing", "route_flood"] {
            let scope = if detector == "endpoint_probing" {
                format!("{}:{:016x}", o.route, self.hash(o.client))
            } else {
                o.route.to_owned()
            };
            let key = format!("{detector}:{scope}:{config_key:016x}");
            let mut w = if let Some(w) = state.windows.remove(&key) {
                w
            } else {
                if state.windows.len() >= MAX_KEYS
                    || state
                        .windows
                        .values()
                        .filter(|w| w.event.route == o.route)
                        .count()
                        >= 128
                {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Window {
                    event: Event {
                        recent_events: Vec::new(),
                        sequence_truncated: false,
                        correlation_source: if detector == "route_flood" {
                            "route_aggregate"
                        } else if o.client.starts_with("verified:") {
                            "verified_identity"
                        } else if o.client.starts_with("session:") {
                            "gateway_cookie"
                        } else {
                            "ip_fallback"
                        },
                        key: String::new(),
                        revision: 0,
                        detector,
                        scope: scope.clone(),
                        route: o.route.into(),
                        window_start_ms: start,
                        window_end_ms: start + window_ms,
                        first_ms: now,
                        last_ms: now,
                        config_version: o.version,
                        samples: 0,
                        earliest_request_started_ms: o.started_ms,
                        max_duration_ms: 0,
                        upstream_404: 0,
                        gateway_404: 0,
                        denials: 0,
                        errors: 0,
                        capacity_errors: 0,
                        denial_error_sources: BTreeMap::new(),
                        distinct_paths: 0,
                        paths_saturated: false,
                        gap_epoch: self.dropped.load(Ordering::Relaxed),
                        quality: "warmup",
                        recovered: false,
                        request_ids: vec![],
                    },
                    paths: HashSet::new(),
                    window_ms,
                    last_seen: now,
                    firing: false,
                    previous_firing: false,
                    gap_epoch: self.dropped.load(Ordering::Relaxed),
                }
            };
            if start != w.event.window_start_ms {
                // Recovery needs a full observed clean window, enough samples,
                // consecutive windows and no loss anywhere since that window.
                if w.previous_firing
                    && !w.firing
                    && w.event.samples >= u64::from(p.min_samples)
                    && start == w.event.window_end_ms
                    && w.gap_epoch == self.dropped.load(Ordering::Relaxed)
                {
                    let mut recovered = w.event.clone();
                    recovered.recovered = true;
                    recovered.quality = "complete";
                    recovered.revision += 1;
                    self.publish(&mut state, recovered);
                    w.previous_firing = false;
                }
                let previous = w.firing || w.previous_firing;
                w.event.key = format!("{key}:{start}");
                w.event.window_start_ms = start;
                w.event.window_end_ms = start + window_ms;
                w.event.first_ms = now;
                w.event.last_ms = now;
                w.event.samples = 0;
                w.event.upstream_404 = 0;
                w.event.gateway_404 = 0;
                w.event.denials = 0;
                w.event.errors = 0;
                w.event.capacity_errors = 0;
                w.event.denial_error_sources.clear();
                w.event.distinct_paths = 0;
                w.event.paths_saturated = false;
                w.event.request_ids.clear();
                w.event.recent_events.clear();
                w.event.sequence_truncated = false;
                w.event.revision = 0;
                w.paths.clear();
                w.firing = false;
                w.previous_firing = previous;
                w.gap_epoch = self.dropped.load(Ordering::Relaxed);
                w.event.gap_epoch = w.gap_epoch;
                w.event.earliest_request_started_ms = o.started_ms;
                w.event.max_duration_ms = 0;
            }
            if w.event.key.is_empty() {
                w.event.key = format!("{key}:{start}");
            }
            w.event.samples = w.event.samples.saturating_add(1);
            w.event.recent_events.push(RecentEvent {
                started_ms: o.started_ms,
                completed_ms: now,
                path_hash: format!("{path:016x}"),
                status: o.status,
                upstream: o.upstream,
            });
            w.event
                .recent_events
                .sort_by_key(|e| (e.started_ms, e.completed_ms));
            if w.event.recent_events.len() > 32 {
                w.event.recent_events.remove(0);
                w.event.sequence_truncated = true;
            }
            w.event.last_ms = now;
            w.last_seen = now;
            w.event.earliest_request_started_ms =
                w.event.earliest_request_started_ms.min(o.started_ms);
            w.event.max_duration_ms = w
                .event
                .max_duration_ms
                .max(now.saturating_sub(o.started_ms));
            if o.status == 404 {
                if o.upstream {
                    w.event.upstream_404 += 1;
                } else {
                    w.event.gateway_404 += 1;
                }
            }
            if o.status == 429 || o.status == 403 {
                w.event.denials += 1;
            }
            if o.status >= 500 {
                w.event.errors += 1;
            }
            if o.status == 503 && o.layer != "allow" {
                w.event.capacity_errors += 1;
            }
            if o.status >= 400 {
                let source = if o.upstream {
                    "upstream"
                } else {
                    match o.layer {
                        "acl" | "global_acl" => "acl",
                        "geoip" | "global_geoip" => "geoip",
                        "rate_limit" | "global_rate_limit" | "identity_rate_limit" => "quota",
                        "crowdsec" => "crowdsec",
                        "challenge" => "challenge",
                        "waf" => "waf_block",
                        "waf_capacity" => "waf_capacity",
                        "forward_auth" => "forward_auth",
                        "api_schema" | "api_schema_capacity" => "api_schema",
                        l if l.starts_with("admission") || l.starts_with("ddos") => {
                            "admission_pressure"
                        }
                        _ => "gateway_other",
                    }
                };
                *w.event.denial_error_sources.entry(source).or_default() += 1;
            }

            if w.paths.len() < 64 {
                w.paths.insert(path);
            } else if !w.paths.contains(&path) {
                w.event.paths_saturated = true;
            }
            w.event.distinct_paths = w.paths.len();
            if w.event.request_ids.len() < 8
                && o.request_id.len() == 32
                && o.request_id.bytes().all(|b| b.is_ascii_hexdigit())
                && !w.event.request_ids.iter().any(|s| s == o.request_id)
            {
                w.event.request_ids.push(o.request_id.to_owned());
            }
            let gap = w.gap_epoch != self.dropped.load(Ordering::Relaxed);
            w.event.quality = if gap {
                "gap"
            } else if w.event.samples < u64::from(p.min_samples) {
                "warmup"
            } else {
                "observed"
            };
            let pressure = w.event.samples >= u64::from(p.requests_per_second) * p.window_seconds;
            let probing = w.event.distinct_paths >= p.distinct_paths as usize
                && w.event.upstream_404 * 100
                    >= w.event.samples * u64::from(p.upstream_404_percent);
            if !gap
                && w.event.samples >= u64::from(p.min_samples)
                && pressure
                && (detector == "route_flood" || probing)
            {
                w.firing = true;
                w.event.revision += 1;
                self.publish(&mut state, w.event.clone());
            }
            state.windows.insert(key, w);
        }
    }
    pub fn pending(&self) -> Vec<Event> {
        let gap = self.dropped.load(Ordering::Relaxed);
        self.state
            .try_lock()
            .map(|s| {
                s.pending
                    .values()
                    .take(32)
                    .cloned()
                    .map(|mut e| {
                        if e.gap_epoch != gap {
                            e.quality = "gap";
                        }
                        e
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn ack(&self, key: &str, revision: u64) {
        if let Ok(mut s) = self.state.try_lock()
            && s.pending.get(key).is_some_and(|e| e.revision == revision)
        {
            s.pending.remove(key);
            self.persisted.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn observation_lost(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    pub fn persistence_failed(&self) {
        self.persistence_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn diagnostics(&self, now: u64) -> serde_json::Value {
        let gap = self.dropped.load(Ordering::Relaxed);
        let state = self.state.try_lock();
        let Ok(s) = state else {
            return serde_json::json!({"quality":"unknown","reason":"contention","dropped":gap});
        };
        let rows:Vec<_>=s.windows.values().take(128).map(|w|serde_json::json!({"detector":w.event.detector,"route":w.event.route,"scope":w.event.scope,"config_version":w.event.config_version,"quality":if now.saturating_sub(w.last_seen)>w.window_ms {"stale"}else if gap!=w.gap_epoch {"gap"}else{w.event.quality},"firing":w.firing,"evidence":w.event})).collect();
        serde_json::json!({"mode":"observe_only","source":"gateway_completions","observed_at_unix_ms":now,"reset":"process_restart;config_change_starts_new_window","max_keys":MAX_KEYS,"keys":s.windows.len(),"max_pending":MAX_EVENTS,"pending":s.pending.len(),"dropped":gap,"quality":if gap>0{"gap"}else if s.windows.is_empty(){"unknown"}else{"observed"},"persisted":self.persisted.load(Ordering::Relaxed),"persistence_errors":self.persistence_errors.load(Ordering::Relaxed),"truncated":s.windows.len()>128,"windows":rows})
    }
}
