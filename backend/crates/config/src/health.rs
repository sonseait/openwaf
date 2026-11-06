//! Bounded operational state; routing documents remain immutable. No network I/O.
use crate::{Context, Document, Validation, canonical_path, request_host, validate_address};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    #[default]
    Head,
    Get,
}
impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Head => "HEAD",
            Self::Get => "GET",
        }
    }
    fn is_head(&self) -> bool {
        *self == Self::Head
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    #[serde(skip_serializing_if = "Method::is_head")]
    pub method: Method,
    pub path: String,
    pub host: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub status_min: u16,
    pub status_max: u16,
    pub healthy_threshold: u8,
    pub unhealthy_threshold: u8,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            method: Method::Head,
            path: "/".into(),
            host: None,
            interval_ms: 2000,
            timeout_ms: 3000,
            status_min: 200,
            status_max: 399,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        }
    }
}
impl Settings {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&mut self) -> Result<(), Validation> {
        self.path = canonical_path(&self.path).map_err(|_| Validation::Health)?;
        if !(250..=30000).contains(&self.interval_ms)
            || !(100..=10000).contains(&self.timeout_ms)
            || !(200..=599).contains(&self.status_min)
            || !(self.status_min..=599).contains(&self.status_max)
            || !(1..=10).contains(&self.healthy_threshold)
            || !(1..=10).contains(&self.unhealthy_threshold)
        {
            return Err(Validation::Health);
        }
        if let Some(host) = &mut self.host {
            let name = request_host(host).map_err(|_| Validation::Health)?;
            let authority: http::uri::Authority = host.parse().map_err(|_| Validation::Health)?;
            if authority.port_u16() == Some(0) {
                return Err(Validation::Health);
            }
            let name = if name.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{name}]")
            } else {
                name
            };
            *host = match authority.port_u16() {
                Some(port) => format!("{name}:{port}"),
                None => name,
            };
        }
        Ok(())
    }
}

#[derive(Clone, Default, Serialize)]
pub struct Diagnostic {
    pub latency_ms: u64,
    pub resolved_addresses: usize,
    pub complete: bool,
    pub addresses: Vec<AddressCheck>,
}
#[derive(Clone, Serialize)]
pub struct AddressCheck {
    pub address: SocketAddr,
    pub accepted: bool,
    pub tcp: &'static str,
    pub tls: &'static str,
    pub http: &'static str,
    pub http_status: Option<u16>,
    pub error: Option<&'static str>,
    pub latency_ms: u64,
}
pub struct Observation {
    pub addresses: Vec<SocketAddr>,
    pub expires: Instant,
    pub checked_at_ms: u64,
    pub reason: &'static str,
    pub diagnostic: Option<Diagnostic>,
}

pub struct Peer {
    pub address: SocketAddr,
    failed: AtomicBool,
}
impl Peer {
    /// Passive failure affects this generation only; a successful active check recovers it.
    pub fn fail(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }
}
struct State {
    recovered_at: Option<Instant>,
    peers: Vec<Arc<Peer>>,
    expires: Instant,
    checked_at_ms: Option<u64>,
    reason: &'static str,
    consecutive_successes: u8,
    consecutive_failures: u8,
    diagnostic: Option<Diagnostic>,
}
pub struct Health {
    slots: Vec<Vec<ArcSwap<State>>>,
    context: Context,
    settings: Vec<Settings>,
}
#[derive(Serialize)]
pub struct Status {
    pub upstream: usize,
    pub endpoint: usize,
    pub available: bool,
    pub addresses: Vec<SocketAddr>,
    pub checked_at_ms: Option<u64>,
    pub valid_for_ms: u64,
    pub reason: &'static str,
    pub source: &'static str,
    pub phase: &'static str,
    pub consecutive_successes: u8,
    pub consecutive_failures: u8,
    pub last_check: Option<Diagnostic>,
}
impl Health {
    pub fn new(document: &Document, context: Context) -> Self {
        Self {
            context,
            settings: document
                .upstreams
                .iter()
                .map(|u| u.health.clone())
                .collect(),
            slots: document
                .upstreams
                .iter()
                .map(|u| {
                    u.endpoints
                        .iter()
                        .map(|_| {
                            ArcSwap::from_pointee(State {
                                recovered_at: None,
                                peers: vec![],
                                expires: Instant::now(),
                                checked_at_ms: None,
                                reason: "pending",
                                consecutive_successes: 0,
                                consecutive_failures: 0,
                                diagnostic: None,
                            })
                        })
                        .collect()
                })
                .collect(),
        }
    }
    /// Defensively validate the entire DNS answer again before publication.
    pub fn publish(
        &self,
        upstream: usize,
        endpoint: usize,
        addresses: Vec<SocketAddr>,
        expires: Instant,
        checked_at_ms: u64,
        reason: &'static str,
    ) {
        self.observe(
            upstream,
            endpoint,
            Observation {
                addresses,
                expires,
                checked_at_ms,
                reason,
                diagnostic: None,
            },
        );
    }
    /// Only the health scheduler writes a slot. Failed checks quarantine traffic
    /// immediately; thresholds classify failure and gate subsequent recovery.
    pub fn observe(&self, upstream: usize, endpoint: usize, observation: Observation) {
        let Observation {
            addresses,
            expires,
            checked_at_ms,
            reason,
            diagnostic,
        } = observation;
        let Some(slot) = self.slots.get(upstream).and_then(|u| u.get(endpoint)) else {
            return;
        };
        let valid = addresses.len() <= 16
            && addresses
                .iter()
                .all(|a| validate_address(*a, &self.context).is_ok());
        let old = slot.load();
        let success = valid && !addresses.is_empty() && expires > Instant::now();
        let passive_failure = old
            .peers
            .iter()
            .any(|peer| peer.failed.load(Ordering::Relaxed));
        let successes = if success {
            if passive_failure {
                1
            } else {
                old.consecutive_successes.saturating_add(1).min(10)
            }
        } else {
            0
        };
        let failures = if success {
            0
        } else {
            old.consecutive_failures.saturating_add(1).min(10)
        };
        let recovered = success && successes >= self.settings[upstream].healthy_threshold;
        let recovered_at = if recovered {
            if !passive_failure && old.expires > Instant::now() && !old.peers.is_empty() {
                old.recovered_at
            } else {
                Some(Instant::now())
            }
        } else {
            None
        };
        slot.store(Arc::new(State {
            recovered_at,
            peers: if success && successes >= self.settings[upstream].healthy_threshold {
                addresses
                    .into_iter()
                    .map(|address| {
                        Arc::new(Peer {
                            address,
                            failed: AtomicBool::new(false),
                        })
                    })
                    .collect()
            } else {
                vec![]
            },
            expires,
            checked_at_ms: Some(checked_at_ms),
            reason: if !valid {
                "forbidden_address"
            } else if success && successes < self.settings[upstream].healthy_threshold {
                "recovery_threshold"
            } else {
                reason
            },
            consecutive_successes: successes,
            consecutive_failures: failures,
            diagnostic,
        }));
    }
    pub fn select(&self, upstream: usize, endpoint: usize, next: usize) -> Option<Arc<Peer>> {
        let state = self.slots.get(upstream)?.get(endpoint)?.load();
        if state.expires <= Instant::now() {
            return None;
        }
        for offset in 0..state.peers.len() {
            let peer = &state.peers[next.wrapping_add(offset) % state.peers.len()];
            if !peer.failed.load(Ordering::Relaxed) {
                return Some(peer.clone());
            }
        }
        None
    }
    pub fn recovery_progress(&self, upstream: usize, endpoint: usize, slow_start_ms: u64) -> u64 {
        if slow_start_ms == 0 {
            return 1000;
        }
        self.slots
            .get(upstream)
            .and_then(|s| s.get(endpoint))
            .and_then(|s| s.load().recovered_at)
            .map_or(1, |since| {
                ((since.elapsed().as_millis() * 1000 / u128::from(slow_start_ms)).min(1000) as u64)
                    .max(1)
            })
    }
    pub fn status(&self) -> Vec<Status> {
        self.slots
            .iter()
            .enumerate()
            .flat_map(|(u, slots)| {
                slots.iter().enumerate().map(move |(e, slot)| {
                    let state = slot.load();
                    let now = Instant::now();
                    let addresses: Vec<_> = state
                        .peers
                        .iter()
                        .filter(|p| state.expires > now && !p.failed.load(Ordering::Relaxed))
                        .map(|p| p.address)
                        .collect();
                    let available = !addresses.is_empty();
                    Status {
                        upstream: u,
                        endpoint: e,
                        available,
                        addresses,
                        checked_at_ms: state.checked_at_ms,
                        valid_for_ms: state
                            .expires
                            .saturating_duration_since(now)
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                        reason: if available {
                            "healthy"
                        } else if state.reason == "healthy" {
                            "expired_or_passive_failure"
                        } else {
                            state.reason
                        },
                        source: "gateway",
                        phase: if state.checked_at_ms.is_none() {
                            "pending"
                        } else if available {
                            "healthy"
                        } else if state.consecutive_successes > 0
                            && state.consecutive_successes < self.settings[u].healthy_threshold
                        {
                            "recovering"
                        } else if state.consecutive_failures >= self.settings[u].unhealthy_threshold
                        {
                            "unhealthy"
                        } else if state.consecutive_failures > 0 {
                            "suspect"
                        } else {
                            "unavailable"
                        },
                        consecutive_successes: state.consecutive_successes,
                        consecutive_failures: state.consecutive_failures,
                        last_check: state.diagnostic.clone(),
                    }
                })
            })
            .collect()
    }
}
