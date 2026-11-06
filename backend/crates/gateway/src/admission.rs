//! Node-owned admission survives config versions. No capacity wait queue or I/O.
//! Registry contention may await at most 5 ms, bounded by pre-routing header slots.
//! Class partitions never borrow: bulk traffic cannot consume critical capacity.
use openwaf_config::{
    resources::{Admission, Budgets},
    traffic::Class,
};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Gate {
    active: AtomicUsize,
    peak: AtomicUsize,
    admitted: AtomicU64,
    rejected: AtomicU64,
}
#[derive(Serialize)]
pub struct Counts {
    pub active: usize,
    pub high_water: usize,
    pub admitted: u64,
    pub rejected: u64,
}
pub struct Permit(Arc<Gate>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}
impl Gate {
    pub fn enter(self: &Arc<Self>, cap: usize) -> Option<Permit> {
        match increment(&self.active, cap) {
            Ok(n) => {
                self.peak.fetch_max(n + 1, Relaxed);
                self.admitted.fetch_add(1, Relaxed);
                Some(Permit(self.clone()))
            }
            Err(_) => {
                self.rejected.fetch_add(1, Relaxed);
                None
            }
        }
    }
    pub fn counts(&self) -> Counts {
        Counts {
            active: self.active.load(Relaxed),
            high_water: self.peak.load(Relaxed),
            admitted: self.admitted.load(Relaxed),
            rejected: self.rejected.load(Relaxed),
        }
    }
}
struct Route {
    requests: Arc<Gate>,
    streams: Arc<Gate>,
    uploads: Arc<Gate>,
    clients: Mutex<HashMap<IpAddr, Arc<Gate>>>,
    used: Instant,
}
impl Route {
    fn new() -> Self {
        Self {
            requests: Default::default(),
            streams: Default::default(),
            uploads: Default::default(),
            clients: Default::default(),
            used: Instant::now(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Reason {
    Global,
    Class,
    Route,
    Client,
    Keys,
    Contention,
    Upload,
    Stream,
}
impl Reason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Global => "admission_global",
            Self::Class => "admission_class",
            Self::Route => "admission_route",
            Self::Client => "admission_client",
            Self::Keys => "admission_keys",
            Self::Contention => "admission_contention",
            Self::Upload => "admission_upload",
            Self::Stream => "admission_stream",
        }
    }
    pub fn status(self) -> u16 {
        if matches!(self, Self::Client) {
            429
        } else {
            503
        }
    }
}
pub struct Lease {
    _permits: Vec<Permit>,
    upload: Arc<Gate>,
    upload_cap: usize,
    is_upload: bool,
    class_upload: Arc<Gate>,
    class_cap: usize,
}
impl Lease {
    pub fn upload(&mut self) -> Result<(), Reason> {
        if !self.is_upload {
            let class = self
                .class_upload
                .enter(self.class_cap)
                .ok_or(Reason::Upload)?;
            self._permits
                .push(self.upload.enter(self.upload_cap).ok_or(Reason::Upload)?);
            self._permits.push(class);
            self.is_upload = true;
        }
        Ok(())
    }
}
pub struct Node {
    pub budgets: Budgets,
    pub connections: Arc<Gate>,
    pub handshakes: Arc<Gate>,
    pub headers: Arc<Gate>,
    total: Arc<Gate>,
    classes: [Arc<Gate>; 4],
    shared: [Arc<Gate>; 4],
    uploads: [Arc<Gate>; 4],
    streams: [Arc<Gate>; 4],
    admitted: AtomicU64,
    reserved: Vec<Arc<Gate>>,
    routes: [tokio::sync::Mutex<HashMap<String, Route>>; 4],
    reasons: [AtomicU64; 8],
}
impl Node {
    pub fn new(budgets: Budgets) -> Arc<Self> {
        let reserved = budgets
            .reserved_routes
            .iter()
            .map(|_| Arc::new(Gate::default()))
            .collect();
        let mut routes: [HashMap<String, Route>; 4] = Default::default();
        for reservation in &budgets.reserved_routes {
            routes[reservation.class.index()].insert(reservation.route.clone(), Route::new());
        }
        Arc::new(Self {
            budgets,
            shared: Default::default(),
            uploads: Default::default(),
            streams: Default::default(),
            admitted: Default::default(),
            reserved,
            connections: Default::default(),
            handshakes: Default::default(),
            headers: Default::default(),
            total: Default::default(),
            classes: Default::default(),
            routes: routes.map(tokio::sync::Mutex::new),
            reasons: Default::default(),
        })
    }
    pub async fn admit(
        &self,
        class: Class,
        id: &str,
        quota: &Admission,
        client: IpAddr,
    ) -> Result<Lease, Reason> {
        let result = self.try_admit(class, id, quota, client).await;
        if let Err(reason) = result {
            self.reject(reason);
        } else {
            self.admitted.fetch_add(1, Relaxed);
        }
        result
    }
    pub fn reject(&self, reason: Reason) {
        self.reasons[reason as usize].fetch_add(1, Relaxed);
    }
    async fn try_admit(
        &self,
        class: Class,
        id: &str,
        quota: &Admission,
        client: IpAddr,
    ) -> Result<Lease, Reason> {
        let c = class.index();
        let mut routes = tokio::time::timeout(Duration::from_millis(5), self.routes[c].lock())
            .await
            .map_err(|_| Reason::Contention)?;
        let mut permits = vec![
            self.total
                .enter(self.budgets.requests)
                .ok_or(Reason::Global)?,
            self.classes[c]
                .enter(self.budgets.classes[c])
                .ok_or(Reason::Class)?,
        ];
        if let Some((i, reservation)) = self
            .budgets
            .reserved_routes
            .iter()
            .enumerate()
            .find(|(_, r)| r.class == class && r.route == id)
        {
            permits.push(
                self.reserved[i]
                    .enter(reservation.slots)
                    .ok_or(Reason::Route)?,
            );
        } else {
            let reserved: usize = self
                .budgets
                .reserved_routes
                .iter()
                .filter(|r| r.class == class)
                .map(|r| r.slots)
                .sum();
            permits.push(
                self.shared[c]
                    .enter(self.budgets.classes[c] - reserved)
                    .ok_or(Reason::Class)?,
            );
        }
        let now = Instant::now();
        routes.retain(|id, r| {
            self.budgets
                .reserved_routes
                .iter()
                .any(|r| r.class == class && r.route == *id)
                || r.requests.active.load(Relaxed) > 0
                || now.saturating_duration_since(r.used) < Duration::from_secs(60)
        });
        if !routes.contains_key(id) && routes.len() >= 128 {
            return Err(Reason::Keys);
        }
        let route = routes.entry(id.to_owned()).or_insert_with(Route::new);
        route.used = now;
        permits.push(route.requests.enter(quota.requests).ok_or(Reason::Route)?);
        if class == Class::Stream {
            permits.push(
                self.streams[c]
                    .enter(self.budgets.classes[c])
                    .ok_or(Reason::Stream)?,
            );
            permits.push(route.streams.enter(quota.streams).ok_or(Reason::Stream)?);
        }
        if class == Class::Upload {
            permits.push(
                self.uploads[c]
                    .enter(self.budgets.classes[c])
                    .ok_or(Reason::Upload)?,
            );
            permits.push(route.uploads.enter(quota.uploads).ok_or(Reason::Upload)?);
        }
        let mut clients = route.clients.try_lock().map_err(|_| Reason::Contention)?;
        clients.retain(|_, g| g.active.load(Relaxed) > 0);
        let client = openwaf_config::normalized_ip(client);
        if !clients.contains_key(&client) && clients.len() >= 128 {
            return Err(Reason::Keys);
        }
        permits.push(
            clients
                .entry(client)
                .or_default()
                .enter(quota.per_client)
                .ok_or(Reason::Client)?,
        );
        Ok(Lease {
            _permits: permits,
            upload: route.uploads.clone(),
            upload_cap: quota.uploads,
            is_upload: class == Class::Upload,
            class_upload: self.uploads[c].clone(),
            class_cap: self.budgets.classes[c],
        })
    }
    /// Fixed labels only. Routes are bounded registry entries, not metric labels.
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1, "source":"gateway_local", "observed_at_unix_ms":openwaf_telemetry::now_ms(), "budgets":self.budgets, "estimated_ram_bytes":self.budgets.estimated_ram(), "estimated_fds":self.budgets.estimated_fds(), "requests":self.total.counts(), "connections":self.connections.counts(), "handshakes":self.handshakes.counts(), "headers":self.headers.counts(), "admitted_total":self.admitted.load(Relaxed),"upload_slots":self.uploads.iter().map(|g|g.counts()).collect::<Vec<_>>(),"stream_slots":self.streams.iter().map(|g|g.counts()).collect::<Vec<_>>(),"classes": self.classes.iter().map(|g| g.counts()).collect::<Vec<_>>(), "rejections": ([Reason::Global, Reason::Class, Reason::Route, Reason::Client, Reason::Keys, Reason::Contention, Reason::Upload, Reason::Stream].iter().map(|r| serde_json::json!({"reason":r.label(),"total":self.reasons[*r as usize].load(Relaxed)})).collect::<Vec<_>>())})
    }
}

fn increment(active: &AtomicUsize, cap: usize) -> Result<usize, usize> {
    let mut n = active.load(Relaxed);
    loop {
        if n >= cap {
            return Err(n);
        }
        match active.compare_exchange_weak(n, n + 1, Relaxed, Relaxed) {
            Ok(n) => return Ok(n),
            Err(next) => n = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn website_defaults_allow_browser_parallelism_and_still_bound_clients_and_route() {
        let node = Node::new(Budgets::default());
        let quota = Admission::default();
        let mut held = Vec::new();
        let first = "192.0.2.1".parse().expect("client");
        for _ in 0..32 {
            held.push(
                node.admit(Class::Api, "website", &quota, first)
                    .await
                    .expect("browser request"),
            );
        }
        assert!(matches!(
            node.admit(Class::Api, "website", &quota, first).await,
            Err(Reason::Client)
        ));
        let second = "192.0.2.2".parse().expect("second client");
        for _ in 0..32 {
            held.push(
                node.admit(Class::Api, "website", &quota, second)
                    .await
                    .expect("second browser"),
            );
        }
        assert!(matches!(
            node.admit(
                Class::Api,
                "website",
                &quota,
                "192.0.2.3".parse().expect("third client")
            )
            .await,
            Err(Reason::Route)
        ));
        assert_eq!(node.total.counts().active, 64);
        drop(held);
        assert_eq!(node.total.counts().active, 0);
        let custom = Admission {
            per_client: 4,
            ..quota
        };
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                node.admit(Class::Api, "website", &custom, first)
                    .await
                    .expect("custom quota"),
            );
        }
        assert!(matches!(
            node.admit(Class::Api, "website", &custom, first).await,
            Err(Reason::Client)
        ));
    }
    #[tokio::test]
    async fn every_hierarchy_is_bounded_and_reserved_route_cannot_be_borrowed() {
        let node = Node::new(Budgets {
            requests: 8,
            classes: [2; 4],
            reserved_routes: vec![openwaf_config::resources::Reservation {
                route: "payment".into(),
                class: Class::Critical,
                slots: 1,
            }],
            ..Default::default()
        });
        let q = Admission {
            requests: 2,
            streams: 1,
            uploads: 1,
            per_client: 2,
        };
        let ip = "192.0.2.1".parse().expect("ip");
        let ordinary = node
            .admit(Class::Critical, "ordinary", &q, ip)
            .await
            .expect("shared");
        assert!(matches!(
            node.admit(Class::Critical, "another", &q, ip).await,
            Err(Reason::Class)
        ));
        let reserved = node
            .admit(Class::Critical, "payment", &q, ip)
            .await
            .expect("reserved route");
        drop((ordinary, reserved));
        let stream = node
            .admit(Class::Stream, "stream", &q, ip)
            .await
            .expect("stream");
        assert!(matches!(
            node.admit(Class::Stream, "stream", &q, ip).await,
            Err(Reason::Stream)
        ));
        let upload = node
            .admit(Class::Upload, "upload", &q, ip)
            .await
            .expect("upload");
        assert!(matches!(
            node.admit(Class::Upload, "upload", &q, ip).await,
            Err(Reason::Upload)
        ));
        drop((stream, upload));
        let mut held = Vec::new();
        for class in [Class::Api, Class::Upload, Class::Stream, Class::Critical] {
            let quota = Admission {
                requests: 2,
                streams: 2,
                uploads: 2,
                per_client: 2,
            };
            for id in if class == Class::Critical {
                ["ordinary", "payment"]
            } else {
                ["first", "second"]
            } {
                held.push(
                    node.admit(class, id, &quota, ip)
                        .await
                        .expect("class capacity"),
                );
            }
        }
        assert_eq!(node.total.counts().active, 8);
        assert!(matches!(
            node.admit(Class::Critical, "payment", &q, ip).await,
            Err(Reason::Global)
        ));
        drop(held);
        assert_eq!(node.total.counts().active, 0);
    }

    #[tokio::test]
    async fn partitions_client_fairness_and_cancellation_survive_policy_changes() {
        let node = Node::new(Budgets {
            requests: 8,
            classes: [2; 4],
            ..Default::default()
        });
        let q = Admission {
            requests: 2,
            streams: 2,
            uploads: 2,
            per_client: 1,
        };
        let ip = "192.0.2.1".parse().expect("ip");
        let a = node
            .admit(Class::Upload, "upload", &q, ip)
            .await
            .expect("first");
        assert!(matches!(
            node.admit(Class::Upload, "upload", &q, ip).await,
            Err(Reason::Client)
        ));
        let b = node
            .admit(Class::Upload, "other", &q, ip)
            .await
            .expect("second");
        assert!(matches!(
            node.admit(Class::Upload, "third", &q, ip).await,
            Err(Reason::Class)
        ));
        let critical = node
            .admit(Class::Critical, "payment", &q, ip)
            .await
            .expect("reserved partition");
        drop((a, b, critical));
        assert_eq!(node.total.counts().active, 0);
        let a = node
            .admit(Class::Api, "api", &q, ip)
            .await
            .expect("old version");
        assert!(matches!(
            node.admit(Class::Api, "api", &q, ip).await,
            Err(Reason::Client)
        ));
        drop(a);
        node.admit(Class::Api, "api", &q, ip)
            .await
            .expect("released");
        assert_eq!(node.total.counts().active, 0);
    }
}
