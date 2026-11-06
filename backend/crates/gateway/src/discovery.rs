//! Private collector client and candidate projection, entirely outside proxy requests.
//! No dependency on Docker's client and no arbitrary socket/operation supplied by HTTP.
use crate::probe::{Endpoint as ProbeEndpoint, ProbeService, Protocol as ProbeProtocol};
use anyhow::{Context as _, ensure};
use openwaf_admin::discovery::{Backend, Candidate, Failure, Inventory, Kind};
use openwaf_config::{
    Address, Context, Document, Endpoint, Protocol, Snapshot, Upstream, hostname, source::Source,
    validate_address,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    env,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, Semaphore},
};

const MAX_WIRE: usize = 4 * 1024 * 1024 + 1;
const MAX_CANDIDATES: usize = 16384;
#[derive(Default)]
pub struct Deployment {
    pub host_network: bool,
    pub networks: BTreeSet<String>,
    pub host_gateway: Option<String>,
    pub self_ids: BTreeSet<String>,
}
pub struct Service {
    path: Option<PathBuf>,
    uid: Option<u32>,
    context: Context,
    deployment: Deployment,
    probe: ProbeService,
    permits: Semaphore,
    metadata_slots: Arc<Semaphore>,
    cache: Mutex<[Option<Arc<Inventory>>; 2]>,
    last_refresh: Mutex<Option<Instant>>,
}
#[derive(Deserialize)]
struct Wire {
    schema_version: u8,
    source: String,
    collection_scope: String,
    stale: bool,
    snapshot: WireSource,
    events: Option<WireEvents>,
}
#[derive(Deserialize)]
struct WireEvents {
    connected: bool,
}
#[derive(Deserialize)]
struct WireSource {
    items: Vec<serde_json::Value>,
    observed_at_unix_ms: Option<u64>,
    degraded: bool,
    error: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct Container {
    id: String,
    name: String,
    image: String,
    state: String,
    health: Option<String>,
    compose_service: Option<String>,
    compose_project: Option<String>,
    networks: Vec<Network>,
    exposed_ports: Vec<String>,
    published_ports: Vec<Published>,
}
#[derive(Deserialize, Serialize)]
struct Network {
    name: String,
    aliases: Vec<String>,
}
#[derive(Deserialize, Serialize)]
struct Published {
    container_port: u16,
    protocol: String,
    bind_address: IpAddr,
    host_port: u16,
}
#[derive(Deserialize, Serialize)]
struct Listener {
    bind_address: IpAddr,
    port: u16,
}
fn now_ms() -> Result<u64, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Failure::Unavailable)
}
fn env_set(name: &str) -> anyhow::Result<BTreeSet<String>> {
    let values: BTreeSet<_> = env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect();
    ensure!(
        values.len() <= 32
            && values.iter().all(|v| v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))),
        "invalid discovery deployment inventory"
    );
    Ok(values)
}
impl Service {
    pub fn from_env(context: Context, ca: Option<&Path>) -> anyhow::Result<Self> {
        let path = env::var_os("OPENWAF_DISCOVERY_SOCKET").map(PathBuf::from);
        let uid = env::var("OPENWAF_DISCOVERY_UID")
            .ok()
            .map(|v| v.parse::<u32>())
            .transpose()
            .context("invalid collector UID")?;
        ensure!(
            path.as_ref()
                .is_none_or(|p| p.is_absolute() && p.to_str().is_some())
                && (path.is_none() || uid.is_some()),
            "discovery socket requires an absolute path and OPENWAF_DISCOVERY_UID"
        );
        let mode = env::var("OPENWAF_GATEWAY_NETWORK_MODE").unwrap_or_else(|_| "bridge".into());
        ensure!(
            matches!(mode.as_str(), "host" | "bridge"),
            "invalid gateway network mode"
        );
        let host_gateway = env::var("OPENWAF_HOST_GATEWAY")
            .ok()
            .map(|s| hostname(&s))
            .transpose()?;
        if let Some(host) = &host_gateway {
            let _: Address = authority(host, 1).parse()?;
            if let Ok(ip) = host.parse::<IpAddr>() {
                let ip = openwaf_config::normalized_ip(ip);
                validate_address(
                    SocketAddr::new(ip, 1),
                    &Context {
                        listeners: vec![],
                        local_ips: vec![],
                    },
                )?;
                ensure!(
                    mode == "host" || !ip.is_loopback(),
                    "bridge host gateway cannot be loopback"
                );
            }
        }
        Ok(Self {
            path,
            uid,
            context: context.clone(),
            deployment: Deployment {
                host_network: mode == "host",
                networks: env_set("OPENWAF_GATEWAY_DOCKER_NETWORKS")?,
                host_gateway,
                self_ids: env_set("OPENWAF_GATEWAY_CONTAINER_IDS")?,
            },
            probe: ProbeService::new(vec![], ca)?.with_context(context),
            permits: Semaphore::new(4),
            metadata_slots: Arc::new(Semaphore::new(4)),
            cache: Mutex::new([None, None]),
            last_refresh: Mutex::new(None),
        })
    }
    async fn command(&self, op: &'static str) -> anyhow::Result<Vec<u8>> {
        let path = self
            .path
            .as_ref()
            .context("collector not configured")?
            .clone();
        let uid = self.uid;
        // A cancelled caller cannot release this permit while a filesystem syscall
        // is still running. At most four blocking metadata jobs can exist.
        let permit = self.metadata_slots.clone().try_acquire_owned()?;
        let path = tokio::task::spawn_blocking(move || -> anyhow::Result<PathBuf> {
            let _permit = permit;
            let metadata = std::fs::symlink_metadata(&path)?;
            let parent = std::fs::symlink_metadata(path.parent().context("socket parent")?)?;
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.permissions().mode() & 0o077 == 0
                    && Some(metadata.uid()) == uid
                    && parent.is_dir()
                    && Some(parent.uid()) == uid
                    && parent.permissions().mode() & 0o077 == 0,
                "collector socket permissions"
            );
            Ok(path)
        })
        .await??;
        let mut stream = UnixStream::connect(path).await?;
        ensure!(
            Some(stream.peer_cred()?.uid()) == self.uid,
            "collector peer identity"
        );
        stream
            .write_all(format!("{{\"op\":\"{op}\"}}\n").as_bytes())
            .await?;
        let mut bytes = Vec::new();
        stream
            .take((MAX_WIRE + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= MAX_WIRE && bytes.last() == Some(&b'\n'),
            "collector response framing or limit"
        );
        Ok(bytes)
    }
    fn candidate(
        &self,
        source: Source,
        address: Option<Address>,
        reason: Option<&'static str>,
        stale: bool,
    ) -> anyhow::Result<Candidate> {
        let mut key = serde_json::to_value(&source)?;
        if let Some(object) = key.as_object_mut() {
            object.remove("observed_at_unix_ms");
        }
        let key = serde_json::to_vec(&(key, &address))?;
        let id = openssl::sha::sha256(&key)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let reason = if stale { Some("source_stale") } else { reason }.or_else(|| {
            let address = address.as_ref()?;
            if source.validate(address).is_err() {
                return Some("invalid_metadata");
            }
            address
                .socket()
                .and_then(|a| validate_address(a, &self.context).err())
                .map(|_| "openwaf_or_forbidden_endpoint")
        });
        Ok(Candidate {
            id,
            selectable: reason.is_none() && address.is_some(),
            address,
            source,
            unavailable_reason: reason,
            verification: "not_tested",
        })
    }
    fn host_address(&self, ip: IpAddr, port: u16) -> (Option<Address>, Option<&'static str>) {
        let ip = openwaf_config::normalized_ip(ip);
        if port == 0 {
            return (None, Some("invalid_port"));
        }
        if ip.is_loopback() && !self.deployment.host_network {
            return (None, Some("host_loopback_unreachable_from_bridge"));
        }
        if ip.is_unspecified() {
            return match &self.deployment.host_gateway {
                Some(host) => (authority(host, port).parse().ok(), None),
                None => (None, Some("gateway_host_address_required")),
            };
        }
        (SocketAddr::new(ip, port).to_string().parse().ok(), None)
    }
    fn project(&self, kind: Kind, bytes: &[u8]) -> anyhow::Result<Inventory> {
        let wire: Wire = serde_json::from_slice(bytes)?;
        ensure!(
            wire.schema_version == 1
                && wire.source == kind.op()
                && wire.collection_scope == "collector_network_namespace",
            "collector schema mismatch"
        );
        let now = now_ms().map_err(|_| anyhow::anyhow!("clock unavailable"))?;
        ensure!(
            wire.snapshot
                .observed_at_unix_ms
                .is_none_or(|time| time <= now.saturating_add(1000)),
            "invalid observation timestamp"
        );
        let stale = wire.stale
            || wire.snapshot.degraded
            || wire
                .snapshot
                .observed_at_unix_ms
                .is_none_or(|time| now.saturating_sub(time) > 20000);
        let observed = wire.snapshot.observed_at_unix_ms.unwrap_or(0);
        let mut result = Inventory {
            schema_version: 1,
            source: kind,
            collection_scope: "collector_network_namespace",
            collector_available: true,
            docker_events_connected: wire.events.map(|events| events.connected),
            stale,
            error: if stale {
                Some(match wire.snapshot.error.as_deref() {
                    Some("docker_refresh_failed") => "docker_refresh_failed",
                    Some("docker_snapshot_too_large") => "docker_snapshot_too_large",
                    Some("host_refresh_failed") => "host_refresh_failed",
                    Some("host_snapshot_too_large") => "host_snapshot_too_large",
                    Some("not_yet_refreshed") => "not_yet_refreshed",
                    _ => "source_stale",
                })
            } else {
                None
            },
            observed_at_unix_ms: wire.snapshot.observed_at_unix_ms,
            items: serde_json::json!([]),
            candidates: vec![],
            candidates_truncated: false,
        };
        let mut candidates = Vec::new();
        match kind {
            Kind::HostPorts => {
                ensure!(
                    wire.snapshot.items.len() <= 16384,
                    "too many host listeners"
                );
                let items: Vec<Listener> = wire
                    .snapshot
                    .items
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<_, _>>()?;
                for listener in &items {
                    if candidates.len() == MAX_CANDIDATES {
                        result.candidates_truncated = true;
                        break;
                    }
                    let (address, reason) = self.host_address(listener.bind_address, listener.port);
                    candidates.push(self.candidate(
                        Source::HostPort {
                            bind_address: listener.bind_address,
                            port: listener.port,
                            observed_at_unix_ms: observed,
                        },
                        address,
                        reason,
                        stale,
                    )?);
                }
                result.items = serde_json::to_value(items)?;
            }
            Kind::Docker => {
                ensure!(wire.snapshot.items.len() <= 512, "too many containers");
                let items: Vec<Container> = wire
                    .snapshot
                    .items
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<_, _>>()?;
                for container in &items {
                    ensure!(
                        container.id.len() <= 128
                            && container.name.len() <= 1024
                            && container.image.len() <= 1024
                            && container.state.len() <= 32
                            && container.health.as_ref().is_none_or(|s| s.len() <= 32)
                            && [&container.compose_service, &container.compose_project]
                                .iter()
                                .all(|s| s.as_ref().is_none_or(|s| s.len() <= 1024))
                            && container.networks.len() <= 128
                            && container.exposed_ports.len() <= 128
                            && container.published_ports.len() <= 512
                            && container.exposed_ports.iter().all(|s| s.len() <= 16)
                            && container
                                .published_ports
                                .iter()
                                .all(|p| p.protocol.len() <= 8)
                            && container.networks.iter().all(|n| n.name.len() <= 128
                                && n.aliases.len() <= 128
                                && n.aliases.iter().all(|a| a.len() <= 253)),
                        "container metadata limits"
                    );
                }
                'containers: for container in &items {
                    if self.deployment.self_ids.contains(&container.id) {
                        continue;
                    }
                    ensure!(
                        container.networks.len() <= 128
                            && container.exposed_ports.len() <= 128
                            && container.published_ports.len() <= 512,
                        "container metadata limits"
                    );
                    let stopped = (container.state != "running")
                        .then_some("container_not_running")
                        .or_else(|| {
                            container
                                .health
                                .as_deref()
                                .filter(|state| *state != "healthy")
                                .map(|_| "container_health_not_ready")
                        });
                    let mut ports = BTreeSet::new();
                    for value in &container.exposed_ports {
                        if let Some((port, "tcp")) = value.split_once('/')
                            && let Ok(port) = port.parse::<u16>()
                            && port > 0
                        {
                            ports.insert(port);
                        }
                    }
                    ports.extend(
                        container
                            .published_ports
                            .iter()
                            .filter(|p| p.protocol == "tcp" && p.container_port > 0)
                            .map(|p| p.container_port),
                    );
                    for network in &container.networks {
                        ensure!(network.aliases.len() <= 128, "alias limit");
                        for alias in &network.aliases {
                            let normalized = hostname(alias)
                                .ok()
                                .filter(|s| s.parse::<IpAddr>().is_err());
                            for port in &ports {
                                if candidates.len() == MAX_CANDIDATES {
                                    result.candidates_truncated = true;
                                    break 'containers;
                                }
                                let reason = stopped
                                    .or_else(|| {
                                        (!self.deployment.networks.contains(&network.name))
                                            .then_some("network_not_shared")
                                    })
                                    .or_else(|| normalized.is_none().then_some("invalid_alias"));
                                let address = normalized
                                    .as_ref()
                                    .and_then(|host| authority(host, *port).parse().ok());
                                candidates.push(self.candidate(
                                    Source::DockerAlias {
                                        container_id: container.id.clone(),
                                        network: network.name.clone(),
                                        alias: normalized.clone().unwrap_or_else(|| alias.clone()),
                                        port: *port,
                                        observed_at_unix_ms: observed,
                                    },
                                    address,
                                    reason,
                                    stale,
                                )?);
                            }
                        }
                    }
                    for published in &container.published_ports {
                        if published.protocol != "tcp" {
                            continue;
                        }
                        if candidates.len() == MAX_CANDIDATES {
                            result.candidates_truncated = true;
                            break 'containers;
                        }
                        let (address, reason) =
                            self.host_address(published.bind_address, published.host_port);
                        candidates.push(self.candidate(
                            Source::DockerPublished {
                                container_id: container.id.clone(),
                                bind_address: published.bind_address,
                                container_port: published.container_port,
                                host_port: published.host_port,
                                observed_at_unix_ms: observed,
                            },
                            address,
                            stopped.or(reason),
                            stale,
                        )?);
                    }
                }
                result.items = serde_json::to_value(items)?;
            }
        }
        candidates.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        candidates.dedup_by(|a, b| a.id == b.id);
        result.candidates = candidates;
        Ok(result)
    }
}
fn authority(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
#[async_trait::async_trait]
impl Backend for Service {
    async fn inventory(&self, kind: Kind) -> Result<Arc<Inventory>, Failure> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| Failure::Unavailable)?;
        let response = tokio::time::timeout(Duration::from_secs(2), self.command(kind.op())).await;
        if let Ok(Ok(bytes)) = response
            && let Ok(inventory) = self.project(kind, &bytes)
        {
            let inventory = Arc::new(inventory);
            self.cache.lock().await[kind.index()] = Some(inventory.clone());
            return Ok(inventory);
        }
        let cached = self.cache.lock().await[kind.index()].clone();
        let mut inventory = cached
            .map(|inventory| inventory.as_ref().clone())
            .unwrap_or(Inventory {
                schema_version: 1,
                source: kind,
                collection_scope: "collector_network_namespace",
                collector_available: false,
                docker_events_connected: None,
                stale: true,
                error: None,
                observed_at_unix_ms: None,
                items: serde_json::json!([]),
                candidates: vec![],
                candidates_truncated: false,
            });
        inventory.collector_available = false;
        inventory.docker_events_connected = None;
        inventory.stale = true;
        inventory.error = Some(if self.path.is_some() {
            "collector_unavailable"
        } else {
            "collector_not_configured"
        });
        for candidate in &mut inventory.candidates {
            candidate.selectable = false;
            candidate.unavailable_reason = Some("source_stale");
        }
        Ok(Arc::new(inventory))
    }
    async fn refresh(&self) -> Result<serde_json::Value, Failure> {
        let _permit = self
            .permits
            .try_acquire()
            .map_err(|_| Failure::Unavailable)?;
        let mut last = self
            .last_refresh
            .try_lock()
            .map_err(|_| Failure::RateLimited)?;
        if last.is_some_and(|time| time.elapsed() < Duration::from_secs(2)) {
            return Err(Failure::RateLimited);
        }
        *last = Some(Instant::now());
        let bytes = tokio::time::timeout(Duration::from_secs(2), self.command("refresh"))
            .await
            .map_err(|_| Failure::Unavailable)?
            .map_err(|_| Failure::Unavailable)?;
        #[derive(Deserialize)]
        struct Ack {
            schema_version: u8,
            accepted: bool,
            queued: bool,
        }
        let ack: Ack = serde_json::from_slice(&bytes).map_err(|_| Failure::Unavailable)?;
        if ack.schema_version != 1 || !ack.accepted {
            return Err(Failure::Unavailable);
        }
        Ok(
            serde_json::json!({"schema_version":1,"accepted":true,"queued":ack.queued,"completed":false}),
        )
    }
    async fn test(&self, endpoint: Endpoint) -> Result<serde_json::Value, Failure> {
        let snapshot = Snapshot::prepare(
            0,
            Document {
                upstreams: vec![Upstream {
                    balancing: Default::default(),
                    affinity: None,
                    id: "probe".into(),
                    endpoints: vec![endpoint],
                    timeouts: Default::default(),
                    health: Default::default(),
                }],
                ..Default::default()
            },
            &self.context,
        )
        .map_err(|_| Failure::Invalid)?;
        let endpoint = &snapshot.document.upstreams[0].endpoints[0];
        // Probe rechecks the full listener/local-IP context after every DNS lookup.
        let report = self
            .probe
            .test(ProbeEndpoint {
                host: endpoint.address.host(),
                port: endpoint.address.port(),
                protocol: if endpoint.protocol == Protocol::Http {
                    ProbeProtocol::Http
                } else {
                    ProbeProtocol::Https
                },
                tls_server_name: endpoint.tls_server_name.clone(),
                tls_verify: endpoint.tls_verify,
            })
            .await;
        serde_json::to_value(report).map_err(|_| Failure::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn service(deployment: Deployment) -> Service {
        let context = Context {
            listeners: vec!["127.0.0.1:8080".parse().expect("listener")],
            local_ips: vec![],
        };
        Service {
            path: None,
            uid: None,
            context: context.clone(),
            deployment,
            probe: ProbeService::new(vec![], None)
                .expect("probe")
                .with_context(context),
            permits: Semaphore::new(4),
            metadata_slots: Arc::new(Semaphore::new(4)),
            cache: Mutex::new([None, None]),
            last_refresh: Mutex::new(None),
        }
    }
    fn wire(kind: Kind, items: serde_json::Value, observed: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"source":kind.op(),"collection_scope":"collector_network_namespace","stale":false,"snapshot":{"items":items,"observed_at_unix_ms":observed,"degraded":false}})).expect("wire")
    }
    #[tokio::test]
    async fn bridge_never_rewrites_host_loopback_and_wildcard_needs_explicit_alias() {
        let mut deployment = Deployment::default();
        let items = serde_json::json!([{"bind_address":"127.0.0.1","port":9000},{"bind_address":"0.0.0.0","port":9001}]);
        let now = now_ms().expect("clock");
        let s = service(deployment);
        let result = s
            .project(Kind::HostPorts, &wire(Kind::HostPorts, items.clone(), now))
            .expect("inventory");
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.unavailable_reason == Some("host_loopback_unreachable_from_bridge"))
        );
        assert!(result.candidates.iter().all(|c| c.address.is_none()));
        deployment = Deployment {
            host_gateway: Some("host.gateway.test".into()),
            ..Default::default()
        };
        let s = service(deployment);
        let result = s
            .project(Kind::HostPorts, &wire(Kind::HostPorts, items, now))
            .expect("inventory");
        assert!(result.candidates.iter().any(|c| c.address.is_none()));
        let wildcard = result
            .candidates
            .iter()
            .find(|c| c.selectable)
            .expect("wildcard");
        assert_eq!(
            wildcard.address.as_ref().expect("alias").host(),
            "host.gateway.test"
        );
        assert!(wildcard.selectable);
    }
    #[tokio::test]
    async fn candidate_identity_is_stable_across_refresh_but_source_expiry_disables_selection() {
        let s = service(Deployment {
            host_network: true,
            ..Default::default()
        });
        let items = serde_json::json!([{"bind_address":"127.0.0.1","port":9000},{"bind_address":"127.0.0.1","port":8080}]);
        let now = now_ms().expect("clock");
        let fresh = s
            .project(Kind::HostPorts, &wire(Kind::HostPorts, items.clone(), now))
            .expect("fresh");
        let stale = s
            .project(Kind::HostPorts, &wire(Kind::HostPorts, items, now - 30000))
            .expect("stale");
        assert_eq!(fresh.candidates[0].id, stale.candidates[0].id);
        assert_eq!(fresh.candidates.iter().filter(|c| c.selectable).count(), 1);
        assert!(stale.stale && stale.candidates.iter().all(|c| !c.selectable));
    }

    #[tokio::test]
    async fn candidate_cross_product_is_capped_and_unknown_provider_fields_are_not_relayed() {
        let s = service(Deployment {
            networks: BTreeSet::from(["front".into()]),
            ..Default::default()
        });
        let ports: Vec<_> = (1..=128).map(|p| format!("{p}/tcp")).collect();
        let networks: Vec<_> = ["front", "back", "other"]
            .iter()
            .map(|n| serde_json::json!({"name":n,"aliases": (0..64).map(|i| format!("web{i}")).collect::<Vec<_>>()}))
            .collect();
        let item = serde_json::json!({"id":"abc123","name":"web","image":"fixture:1","state":"running","health":"healthy",
            "compose_service":null,"compose_project":null,"networks":networks,"exposed_ports":ports,"published_ports":[],"environment":"private-provider-field"});
        let result = s
            .project(
                Kind::Docker,
                &wire(
                    Kind::Docker,
                    serde_json::json!([item]),
                    now_ms().expect("clock"),
                ),
            )
            .expect("inventory");
        assert_eq!(result.candidates.len(), MAX_CANDIDATES);
        assert!(result.candidates_truncated);
        assert!(result.candidates.iter().any(|c| c.selectable));
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.unavailable_reason == Some("network_not_shared"))
        );
        assert!(!result.items.to_string().contains("private-provider-field"));
    }
}
