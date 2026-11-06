//! Full LAPI resync on a dedicated thread; proxy reads only immutable local state.
#![forbid(unsafe_code)]
mod checkpoint;
pub mod correlation;
pub mod ddos;
mod secret;
pub mod traffic;
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use ipnet::IpNet;
use reqwest::{
    Url,
    blocking::Client,
    header::{HeaderMap, HeaderValue},
};
pub use secret::seal;
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

const MAX_DECISIONS: usize = 10_000;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    lapi_url: String,
    key_file: PathBuf,
    master_key_file: PathBuf,
    #[serde(default)]
    ca_pem: Option<PathBuf>,
    #[serde(default)]
    checkpoint_file: Option<PathBuf>,
    #[serde(default = "poll_default")]
    poll_seconds: u64,
}
fn poll_default() -> u64 {
    10
}
#[derive(Deserialize)]
struct Response {
    #[serde(default, deserialize_with = "decision_list")]
    new: Option<Vec<Decision>>,
    deleted: Option<Vec<serde_json::Value>>,
}
fn decision_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Vec<Decision>>, D::Error> {
    Option::<Vec<Decision>>::deserialize(deserializer).map(|value| Some(value.unwrap_or_default()))
}
#[derive(Deserialize)]
struct Decision {
    id: u64,
    scope: String,
    value: String,
    duration: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    simulated: bool,
}
#[derive(Clone)]
struct Ban {
    network: IpNet,
    expires: Instant,
    expires_at_unix_ms: u64,
}
struct Snapshot {
    wall_highwater: u64,
    bans: HashMap<u64, Ban>,
    degraded: bool,
    last_success: Option<Instant>,
}
pub struct Store {
    snapshot: ArcSwap<Snapshot>,
    checkpoint_status: std::sync::Mutex<&'static str>,
    checkpoint_recovery: &'static str,
}
pub struct Health {
    pub checkpoint_recovery: &'static str,
    pub checkpoint_status: &'static str,
    pub degraded: bool,
    pub last_success_age: Option<Duration>,
}
impl Store {
    pub fn health(&self) -> Health {
        let snapshot = self.snapshot.load();
        Health {
            checkpoint_recovery: self.checkpoint_recovery,
            checkpoint_status: *self
                .checkpoint_status
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            degraded: snapshot.degraded,
            last_success_age: snapshot.last_success.map(|time| time.elapsed()),
        }
    }
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let snapshot = self.snapshot.load();
        let now = Instant::now();
        snapshot
            .bans
            .values()
            .any(|ban| ban.expires > now && ban.network.contains(&ip))
    }
}
fn duration(value: &str) -> Result<Duration> {
    ensure!(value.len() <= 64, "invalid decision duration");
    let negative = value.starts_with('-');
    let duration = humantime::parse_duration(value.trim_start_matches(['-', '+']))
        .context("invalid decision duration")?;
    ensure!(
        duration <= Duration::from_secs(366 * 86400),
        "decision duration exceeds one year"
    );
    Ok(if negative { Duration::ZERO } else { duration })
}
fn apply(old: &Snapshot, response: Response, started: Instant) -> Result<Snapshot> {
    let decisions = response.new.context("missing full decision list")?;
    ensure!(
        decisions.len() <= MAX_DECISIONS
            && response
                .deleted
                .as_ref()
                .is_none_or(|v| v.len() <= MAX_DECISIONS),
        "too many decisions"
    );
    // startup=true is authoritative; deleted entries are already absent in new.
    let mut bans = HashMap::new();
    let mut ids = std::collections::HashSet::new();
    for decision in decisions {
        ensure!(
            decision.id > 0 && ids.insert(decision.id),
            "invalid/duplicate decision ID"
        );
        if decision.kind != "ban"
            || decision.simulated
            || !matches!(decision.scope.as_str(), "Ip" | "Range")
        {
            continue;
        }
        let network: IpNet = if decision.scope == "Ip" {
            decision
                .value
                .parse::<IpAddr>()
                .context("invalid decision IP")?
                .into()
        } else {
            decision.value.parse().context("invalid decision range")?
        };
        let network = match network {
            IpNet::V6(net) if net.prefix_len() >= 96 => match net.addr().to_ipv4_mapped() {
                Some(ip) => IpNet::new(IpAddr::V4(ip), net.prefix_len() - 96)
                    .context("invalid mapped decision range")?,
                None => network,
            },
            _ => network,
        }
        .trunc();
        let duration = duration(&decision.duration)?;
        let expires = started + duration;
        let expires_at_unix_ms = checkpoint::wall_ms()
            .saturating_sub(started.elapsed().as_millis() as u64)
            .saturating_add(duration.as_millis() as u64);
        let expires_at_unix_ms = old.bans.get(&decision.id).map_or(expires_at_unix_ms, |b| {
            b.expires_at_unix_ms.min(expires_at_unix_ms)
        });
        let expires = match old.bans.get(&decision.id) {
            Some(previous) => {
                ensure!(previous.network == network, "decision identity changed");
                previous.expires.min(expires)
            }
            None => expires,
        };
        // Keep expired IDs until absent from authoritative response, preventing a
        // repeated stale duration from resurrecting the same decision.
        bans.insert(
            decision.id,
            Ban {
                network,
                expires,
                expires_at_unix_ms,
            },
        );
    }
    Ok(Snapshot {
        wall_highwater: old.wall_highwater.max(checkpoint::wall_ms()),
        bans,
        degraded: false,
        last_success: Some(Instant::now()),
    })
}
fn fetch(client: &Client, url: &Url) -> Result<Response> {
    let response = client
        .get(url.clone())
        .send()
        .map_err(|_| anyhow::anyhow!("transport"))?;
    ensure!(
        response.status().is_success(),
        "HTTP status {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    response
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read response")?;
    ensure!(bytes.len() <= MAX_RESPONSE, "response exceeds limit");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid response schema"))
}
pub struct Worker {
    stop: Option<mpsc::SyncSender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Worker {
    pub fn start(path: &Path) -> Result<(Arc<Store>, Self)> {
        let config: Config = serde_json::from_slice(&secret::read(path, 16384, false)?)
            .context("invalid CrowdSec config")?;
        ensure!(
            (1..=60).contains(&config.poll_seconds),
            "CrowdSec poll must be 1..60 seconds"
        );
        let mut url = Url::parse(&config.lapi_url).context("invalid LAPI URL")?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "LAPI URL must be an origin without credentials"
        );
        let loopback = url
            .host_str()
            .and_then(|v| v.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && loopback),
            "LAPI requires HTTPS or numeric loopback HTTP"
        );
        url.set_path("/v1/decisions/stream");
        url.set_query(Some("startup=true"));
        let key = secret::load(&config.key_file, &config.master_key_file)?;
        let mut value = HeaderValue::from_bytes(&key)
            .map_err(|_| anyhow::anyhow!("invalid CrowdSec credential"))?;
        ensure!(!key.is_empty(), "empty CrowdSec credential");
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("X-Api-Key", value);
        let mut builder = Client::builder()
            .user_agent(concat!("openwaf/v", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3));
        if let Some(path) = &config.ca_pem {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&secret::read(path, 65536, false)?)
                    .context("invalid LAPI CA")?,
            );
        }
        let client = builder.build().context("create LAPI client")?;
        let checkpoint = config
            .checkpoint_file
            .map(|path| checkpoint::Checkpoint::new(path, &config.master_key_file))
            .transpose()?;
        let (initial, checkpoint_status) =
            checkpoint.as_ref().map(|c| c.load()).unwrap_or_else(|| {
                (
                    Snapshot {
                        wall_highwater: checkpoint::wall_ms(),
                        bans: HashMap::new(),
                        degraded: true,
                        last_success: None,
                    },
                    "disabled",
                )
            });
        let store = Arc::new(Store {
            snapshot: ArcSwap::from_pointee(initial),
            checkpoint_status: std::sync::Mutex::new(checkpoint_status),
            checkpoint_recovery: checkpoint_status,
        });
        let local = store.clone();
        let (stop, receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new().name("crowdsec-sync".into()).spawn(move || {
            eprintln!("CrowdSec degraded: awaiting LAPI; checkpoint={checkpoint_status}");
            let mut wall_highwater = checkpoint::wall_ms();
            loop {
                let started = Instant::now();
                let old = local.snapshot.load_full();
                match fetch(&client, &url).and_then(|response| apply(&old, response, started)) {
                    Ok(snapshot) => {
                        if old.degraded { eprintln!("CrowdSec healthy: local snapshot synchronized"); }
                        local.snapshot.store(Arc::new(snapshot));
                    }
                    Err(_) => {
                        // Never log provider bodies, decision values, URLs or keys.
                        if !old.degraded { eprintln!("CrowdSec degraded: sync failed; last_success_age_seconds={}; original expiry retained", old.last_success.map(|v| v.elapsed().as_secs()).unwrap_or(0)); }
                        local.snapshot.store(Arc::new(Snapshot { wall_highwater: old.wall_highwater.max(checkpoint::wall_ms()), bans: old.bans.clone(), degraded: true, last_success: old.last_success }));
                    }
                }
                if let Some(checkpoint) = &checkpoint {
                    let wall = checkpoint::wall_ms();
                    let state = if wall < wall_highwater || wall < local.snapshot.load().wall_highwater { "clock_rollback" } else {
                        wall_highwater = wall;
                        if checkpoint.save(&local.snapshot.load()).is_ok() { "current" } else { "write_failed" }
                    };
                    *local.checkpoint_status.lock().unwrap_or_else(|e| e.into_inner()) = state;
                }
                match receive.recv_timeout(Duration::from_secs(config.poll_seconds)) { Err(mpsc::RecvTimeoutError::Timeout) => {}, _ => break }
            }
            eprintln!("CrowdSec shutdown: worker stopped");
        }).context("start CrowdSec worker")?;
        Ok((
            store,
            Self {
                stop: Some(stop),
                worker: Some(worker),
            },
        ))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(4);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                if worker.join().is_err() {
                    eprintln!("CrowdSec worker panicked");
                }
            } else {
                eprintln!("CrowdSec worker exceeded shutdown deadline");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn empty() -> Snapshot {
        Snapshot {
            wall_highwater: checkpoint::wall_ms(),
            bans: HashMap::new(),
            degraded: true,
            last_success: None,
        }
    }
    pub(super) fn response(id: u64, value: &str, duration: &str) -> Response {
        serde_json::from_value(serde_json::json!({"new":[{"id":id,"scope":"Range","value":value,"duration":duration,"type":"ban"}],"deleted":[]})).unwrap()
    }
    #[test]
    fn expiry_never_extends_or_resurrects() {
        let now = Instant::now();
        let first = apply(&empty(), response(1, "127.0.0.0/8", "2s"), now).unwrap();
        let later = apply(
            &first,
            response(1, "127.0.0.0/8", "2s"),
            now + Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(first.bans[&1].expires, later.bans[&1].expires);
        let store = Store {
            snapshot: ArcSwap::from_pointee(later),
            checkpoint_status: std::sync::Mutex::new("disabled"),
            checkpoint_recovery: "disabled",
        };
        assert!(store.blocked("127.0.0.1".parse().unwrap()));
        assert!(store.blocked("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!store.blocked("192.0.2.1".parse().unwrap()));
        let mapped = apply(&empty(), response(2, "::ffff:127.0.0.0/104", "2s"), now).unwrap();
        let store = Store {
            snapshot: ArcSwap::from_pointee(mapped),
            checkpoint_status: std::sync::Mutex::new("disabled"),
            checkpoint_recovery: "disabled",
        };
        assert!(store.blocked("127.0.0.1".parse().unwrap()));
    }
    #[test]
    fn authoritative_removal_new_id_and_ipv6() {
        let now = Instant::now();
        let first = apply(&empty(), response(1, "2001:db8::/32", "1h2m3.5s"), now).unwrap();
        let store = Store {
            snapshot: ArcSwap::from_pointee(first),
            checkpoint_status: std::sync::Mutex::new("disabled"),
            checkpoint_recovery: "disabled",
        };
        assert!(store.blocked("2001:db8::2".parse().unwrap()));
        let removed = apply(
            &store.snapshot.load(),
            serde_json::from_str("{\"new\":[]}").unwrap(),
            now,
        )
        .unwrap();
        assert!(removed.bans.is_empty());
        let replacement = apply(&removed, response(2, "2001:db8::/32", "1s"), now).unwrap();
        assert_eq!(replacement.bans.len(), 1);
    }
    #[test]
    fn invalid_snapshot_is_rejected_and_expiry_is_local() {
        let now = Instant::now();
        assert!(apply(&empty(), response(0, "127.0.0.0/8", "2s"), now).is_err());
        assert!(apply(&empty(), response(1, "invalid", "2s"), now).is_err());
        let first = apply(&empty(), response(1, "127.0.0.0/8", "-1s"), now).unwrap();
        let store = Store {
            snapshot: ArcSwap::from_pointee(first),
            checkpoint_status: std::sync::Mutex::new("disabled"),
            checkpoint_recovery: "disabled",
        };
        assert!(!store.blocked("127.0.0.1".parse().unwrap()));
        assert!(duration("garbage").is_err());
        assert!(duration("999999h").is_err());
        assert_eq!(
            duration("1h2m3.5s").unwrap(),
            Duration::from_millis(3723500)
        );
    }
    #[test]
    fn simulation_and_non_ban_do_not_block() {
        let mut data = response(1, "127.0.0.0/8", "2s");
        data.new.as_mut().unwrap()[0].simulated = true;
        assert!(
            apply(&empty(), data, Instant::now())
                .unwrap()
                .bans
                .is_empty()
        );
    }
    #[test]
    fn bounded_and_complete_snapshots() {
        let now = Instant::now();
        assert!(apply(&empty(), serde_json::from_str("{}").unwrap(), now).is_err());
        assert!(
            apply(
                &empty(),
                serde_json::from_str("{\"new\":null}").unwrap(),
                now
            )
            .unwrap()
            .bans
            .is_empty()
        );
        let mut duplicate = response(1, "127.0.0.0/8", "1s");
        duplicate
            .new
            .as_mut()
            .unwrap()
            .push(response(1, "127.0.0.0/8", "1s").new.unwrap().remove(0));
        assert!(apply(&empty(), duplicate, now).is_err());
        let mut oversized = response(1, "127.0.0.0/8", "1s");
        oversized.deleted = Some(vec![serde_json::Value::Null; MAX_DECISIONS + 1]);
        assert!(apply(&empty(), oversized, now).is_err());
    }
    #[test]
    fn credential_roundtrip_tamper_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let master = dir.path().join("master");
        let output = dir.path().join("sealed");
        std::fs::write(&input, b"test-runtime-key").unwrap();
        std::fs::write(&master, [42; 32]).unwrap();
        for path in [&input, &master] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        seal(&input, &output, &master).unwrap();
        assert_eq!(
            &*secret::load(&output, &master).unwrap(),
            b"test-runtime-key"
        );
        assert!(seal(&input, &output, &master).is_err());
        let mut data = std::fs::read(&output).unwrap();
        data[34] ^= 1;
        std::fs::write(&output, data).unwrap();
        assert!(secret::load(&output, &master).is_err());
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secret::load(&output, &master).is_err());
    }
}

pub mod principal;

pub mod abuse;
