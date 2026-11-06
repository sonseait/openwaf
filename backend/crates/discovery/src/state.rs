use crate::{
    docker::{self, Container},
    host::{self, Listener},
};
use arc_swap::ArcSwap;
use serde::Serialize;
use std::{
    io::{self, Write},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, watch};
const MAX_JSON: usize = 4 * 1024 * 1024;
#[derive(Clone, Serialize)]
pub struct Source<T> {
    pub items: Vec<T>,
    pub observed_at_unix_ms: Option<u64>,
    pub degraded: bool,
    pub error: Option<&'static str>,
    #[serde(skip)]
    observed: Option<Instant>,
}
impl<T: Clone> Source<T> {
    fn empty() -> Self {
        Self {
            items: Vec::new(),
            observed_at_unix_ms: None,
            degraded: true,
            error: Some("not_yet_refreshed"),
            observed: None,
        }
    }
    fn update(&self, result: anyhow::Result<Vec<T>>, error: &'static str) -> Self {
        match result {
            Ok(items) => Self {
                items,
                observed_at_unix_ms: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                ),
                degraded: false,
                error: None,
                observed: Some(Instant::now()),
            },
            Err(_) => {
                let mut previous = self.clone();
                previous.degraded = true;
                previous.error = Some(error);
                previous
            }
        }
    }
    pub fn stale(&self) -> bool {
        self.degraded
            || self
                .observed
                .is_none_or(|time| time.elapsed() > Duration::from_secs(20))
    }
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub docker: Source<Container>,
    pub host_ports: Source<Listener>,
}
pub struct Store {
    current: ArcSwap<Snapshot>,
    events: ArcSwap<crate::events::Status>,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            events: ArcSwap::from_pointee(crate::events::Status::default()),
            current: ArcSwap::from_pointee(Snapshot {
                schema_version: 1,
                docker: Source::empty(),
                host_ports: Source::empty(),
            }),
        }
    }
}
struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len() + bytes.len() > MAX_JSON {
            return Err(io::Error::other("discovery response exceeds limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn encode(value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let mut output = Limited(Vec::new());
    serde_json::to_writer(&mut output, value)?;
    output.0.push(b'\n');
    Ok(output.0)
}
pub async fn refresh_loop(
    store: Arc<Store>,
    docker_path: std::path::PathBuf,
    excluded: Vec<SocketAddr>,
    mut refresh: mpsc::Receiver<()>,
    mut stop: watch::Receiver<bool>,
) {
    let (event_tx, mut event_rx) = mpsc::channel(1);
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(crate::events::run(
        docker_path.clone(),
        store.clone(),
        event_tx,
        stop.clone(),
    ));
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased;
            _=stop.changed()=>break,
            _result=workers.join_next()=>{eprintln!("runtime component=docker_events state=failed reason=worker_stopped");break;},
            _=interval.tick()=>{},
            event=event_rx.recv()=>{
                if event.is_none(){break;}
                // Coalesce bursts; at most one event-triggered batch per second.
                tokio::select! { biased; _=stop.changed()=>break, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
                while event_rx.try_recv().is_ok() {}
            },
            command=refresh.recv()=>{if command.is_none(){break;}},
        }
        let collect = async {
            tokio::join!(
                tokio::time::timeout(Duration::from_secs(5), docker::collect(&docker_path)),
                tokio::time::timeout(Duration::from_secs(2), host::collect(&excluded))
            )
        };
        let results = tokio::select! { biased; _=stop.changed()=>break, result=collect=>result };
        let previous = store.current.load_full();
        let mut next = Snapshot {
            schema_version: 1,
            docker: previous.docker.update(
                results
                    .0
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("Docker deadline"))),
                "docker_refresh_failed",
            ),
            host_ports: previous.host_ports.update(
                results
                    .1
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("host deadline"))),
                "host_refresh_failed",
            ),
        };
        if encode(&next.docker).map_or(true, |data| data.len() > MAX_JSON - 1024) {
            next.docker = previous.docker.update(
                Err(anyhow::anyhow!("metadata size")),
                "docker_snapshot_too_large",
            );
        }
        if encode(&next.host_ports).map_or(true, |data| data.len() > MAX_JSON - 1024) {
            next.host_ports = previous.host_ports.update(
                Err(anyhow::anyhow!("metadata size")),
                "host_snapshot_too_large",
            );
        }
        if previous.docker.degraded != next.docker.degraded
            || previous.docker.error != next.docker.error
        {
            eprintln!(
                "Discovery Docker degraded={} reason={:?}",
                next.docker.degraded, next.docker.error
            );
        }
        if previous.host_ports.degraded != next.host_ports.degraded
            || previous.host_ports.error != next.host_ports.error
        {
            eprintln!(
                "Discovery host ports degraded={} reason={:?}",
                next.host_ports.degraded, next.host_ports.error
            );
        }
        store.current.store(Arc::new(next));
    }
    workers.shutdown().await;
    eprintln!("runtime component=discovery_refresh state=stopped");
}
impl Store {
    pub(crate) fn event_status(&self, connected: bool) {
        let previous = self.events.load();
        let error = if connected {
            None
        } else {
            Some("docker_events_unavailable")
        };
        if previous.connected != connected || previous.error != error {
            eprintln!(
                "runtime component=docker_events state={}",
                if connected { "recovered" } else { "degraded" }
            );
            self.events
                .store(Arc::new(crate::events::Status { connected, error }));
        }
    }
    pub fn response(&self, op: &str) -> anyhow::Result<Vec<u8>> {
        let current = self.current.load();
        match op {
            "docker" => encode(
                &serde_json::json!({"schema_version":1,"source":"docker","collection_scope":"collector_network_namespace","stale":current.docker.stale(),"snapshot":current.docker,"events":**self.events.load()}),
            ),
            "host-ports" => encode(
                &serde_json::json!({"schema_version":1,"source":"host-ports","collection_scope":"collector_network_namespace","stale":current.host_ports.stale(),"snapshot":current.host_ports}),
            ),
            _ => anyhow::bail!("unknown discovery operation"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_retains_last_success_and_timestamp() {
        let source = Source::empty().update(Ok(vec![42]), "failed");
        let failed = source.update(Err(anyhow::anyhow!("private provider error")), "failed");
        assert_eq!(failed.items, vec![42]);
        assert_eq!(source.observed_at_unix_ms, failed.observed_at_unix_ms);
        assert!(failed.stale());
        let recovered = failed.update(Ok(vec![]), "failed");
        assert!(!recovered.stale());
        assert!(recovered.items.is_empty());
    }
    #[test]
    fn output_is_bounded() {
        assert!(encode(&"x".repeat(MAX_JSON)).is_err());
        assert!(Store::default().response("exec").is_err());
    }
}
