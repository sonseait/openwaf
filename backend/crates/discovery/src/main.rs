//! Private collector protocol v1: one bounded JSON line per Unix connection.
#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use openwaf_discovery::{Store, docker, refresh_loop};
use serde::Deserialize;
use std::{
    env, fs,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    op: String,
}
struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl SocketFile {
    fn bind(path: &Path) -> Result<(UnixListener, Self)> {
        let parent = path.parent().context("socket parent required")?;
        let metadata =
            fs::symlink_metadata(parent).context("inspect collector socket directory")?;
        ensure!(
            path.is_absolute()
                && metadata.is_dir()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == nix::unistd::geteuid().as_raw(),
            "collector socket requires an absolute path in an owned directory mode 0700"
        );
        // Never unlink existing paths, even if they look like a stale socket.
        let listener = UnixListener::bind(path)
            .context("bind private collector socket (path must not exist)")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(path)?;
        Ok((
            listener,
            Self {
                path: path.into(),
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        ))
    }
}
impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
            && let Err(_error) = fs::remove_file(&self.path)
        {
            eprintln!("runtime component=discovery_socket state=degraded reason=cleanup_failed");
        }
    }
}
async fn connection(
    mut stream: UnixStream,
    store: Arc<Store>,
    refresh: mpsc::Sender<()>,
) -> Result<()> {
    let mut input = Vec::new();
    loop {
        ensure!(input.len() < 256, "collector command exceeds limit");
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        input.push(byte);
    }
    let command: Command = serde_json::from_slice(&input).context("invalid collector command")?;
    let output = match command.op.as_str() {
        "docker" | "host-ports" => store.response(&command.op)?,
        "refresh" => {
            let queued = match refresh.try_send(()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => false,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    anyhow::bail!("refresh worker unavailable")
                }
            };
            serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"accepted":true,"queued":queued}),
            )?
        }
        _ => b"{\"error\":\"unknown_operation\"}\n".to_vec(),
    };
    stream.write_all(&output).await?;
    if !output.ends_with(b"\n") {
        stream.write_all(b"\n").await?;
    }
    stream.shutdown().await?;
    Ok(())
}
fn main() -> Result<()> {
    openwaf_env::load()?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(run())
}
async fn run() -> Result<()> {
    let path = PathBuf::from(
        env::var_os("OPENWAF_DISCOVERY_SOCKET").context("OPENWAF_DISCOVERY_SOCKET required")?,
    );
    let docker_path = PathBuf::from(
        env::var_os("OPENWAF_DOCKER_SOCKET").unwrap_or_else(|| "/var/run/docker.sock".into()),
    );
    let excluded: Vec<SocketAddr> = env::var("OPENWAF_DISCOVERY_EXCLUDE")
        .unwrap_or_default()
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|value| value.parse().context("invalid excluded listener"))
        .collect::<Result<_>>()?;
    ensure!(excluded.len() <= 128, "too many excluded listeners");
    docker::validate_socket_path(&docker_path)?;
    let (listener, _socket) = SocketFile::bind(&path)?;
    let store = Arc::new(Store::default());
    let (refresh_tx, refresh_rx) = mpsc::channel(1);
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut worker = tokio::spawn(refresh_loop(
        store.clone(),
        docker_path,
        excluded,
        refresh_rx,
        stop_rx,
    ));
    let permits = Arc::new(Semaphore::new(8));
    let mut connections = JoinSet::new();
    let rejected = Arc::new(AtomicU64::new(0));
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!(
        "runtime component=discovery_collector state=started protocol=1 refresh_seconds=10 max_clients=8"
    );
    let result: Result<()> = loop {
        tokio::select! {
            _=terminate.recv()=>break Ok(()),
            signal=tokio::signal::ctrl_c()=>break signal.context("collector signal handler"),
            result=&mut worker=>break match result {Ok(())=>Err(anyhow::anyhow!("discovery worker stopped unexpectedly")),Err(_)=>Err(anyhow::anyhow!("discovery worker failed"))},
            Some(result)=connections.join_next()=>{if result.is_err(){eprintln!("runtime component=discovery_connection state=failed reason=task_failed");}},
            accepted=listener.accept()=>{
                let (stream,_)=match accepted {Ok(value)=>value,Err(_)=>break Err(anyhow::anyhow!("collector accept failed"))};
                if connections.len() >= 8 {drop(stream); continue;}
                let permit=match permits.clone().try_acquire_owned(){Ok(permit)=>permit,Err(_)=>{drop(stream);continue;}};
                let local=store.clone();let refresh=refresh_tx.clone();let failures=rejected.clone();
                connections.spawn(async move {
                    let _permit=permit;
                    // Both slow readers and slow consumers are bounded; no raw
                    // command, provider response or container environment logged.
                    if !matches!(tokio::time::timeout(Duration::from_secs(2),connection(stream,local,refresh)).await,Ok(Ok(()))) {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                });
            },
        }
    };
    if stop_tx.send(true).is_err() {
        eprintln!(
            "runtime component=discovery_collector state=degraded reason=worker_unavailable_at_shutdown"
        );
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if !worker.is_finished() {
        match tokio::time::timeout(Duration::from_secs(2), &mut worker).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => eprintln!(
                "runtime component=discovery_collector state=failed reason=worker_failed_at_shutdown"
            ),
            Err(_) => {
                worker.abort();
                eprintln!(
                    "runtime component=discovery_collector state=degraded reason=shutdown_deadline"
                );
            }
        }
    }
    eprintln!(
        "Discovery collector shutdown: rejected_clients={}",
        rejected.load(Ordering::Relaxed)
    );
    result
}
