//! Separate, read-only Docker NDJSON stream. Inventory remains Bollard-backed.
//! Reconnect always requests a full inventory; events are hints, not state.
use crate::state::Store;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    net::UnixStream,
    sync::{mpsc, watch},
    task::JoinHandle,
};
const MAX_LINE: usize = 64 * 1024;
#[derive(Clone, Serialize)]
pub(crate) struct Status {
    pub connected: bool,
    pub error: Option<&'static str>,
}
impl Default for Status {
    fn default() -> Self {
        Self {
            connected: false,
            error: Some("not_yet_connected"),
        }
    }
}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[derive(Deserialize)]
struct Event {
    #[serde(rename = "Type")]
    kind: String,
}
fn line(buffer: &mut Vec<u8>, byte: u8) -> anyhow::Result<bool> {
    if byte == b'\n' {
        let event: Event = serde_json::from_slice(buffer)?;
        buffer.clear();
        return Ok(event.kind == "container");
    }
    anyhow::ensure!(buffer.len() < MAX_LINE, "Docker event exceeds limit");
    buffer.push(byte);
    Ok(false)
}
async fn stream(path: &Path, store: &Store, refresh: &mpsc::Sender<()>) -> anyhow::Result<()> {
    let (mut sender, connection) = tokio::time::timeout(Duration::from_secs(2), async {
        let socket = UnixStream::connect(path).await?;
        hyper::client::conn::http1::Builder::new()
            .max_headers(64)
            .max_buf_size(16 * 1024)
            .handshake(TokioIo::new(socket))
            .await
            .map_err(anyhow::Error::from)
    })
    .await??;
    let _driver = Driver(tokio::spawn(async move {
        if connection.await.is_err() { /* body consumer observes failure */ }
    }));
    let request = Request::builder()
        .method("GET")
        .uri("/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D")
        .header("Host", "localhost")
        .body(Empty::<Bytes>::new())?;
    let response =
        tokio::time::timeout(Duration::from_secs(2), sender.send_request(request)).await??;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "Docker event status failure"
    );
    store.event_status(true);
    notify(refresh)?; // resync after every connect, covering disconnected gaps
    let mut body = response.into_body();
    let mut pending = Vec::new();
    // An idle healthy stream has no deadline: Docker provides no heartbeat.
    // Cancellation drops both body and owned HTTP connection driver.
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            for byte in data {
                if line(&mut pending, byte)? {
                    notify(refresh)?;
                }
            }
        }
        // Keep shutdown responsive even under a continuous event flood.
        tokio::task::yield_now().await;
    }
    anyhow::bail!("Docker event stream ended")
}
fn notify(refresh: &mpsc::Sender<()>) -> anyhow::Result<()> {
    match refresh.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
        Err(mpsc::error::TrySendError::Closed(_)) => anyhow::bail!("refresh worker stopped"),
    }
}
pub(crate) async fn run(
    path: std::path::PathBuf,
    store: Arc<Store>,
    refresh: mpsc::Sender<()>,
    mut stop: watch::Receiver<bool>,
) {
    let mut retry = 1;
    loop {
        tokio::select! { biased;
            _=stop.changed()=>break,
            result=stream(&path,&store,&refresh)=>{
                if result.is_err() { store.event_status(false); }
            },
        }
        tokio::select! { biased;
            _=stop.changed()=>break,
            _=tokio::time::sleep(Duration::from_secs(retry))=>{},
        }
        retry = (retry * 2).min(10);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_lines_are_bounded_and_validated() {
        let mut buffer = Vec::new();
        for byte in b"{\"Type\":\"container\",\"Action\":\"start\"}" {
            assert!(!line(&mut buffer, *byte).unwrap());
        }
        assert!(line(&mut buffer, b'\n').unwrap());
        assert!(buffer.is_empty());
        assert!(line(&mut buffer, b'\n').is_err());
        let mut buffer = vec![b'x'; MAX_LINE];
        assert!(line(&mut buffer, b'x').is_err());
    }
}
