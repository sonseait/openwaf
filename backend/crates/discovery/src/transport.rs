//! Bound wire bytes before Bollard deserializes JSON. Internal socket is private
//! and accepts only the read-only inventory endpoints; never a generic relay.
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    task::{JoinHandle, JoinSet},
};
const MAX_WIRE: usize = 4 * 1024 * 1024;
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn allowed<B>(request: &Request<B>) -> bool {
    if request.method() != hyper::Method::GET || request.uri().path().len() > 256 {
        return false;
    }
    let path = request.uri().path();
    if path == "/version" {
        return true;
    }
    let mut parts: Vec<_> = path.trim_start_matches('/').split('/').collect();
    if parts
        .first()
        .is_some_and(|version| version.starts_with('v'))
    {
        let version = parts.remove(0);
        if version.len() < 2
            || !version[1..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return false;
        }
    }
    match parts.as_slice() {
        ["containers", "json"] => true,
        ["containers", id, "json"] => {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }
        _ => false,
    }
}
fn failure() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(b"{}")));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
}
async fn forward(request: Request<Incoming>, path: &Path) -> Result<Response<Full<Bytes>>> {
    anyhow::ensure!(allowed(&request), "Docker operation forbidden");
    let stream = UnixStream::connect(path)
        .await
        .context("connect Docker socket")?;
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_headers(64)
        .max_buf_size(16 * 1024)
        .handshake(TokioIo::new(stream))
        .await?;
    let _driver = Driver(tokio::spawn(async move {
        if connection.await.is_err() { /* caller receives transport/body error */ }
    }));
    let uri = request
        .uri()
        .path_and_query()
        .context("invalid Docker request")?
        .as_str();
    let upstream = Request::builder()
        .method("GET")
        .uri(uri)
        .header("Host", "localhost")
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(upstream).await?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "Docker inventory status failure"
    );
    if let Some(size) = response.headers().get(hyper::header::CONTENT_LENGTH) {
        anyhow::ensure!(
            size.to_str()?.parse::<usize>()? <= MAX_WIRE,
            "Docker response too large"
        );
    }
    // Limited covers chunked/unknown-size responses and errors before collect
    // can allocate an unbounded JSON document. Headers have a separate cap.
    let bytes = Limited::new(response.into_body(), MAX_WIRE)
        .collect()
        .await
        .map_err(|_| anyhow::anyhow!("Docker response body failed or exceeded wire limit"))?
        .to_bytes();
    Ok(Response::new(Full::new(bytes)))
}
pub(crate) struct BoundedSocket {
    task: JoinHandle<()>,
    directory: tempfile::TempDir,
}
impl BoundedSocket {
    pub fn start(engine: &Path) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("openwaf-discovery-")
            .tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(directory.path().join("engine.sock"))?;
        let engine = engine.to_path_buf();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_)=connections.join_next()=>{},
                    result=listener.accept()=>{
                        let Ok((stream,_))=result else {break;};
                        if connections.len()>=2 {drop(stream);continue;}
                        let engine=engine.clone();
                        connections.spawn(async move {
                            let service=service_fn(move |request| {
                                let engine=engine.clone();
                                async move {
                                    let response=match tokio::time::timeout(Duration::from_secs(2),forward(request,&engine)).await {Ok(Ok(value))=>value,_=>failure()};
                                    Ok::<_,Infallible>(response)
                                }
                            });
                            // Per-batch lifetime is also bounded by refresh_loop.
                            let _=hyper::server::conn::http1::Builder::new().max_headers(64).max_buf_size(16*1024).serve_connection(TokioIo::new(stream),service).await;
                        });
                    },
                }
            }
        });
        Ok(Self { task, directory })
    }
    pub fn path(&self) -> PathBuf {
        self.directory.path().join("engine.sock")
    }
}
impl Drop for BoundedSocket {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_only_allows_inventory_gets() {
        for uri in [
            "/version",
            "/containers/json?all=true",
            "/v1.49/containers/abc123/json",
        ] {
            assert!(allowed(&Request::builder().uri(uri).body(()).unwrap()));
        }
        for uri in [
            "/containers/abc/start",
            "/exec/abc/json",
            "/images/json",
            "/v1.49/containers/abc/exec",
        ] {
            assert!(!allowed(&Request::builder().uri(uri).body(()).unwrap()));
        }
        assert!(!allowed(
            &Request::builder()
                .method("POST")
                .uri("/containers/json")
                .body(())
                .unwrap()
        ));
    }
}
