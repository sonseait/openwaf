//! HTTP-01 listener: exact active (Host, token), no proxying or global WAF bypass.
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
};

pub struct Challenge {
    pub hostname: String,
    pub token: String,
    pub value: String,
}

pub type Active = Arc<ArcSwapOption<Challenge>>;

fn response<T>(request: &Request<T>, active: &Active) -> Response<Full<Bytes>> {
    let current = active.load();
    let found = current.as_ref().filter(|challenge| {
        let host = request
            .headers()
            .get(http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<http::uri::Authority>().ok());
        request.method() == http::Method::GET
            && host.is_some_and(|h| h.host().eq_ignore_ascii_case(&challenge.hostname))
            && request.uri().path_and_query().is_some_and(|path| {
                path.as_str() == format!("/.well-known/acme-challenge/{}", challenge.token)
            })
    });
    let mut response = Response::new(Full::new(Bytes::from(
        found
            .map(|challenge| challenge.value.clone())
            .unwrap_or_default(),
    )));
    *response.status_mut() = if found.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain"),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

pub struct Server {
    pub active: Active,
    stop: oneshot::Sender<()>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Server {
    pub async fn start(address: SocketAddr) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|_| anyhow::anyhow!("cannot bind HTTP-01 listener"))?;
        let active = Arc::new(ArcSwapOption::empty());
        let shared = active.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(16));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    result = connections.join_next(), if !connections.is_empty() => {
                        if result.is_some_and(|r| r.is_err()) {
                            eprintln!("HTTP-01 connection task failed");
                        }
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.map_err(|_| anyhow::anyhow!("HTTP-01 accept failed"))?;
                        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                        let shared = shared.clone();
                        connections.spawn(async move {
                            let _slot = slot;
                            let service = service_fn(move |request| {
                                let response = response(&request, &shared);
                                async { Ok::<_, Infallible>(response) }
                            });
                            let mut builder = http1::Builder::new();
                            builder.keep_alive(false).max_headers(32).max_buf_size(8192)
                                .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(3));
                            // Malformed/disconnected peers are normal protocol errors; no
                            // request paths/headers or token values are logged.
                            let _connection_result = tokio::time::timeout(Duration::from_secs(5),
                                builder.serve_connection(TokioIo::new(stream), service)).await;
                        });
                    }
                }
            }
            connections.abort_all();
            while let Some(result) = connections.join_next().await {
                if result.is_err_and(|error| !error.is_cancelled()) {
                    eprintln!("HTTP-01 connection task failed during shutdown");
                }
            }
            Ok(())
        });
        Ok(Self { active, stop, task })
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.active.store(None);
        if self.stop.send(()).is_err() {
            eprintln!("HTTP-01 listener stopped before shutdown");
        }
        self.task
            .await
            .map_err(|_| anyhow::anyhow!("HTTP-01 listener task failed"))?
    }
}

/// Remove authorization even if the order future is cancelled or returns early.
pub struct Registration(pub Active);
impl Drop for Registration {
    fn drop(&mut self) {
        self.0.store(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_active_host_token_and_get_are_served() -> anyhow::Result<()> {
        let active = Arc::new(ArcSwapOption::empty());
        let request = |host: &str, path: &str, method: &str| {
            Request::builder()
                .uri(path)
                .header("Host", host)
                .method(method)
                .body(())
        };
        let path = "/.well-known/acme-challenge/known-token";
        let valid = request("acme.example.test", path, "GET")?;
        assert_eq!(response(&valid, &active).status(), StatusCode::NOT_FOUND);
        let registration = Registration(active.clone());
        active.store(Some(Arc::new(Challenge {
            hostname: "acme.example.test".into(),
            token: "known-token".into(),
            value: "authorization".into(),
        })));
        let served = response(&request("ACME.example.test:80", path, "GET")?, &active);
        assert_eq!(served.status(), StatusCode::OK);
        use http_body_util::BodyExt;
        assert_eq!(
            served.into_body().collect().await?.to_bytes(),
            "authorization"
        );
        for (host, path, method) in [
            ("other.example.test", path, "GET"),
            ("acme.example.test", path, "POST"),
            (
                "acme.example.test",
                "/.well-known/acme-challenge/unknown",
                "GET",
            ),
            (
                "acme.example.test",
                "/.well-known/acme-challenge/known-token?x=1",
                "GET",
            ),
            ("acme.example.test", "/", "GET"),
        ] {
            assert_eq!(
                response(&request(host, path, method)?, &active).status(),
                StatusCode::NOT_FOUND
            );
        }
        drop(registration);
        assert_eq!(response(&valid, &active).status(), StatusCode::NOT_FOUND);
        Ok(())
    }
}
