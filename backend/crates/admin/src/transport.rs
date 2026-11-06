//! Bound accepted connections before Axum spawns a connection task. A connection
//! has a 30-second lifetime; an authenticated ZIP upload may extend it to 215s.
use axum::{
    body::Body,
    extract::connect_info::Connected,
    http::{HeaderValue, Version, header},
    response::Response,
    serve::{IncomingStream, Listener},
};
use futures_util::StreamExt;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Sleep,
};

pub struct BoundedListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}
impl BoundedListener {
    pub fn new(inner: TcpListener) -> Self {
        Self {
            inner,
            slots: Arc::new(Semaphore::new(128)),
        }
    }
}
pub struct Connection {
    inner: TcpStream,
    _slot: OwnedSemaphorePermit,
    deadline: Pin<Box<Sleep>>,
    upload: Arc<AtomicBool>,
    extended: bool,
}
#[derive(Clone, Copy)]
pub struct Peer(pub SocketAddr);
#[derive(Clone)]
pub struct ConnectionInfo {
    pub peer: Peer,
    upload: Arc<AtomicBool>,
    deadline: tokio::time::Instant,
}
impl ConnectionInfo {
    pub(crate) fn extend_upload(&self) {
        self.upload.store(true, Ordering::Release);
    }

    /// Finish the HTTP body before the socket budget expires. Use the accepted
    /// connection's deadline, since a pooled connection may already be old when
    /// an SSE request starts. The hard I/O deadline remains the slow-reader bound.
    pub(crate) fn finish_event_stream(&self, response: Response, version: Version) -> Response {
        if !response.status().is_success()
            || !response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value == "text/event-stream")
        {
            return response;
        }
        let deadline = self.deadline - Duration::from_secs(2);
        let (mut parts, body) = response.into_parts();
        // Do not return this almost-expired socket to the edge's HTTP/1 pool.
        // HTTP/2 forbids Connection; each stream still ends with clean framing.
        if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
            parts
                .headers
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        let stream = body
            .into_data_stream()
            .take_until(tokio::time::sleep_until(deadline));
        Response::from_parts(parts, Body::from_stream(stream))
    }
}
impl Connected<IncomingStream<'_, BoundedListener>> for ConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, BoundedListener>) -> Self {
        Self {
            peer: Peer(*stream.remote_addr()),
            upload: stream.io().upload.clone(),
            deadline: stream.io().deadline.deadline(),
        }
    }
}
impl Connection {
    fn extend(&mut self) {
        if !self.extended && self.upload.load(Ordering::Acquire) {
            // Only set by the guard after session/Origin/CSRF validation. One finite
            // extension per connection; incomplete/unauthenticated requests stay 30s.
            self.extended = true;
            self.deadline
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_secs(185));
        }
    }
}
impl Connected<IncomingStream<'_, BoundedListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, BoundedListener>) -> Self {
        Self(*stream.remote_addr())
    }
}
impl Listener for BoundedListener {
    type Io = Connection;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Connection, SocketAddr) {
        loop {
            let (inner, addr) = Listener::accept(&mut self.inner).await;
            if let Ok(slot) = self.slots.clone().try_acquire_owned() {
                return (
                    Connection {
                        inner,
                        _slot: slot,
                        deadline: Box::pin(tokio::time::sleep(Duration::from_secs(30))),
                        upload: Arc::new(AtomicBool::new(false)),
                        extended: false,
                    },
                    addr,
                );
            }
            // Close overflow sockets without spawning another task.
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.extend();
        if std::future::Future::poll(this.deadline.as_mut(), cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "admin connection deadline",
            )));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.extend();
        if std::future::Future::poll(this.deadline.as_mut(), cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "admin connection deadline",
            )));
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.extend();
        if std::future::Future::poll(this.deadline.as_mut(), cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "admin connection deadline",
            )));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn sse_on_pooled_socket_finishes_cleanly_and_api_reconnects() -> anyhow::Result<()> {
        use axum::{
            Router,
            extract::ConnectInfo,
            response::{Sse, sse::Event},
            routing::get,
        };
        use std::{convert::Infallible, future::IntoFuture};

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let listener = BoundedListener::new(listener);
        let slots = listener.slots.clone();
        let app = Router::new()
            .route(
                "/ready",
                get(
                    |ConnectInfo(info): ConnectInfo<ConnectionInfo>| async move {
                        info.peer.0.port().to_string()
                    },
                ),
            )
            .route(
                "/events",
                get(
                    |ConnectInfo(mut info): ConnectInfo<ConnectionInfo>| async move {
                        // Advance the accepted socket's age for this regression without
                        // waiting 28 seconds. Its original accept time is preserved.
                        info.deadline -= Duration::from_millis(27800);
                        let events = futures_util::stream::iter([Ok::<_, Infallible>(
                            Event::default().data("ready"),
                        )])
                        .chain(futures_util::stream::pending());
                        let response =
                            axum::response::IntoResponse::into_response(Sse::new(events));
                        let mut response = info.finish_event_stream(response, Version::HTTP_11);
                        response
                            .headers_mut()
                            .insert("x-test-peer", HeaderValue::from(info.peer.0.port()));
                        response
                    },
                ),
            );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<ConnectionInfo>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .into_future(),
        );
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()?;
        let first = client.get(format!("http://{address}/ready")).send().await?;
        assert_eq!(first.status(), 200);
        assert!(!first.headers().contains_key(header::CONNECTION));
        let first_peer = first.text().await?;
        let response = client
            .get(format!("http://{address}/events"))
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-test-peer"], first_peer);
        assert_eq!(response.headers()[header::CONNECTION], "close");
        // Reqwest rejects incomplete chunked bodies. A clean SSE end must
        // deliver the terminal chunk, rather than close the socket mid-body.
        assert_eq!(response.bytes().await?.as_ref(), b"data: ready\n\n");
        let next = client.get(format!("http://{address}/ready")).send().await?;
        assert_eq!(next.status(), 200);
        assert_ne!(next.text().await?, first_peer);
        drop(client);
        stop.send(()).expect("server shutdown");
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        assert_eq!(slots.available_permits(), 128);
        Ok(())
    }

    #[tokio::test]
    async fn expired_sse_budget_finishes_immediately_without_h2_connection_header() {
        use axum::response::{IntoResponse, Sse, sse::Event};
        let info = ConnectionInfo {
            peer: Peer("127.0.0.1:1234".parse().expect("peer")),
            upload: Arc::new(AtomicBool::new(false)),
            deadline: tokio::time::Instant::now(),
        };
        let events = futures_util::stream::pending::<Result<Event, std::convert::Infallible>>();
        let response = info.finish_event_stream(Sse::new(events).into_response(), Version::HTTP_2);
        assert!(!response.headers().contains_key(header::CONNECTION));
        let body = tokio::time::timeout(
            Duration::from_millis(100),
            axum::body::to_bytes(response.into_body(), 1024),
        )
        .await
        .expect("immediate clean end")
        .expect("body");
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn slow_reader_cannot_write_past_connection_deadline() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut listener = BoundedListener::new(listener);
        let _client = TcpStream::connect(addr).await?;
        let (mut accepted, _) = listener.accept().await;
        accepted.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(
            accepted
                .write(b"event")
                .await
                .expect_err("expired write")
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            accepted.flush().await.expect_err("expired flush").kind(),
            io::ErrorKind::TimedOut
        );
        Ok(())
    }
    #[tokio::test]
    async fn incomplete_headers_expire_and_release_connection_slot() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut listener = BoundedListener {
            inner: listener,
            slots: Arc::new(Semaphore::new(1)),
        };
        let _client = TcpStream::connect(addr).await?;
        let (mut accepted, _) = listener.accept().await;
        assert_eq!(listener.slots.available_permits(), 0);
        accepted.deadline = Box::pin(tokio::time::sleep(Duration::from_millis(10)));
        let mut byte = [0];
        let result = accepted.read(&mut byte).await;
        assert!(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut));
        drop(accepted);
        assert_eq!(listener.slots.available_permits(), 1);
        Ok(())
    }
    #[tokio::test]
    async fn only_authenticated_upload_budget_can_extend_once() -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut listener = BoundedListener::new(listener);
        let _client = TcpStream::connect(address).await?;
        let (mut connection, peer) = listener.accept().await;
        let info = ConnectionInfo {
            peer: Peer(peer),
            upload: connection.upload.clone(),
            deadline: connection.deadline.deadline(),
        };
        connection.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        info.extend_upload();
        assert_eq!(connection.write(b"upload").await?, 6);
        assert!(connection.extended);
        connection.deadline = Box::pin(tokio::time::sleep(Duration::ZERO));
        tokio::time::sleep(Duration::from_millis(2)).await;
        info.extend_upload();
        assert_eq!(
            connection
                .write(b"late")
                .await
                .expect_err("one extension only")
                .kind(),
            io::ErrorKind::TimedOut
        );
        Ok(())
    }
    #[tokio::test]
    async fn overflow_closes_socket_and_cancellation_preserves_admission() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let mut listener = BoundedListener {
            inner: listener,
            slots: Arc::new(Semaphore::new(1)),
        };
        let _first = TcpStream::connect(addr).await?;
        let (accepted, _) = listener.accept().await;
        let mut overflow = TcpStream::connect(addr).await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let mut byte = [0];
        assert_eq!(overflow.read(&mut byte).await?, 0);
        drop(accepted);
        let _next = TcpStream::connect(addr).await?;
        let (accepted, _) = listener.accept().await;
        assert_eq!(listener.slots.available_permits(), 0);
        drop(accepted);
        assert_eq!(listener.slots.available_permits(), 1);
        Ok(())
    }
}
