//! A deadline owns the entire Pingora future, including stalled downstream writes.
//! No detached timer/task: expiry drops both streams and the request context. Native
//! WAF work retains its own worker-owned admission until native cleanup completes.
use async_trait::async_trait;
use pingora::{
    apps::{HttpServerApp, ReusedHttpStream, ServerApp},
    protocols::{ALPN, Stream, http::ServerSession},
    proxy::{HttpProxy, ProxyHttp},
    server::ShutdownWatch,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, watch},
    time::Instant,
};

tokio::task_local! {
    static OUTCOME: Arc<AtomicU8>;
    static HEADER: std::cell::RefCell<Option<openwaf_gateway::admission::Permit>>;
    static DEADLINE: watch::Sender<Instant>;
    static ENDPOINT: watch::Sender<Option<watch::Receiver<u64>>>;
}

pub fn outcome() -> Arc<AtomicU8> {
    OUTCOME.try_with(Arc::clone).unwrap_or_default()
}
pub fn reason(state: &AtomicU8) -> &'static str {
    match state.load(Ordering::Acquire) {
        1 => "absolute_timeout",
        2 => "force_disconnect",
        _ => "cancelled",
    }
}

/// Called once after validated routing. Client headers cannot opt out of expiry.
pub fn admitted(total: Duration) -> pingora::Result<()> {
    let _ = HEADER.try_with(|permit| permit.borrow_mut().take());
    DEADLINE
        .try_with(|deadline| deadline.send_replace(Instant::now() + total))
        .map(|_| ())
        .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))
}

/// Register cancellation for this HTTP request/stream only.
pub fn endpoint(receiver: watch::Receiver<u64>) {
    let _ = ENDPOINT.try_with(|sender| sender.send_replace(Some(receiver)));
}
async fn cancelled(receiver: &mut watch::Receiver<Option<watch::Receiver<u64>>>) {
    loop {
        let current = receiver.borrow_and_update().clone();
        if let Some(mut endpoint) = current {
            tokio::select! { _=endpoint.changed()=>return, _=receiver.changed()=>{} }
        } else if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub struct Transport<G: ProxyHttp> {
    pub proxy: Arc<HttpProxy<G>>,
    pub telemetry: Arc<openwaf_telemetry::Hub>,
    pub admission: Arc<openwaf_gateway::admission::Node>,
}

struct Bounded<G: ProxyHttp> {
    proxy: Arc<HttpProxy<G>>,
    first_stream: Option<Arc<Notify>>,
    admission: Arc<openwaf_gateway::admission::Node>,
}

/// Pingora's per-request callback starts after H2 preface/HEADERS parsing.
/// Bound that initial gap as well, without replacing its H2 accept/drain loop.
#[async_trait]
impl<G> ServerApp for Transport<G>
where
    G: ProxyHttp + Send + Sync + 'static,
    G::CTX: Send + Sync,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let _connection = self.telemetry.connection();
        let first_stream =
            matches!(stream.selected_alpn_proto(), Some(ALPN::H2)).then(|| Arc::new(Notify::new()));
        let app = Arc::new(Bounded {
            proxy: self.proxy.clone(),
            first_stream: first_stream.clone(),
            admission: self.admission.clone(),
        });
        let processing = app.process_new(stream, shutdown);
        tokio::pin!(processing);
        if let Some(first_stream) = first_stream {
            let mut stopping = shutdown.clone();
            if *stopping.borrow() {
                return None;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => return None,
                _ = stopping.changed() => return None,
                _ = first_stream.notified() => {},
                result = &mut processing => return result,
            }
        }
        processing.await
    }

    async fn cleanup(&self) {
        self.proxy.http_cleanup().await;
    }
}

/// Marker persisted only after a complete, reusable HTTP/1 request.
pub struct Reused;

#[async_trait]
impl<G> HttpServerApp for Bounded<G>
where
    G: ProxyHttp + Send + Sync + 'static,
    G::CTX: Send + Sync,
{
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        let header = self
            .admission
            .headers
            .enter(self.admission.budgets.headers)?;
        if let Some(first_stream) = &self.first_stream {
            first_stream.notify_one();
        }
        // Idle reused connections need a separate budget from fresh connections.
        // Both budgets also bound trickling headers; neither resets per byte.
        // Pingora pre-sets keepalive even on fresh sessions. Its presence alone
        // cannot distinguish a new connection from a reusable completed request.
        let previous = session.take_connection_user_context();
        let reused = previous.as_ref().is_some_and(|ctx| ctx.is::<Reused>());
        session.set_connection_user_context(previous);
        let header_seconds = match (reused, session.get_keepalive()) {
            (true, Some(0)) => 30,
            (true, Some(seconds)) => seconds.min(30),
            _ => 5,
        };
        let (sender, mut receiver) =
            watch::channel(Instant::now() + Duration::from_secs(header_seconds));
        let proxy = self.proxy.process_new_http(session, shutdown);
        let (endpoint_sender, mut endpoint_receiver) = watch::channel(None);
        let outcome = Arc::new(AtomicU8::new(0));
        OUTCOME.scope(outcome.clone(), HEADER
            .scope(
                std::cell::RefCell::new(Some(header)),
                DEADLINE.scope(
                    sender,
                    ENDPOINT.scope(endpoint_sender, async {
                        tokio::pin!(proxy);
                        loop {
                            let expires = *receiver.borrow_and_update();
                            tokio::select! {
                                biased;
                                _ = cancelled(&mut endpoint_receiver) => { outcome.store(2, Ordering::Release); return None; },
                                _ = tokio::time::sleep_until(expires) => {
                                    // Admission may have updated the watch in the same
                                    // poll that this earlier header timer became ready.
                                    if *receiver.borrow() <= Instant::now() { outcome.store(1, Ordering::Release); return None; }
                                },
                                result = &mut proxy => return result,
                                result = receiver.changed() => {
                                    if result.is_err() { return None; }
                                }
                            }
                        }
                    }),
                ),
            )
            ).await
    }

    async fn http_cleanup(&self) {
        self.proxy.http_cleanup().await;
    }

    fn server_options(&self) -> Option<&pingora::apps::HttpServerOptions> {
        self.proxy.server_options()
    }

    fn h2_options(&self) -> Option<pingora::protocols::http::v2::server::H2Options> {
        self.proxy.h2_options()
    }
}
