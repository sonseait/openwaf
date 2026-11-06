//! Admission before spawning handshake tasks. A connection owns its permit through
//! TLS, H1 keepalive and every multiplexed H2 stream. JoinSet owns cancellation.
use crate::lifetime::Transport;
use async_trait::async_trait;
use openwaf_gateway::admission::Node;
use pingora::{
    apps::ServerApp,
    listeners::Listeners,
    proxy::ProxyHttp,
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use std::{sync::Arc, time::Duration};
use tokio::task::JoinSet;

pub struct Listener<G: ProxyHttp> {
    pub endpoints: Listeners,
    pub app: Arc<Transport<G>>,
    pub admission: Arc<Node>,
}
#[async_trait]
impl<G> Service for Listener<G>
where
    G: ProxyHttp + Send + Sync + 'static,
    G::CTX: Send + Sync,
{
    async fn start_service(
        &mut self,
        fds: Option<ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        let endpoints = match self.endpoints.build(fds).await {
            Ok(endpoints) => endpoints,
            Err(error) => {
                eprintln!("OpenWAF listener initialization failed: {error}");
                return;
            }
        };
        let mut acceptors = JoinSet::new();
        for mut stack in endpoints {
            let app = self.app.clone();
            let admission = self.admission.clone();
            let mut stopping = shutdown.clone();
            acceptors.spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = stopping.changed() => break,
                        result = connections.join_next(), if !connections.is_empty() => {
                            if result.is_some_and(|r| r.is_err()) { eprintln!("OpenWAF connection task failed"); }
                        },
                        accepted = stack.accept() => {
                            let io = match accepted {
                                Ok(io) => io,
                                Err(_) => { tokio::time::sleep(Duration::from_millis(50)).await; continue; }
                            };
                            let Some(connection) = admission.connections.enter(admission.budgets.connections) else { continue; };
                            let Some(handshake) = admission.handshakes.enter(admission.budgets.handshakes) else { continue; };
                            let app = app.clone();
                            let mut stop = stopping.clone();
                            connections.spawn(async move {
                                let _connection = connection;
                                let io = tokio::select! {
                                    _ = stop.changed() => return,
                                    result = tokio::time::timeout(Duration::from_secs(5), io.handshake()) => {
                                        match result { Ok(Ok(io)) => io, _ => return }
                                    }
                                };
                                drop(handshake);
                                let mut event = Some(io);
                                while let Some(io) = event {
                                    event = app.process_new(io, &stop).await;
                                }
                            });
                        }
                    }
                }
                stack.cleanup();
                // Let Pingora drain requests. After the finite grace period,
                // abort per-connection owners; native workers retain native jobs.
                let drain = async { while connections.join_next().await.is_some() {} };
                if tokio::time::timeout(Duration::from_secs(5), drain).await.is_err() {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                }
            });
        }
        tokio::select! {
            _ = shutdown.changed() => {},
            _ = acceptors.join_next() => {},
        }
        while acceptors.join_next().await.is_some() {}
        self.endpoints.cleanup();
        self.app.cleanup().await;
    }
    fn name(&self) -> &str {
        "OpenWAF bounded listener"
    }
    fn listen_addresses(&self) -> Option<Vec<String>> {
        Some(self.endpoints.addresses())
    }
}
