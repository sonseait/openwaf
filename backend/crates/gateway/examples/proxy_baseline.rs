//! Loopback-only benchmark reference: Pingora transport with no OpenWAF filters,
//! WAF engines, body buffering, admin runtime or telemetry. Never deploy this.
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use pingora::{
    proxy::{ProxyHttp, Session},
    server::{RunArgs, Server},
    upstreams::peer::HttpPeer,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

struct Baseline(SocketAddr);
#[async_trait]
impl ProxyHttp for Baseline {
    type CTX = ();
    fn new_ctx(&self) {}
    async fn upstream_peer(&self, _: &mut Session, _: &mut ()) -> pingora::Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(self.0, false, String::new());
        peer.options.connection_timeout = Some(Duration::from_secs(3));
        peer.options.read_timeout = Some(Duration::from_secs(10));
        peer.options.write_timeout = Some(Duration::from_secs(10));
        Ok(Box::new(peer))
    }
}
fn main() -> Result<()> {
    let listen: SocketAddr = std::env::var("OPENWAF_LISTEN")?.parse()?;
    let upstream: SocketAddr = std::env::var("OPENWAF_UPSTREAM")?.parse()?;
    ensure!(
        listen.ip().is_loopback()
            && upstream.ip().is_loopback()
            && listen.port() != 0
            && upstream.port() != 0
            && listen != upstream,
        "benchmark reference requires distinct loopback endpoints"
    );
    let mut server = Server::new(None)?;
    let config = Arc::get_mut(&mut server.configuration).context("shared configuration")?;
    config.threads = 2;
    config.grace_period_seconds = Some(1);
    config.graceful_shutdown_timeout_seconds = Some(5);
    server.bootstrap();
    let mut proxy = pingora::proxy::http_proxy_service(&server.configuration, Baseline(upstream));
    proxy.add_tcp(&listen.to_string());
    server.add_service(proxy);
    server.run(RunArgs::default());
    Ok(())
}
