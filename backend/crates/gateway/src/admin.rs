//! Owned control-plane runtime; PostgreSQL/Axum never run on Pingora's runtime.
use anyhow::{Context, Result, ensure};
use openwaf_admin::{
    App, connect,
    crypto::MasterKey,
    router,
    transport::{BoundedListener, ConnectionInfo},
};
use openwaf_config::{Context as ConfigContext, Store};
use std::{
    collections::BTreeSet,
    env,
    future::IntoFuture,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

pub struct Diagnostics {
    pub principal_limiter: Arc<openwaf_security::principal::Limiter>,
    pub simulator: Arc<crate::simulator::Service>,
    pub abuse: Arc<openwaf_security::abuse::Service>,
    pub body_recorder: Arc<openwaf_storage::bodies::Service>,
    pub ddos: Arc<openwaf_security::ddos::Protection>,
    pub replay: Arc<crate::replay::Budget>,
    pub retry_slots: Arc<openwaf_gateway::admission::Gate>,
    pub compiler: Arc<crate::waf_policy::Client>,
    pub global_rate_limiter: Arc<openwaf_security::traffic::Limiter>,
    pub rate_limiter: Arc<openwaf_security::traffic::Limiter>,
    pub admission: Arc<openwaf_gateway::admission::Node>,
    pub shadow: Arc<crate::shadow::Service>,
    pub pool: Arc<openwaf_waf::Pool>,
    pub tls: Option<Arc<openwaf_tls::Store>>,
    pub crowdsec: Option<Arc<openwaf_security::Store>>,
}

pub struct Managed {
    pub store: Arc<Store>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Managed {
    pub fn start(
        gateway: SocketAddr,
        preparer: Arc<dyn openwaf_admin::config::Preparer>,
        health_requests: Arc<openwaf_config::requests::Requests>,
        telemetry: Arc<openwaf_telemetry::Hub>,
        telemetry_receiver: tokio::sync::mpsc::Receiver<openwaf_telemetry::Log>,
        diagnostics: Diagnostics,
    ) -> Result<Option<Self>> {
        let url = match env::var("OPENWAF_DATABASE_URL") {
            Ok(url) => url,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(_) => anyhow::bail!("invalid admin database environment"),
        };
        let master = env::var("OPENWAF_ADMIN_MASTER_KEY_FILE")
            .context("managed gateway requires admin master key file")?;
        let origin = env::var("OPENWAF_ADMIN_ORIGIN")
            .context("managed gateway requires admin HTTPS origin")?;
        let listener: SocketAddr = env::var("OPENWAF_ADMIN_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:9090".into())
            .parse()
            .context("invalid admin listener")?;
        ensure!(
            listener.ip().is_loopback() && listener.port() != 0 && listener != gateway,
            "admin listener must be distinct loopback address"
        );
        let discover = env::var("OPENWAF_DISCOVER_LOCAL_IPS").unwrap_or_else(|_| "false".into());
        ensure!(
            matches!(discover.as_str(), "true" | "false"),
            "OPENWAF_DISCOVER_LOCAL_IPS must be true or false"
        );
        let local_ips = listener_ips(
            &env::var("OPENWAF_LOCAL_IPS").unwrap_or_default(),
            discover == "true",
        )?;
        ensure!(
            local_ips.len() <= 128 && (!gateway.ip().is_unspecified() || !local_ips.is_empty()),
            "wildcard gateway listener requires OPENWAF_LOCAL_IPS inventory (maximum 128)"
        );
        let context = ConfigContext {
            // Axum is an intentional terminal upstream for the dashboard/API.
            // It never forwards traffic, so only the Pingora socket is a loop.
            listeners: vec![gateway],
            local_ips,
        };
        let (send, ready) = mpsc::sync_channel(1);
        let (stop, stopped) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("admin-control-plane".into())
            .spawn(move || {
                let result = (|| -> Result<()> {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .max_blocking_threads(2)
                        .enable_all()
                        .build()?;
                    let result = runtime.block_on(async {
                        let init = async {
                            let key = MasterKey::load(Path::new(&master))?;
                            let db = connect(&url).await?;
                            let mut app = App::managed_prepared(
                                db.clone(),
                                key,
                                origin,
                                context.clone(),
                                Some(preparer),
                            )
                            .await?;
                            openwaf_admin::statistics::restore(&db, &telemetry).await?;
                            let mut telemetry_service = openwaf_admin::telemetry::Service::new(telemetry.clone());
                            if let Some(path) = env::var_os("OPENWAF_METRICS_TOKEN_FILE") {
                                let token = openwaf_admin::crypto::private_file(Path::new(&path), 128)?;
                                ensure!(token.len() == 64 && token.iter().all(u8::is_ascii_hexdigit), "metrics token requires exactly 64 hex bytes");
                                telemetry_service.scrape_token = Some(token);
                            }
                            Arc::get_mut(&mut app).context("admin already shared")?.simulator=Some(diagnostics.simulator.clone());
                            Arc::get_mut(&mut app).context("admin already shared")?.abuse=diagnostics.abuse.clone();
                            Arc::get_mut(&mut app).context("admin already shared")?.application_tls=diagnostics.tls.clone();
                            Arc::get_mut(&mut app).context("admin already shared")?.shadow=Some(diagnostics.shadow.clone());
                            telemetry_service.bodies = Some(diagnostics.body_recorder.clone());
                            let body_history = diagnostics.body_recorder.clone();
                            let diagnostic_store = app.config.as_ref().context("missing snapshot")?.store.clone();
                            let diagnostic_health = health_requests.clone();
                            telemetry_service.diagnostics = Some(Arc::new(move || {
                                let snapshot = diagnostic_store.load();
                                let mut queued = 0; let mut executing = 0; let mut rejected = 0;let mut healthy=true;let mut failed=0;let mut seen=std::collections::BTreeSet::new();
                                let pools = snapshot.prepared.as_ref().and_then(|p| p.downcast_ref::<crate::waf_policy::Prepared>());
                                if let Some(pools) = pools {
                                    for pool in pools.routes.iter().flatten() {if !seen.insert(Arc::as_ptr(pool) as usize){continue;} healthy&=pool.healthy();let stats = pool.stats(); queued += stats.queued; executing += stats.executing; rejected += stats.rejected;failed+=stats.failed; }
                                } else {healthy=diagnostics.pool.healthy(); let stats = diagnostics.pool.stats();failed=stats.failed; queued = stats.queued; executing = stats.executing; rejected = stats.rejected; }
                                let mut registry=diagnostics.compiler.stats();
                                registry["active_pools"]=serde_json::json!(seen.len());
                                if let Some(total)=registry["pools"].as_u64() { registry["retired_pools"]=serde_json::json!(total.saturating_sub(seen.len() as u64)); }
                                let crowdsec = diagnostics.crowdsec.as_ref().map(|s| { let h = s.health(); serde_json::json!({"degraded": h.degraded, "checkpoint_status": h.checkpoint_status, "checkpoint_degraded": matches!(h.checkpoint_status,"write_failed"|"clock_rollback"), "checkpoint_recovery": h.checkpoint_recovery, "last_success_age_ms": h.last_success_age.map(|d| d.as_millis() as u64)}) });
                                serde_json::json!({"observed_at_unix_ms": openwaf_telemetry::now_ms(), "body_recording": diagnostics.body_recorder.stats(), "config_version": snapshot.version, "admission":diagnostics.admission.snapshot(), "waf_registry":registry, "identity_rate_limit":diagnostics.principal_limiter.stats(), "detectors":diagnostics.abuse.diagnostics(openwaf_telemetry::now_ms()), "rate_limit":diagnostics.rate_limiter.stats(), "global_rate_limit": diagnostics.global_rate_limiter.stats(), "ddos": diagnostics.ddos.stats(), "health_capacity":diagnostic_health.stats(), "replay":diagnostics.replay.stats(), "retry_capacity":diagnostics.retry_slots.counts(),"retry_slots":diagnostics.retry_slots.counts().active, "waf": {"healthy":healthy,"failed_inspections":failed,"queued": queued, "executing": executing, "rejected_active_policies": rejected}, "crowdsec": crowdsec, "tls": diagnostics.tls.as_ref().map(|tls| serde_json::json!({"revision": tls.revision(), "certificates": tls.certificates()})), "upstreams": snapshot.health.status()})
                            }));
                            if let Ok(url) = env::var("OPENWAF_PROMETHEUS_URL") {
                                telemetry_service.prometheus = Some(openwaf_storage::Prometheus::new(&url)?);
                            }
                            if let Ok(url) = env::var("OPENWAF_CLICKHOUSE_URL") {
                                let credential = env::var_os("OPENWAF_CLICKHOUSE_CREDENTIAL_FILE")
                                    .map(|path| openwaf_admin::crypto::private_file(Path::new(&path), 4096))
                                    .transpose()?;
                                let credentials: Option<serde_json::Value> = credential.as_ref()
                                    .map(|bytes| serde_json::from_slice(bytes).context("invalid history credential file"))
                                    .transpose()?;
                                let user = credentials.as_ref().and_then(|v| v["user"].as_str());
                                let password = credentials.as_ref().and_then(|v| v["password"].as_str());
                                ensure!(credential.is_none() || (user.is_some() && password.is_some()), "history credential file requires user/password");
                                telemetry_service.history = Some(openwaf_storage::History::new(&url, user, password)?);
                            }
                            if let Some(history) = &telemetry_service.history {
                                body_history.history.set(history.clone()).map_err(|_| anyhow::anyhow!("body history already configured"))?;
                            }
                            Arc::get_mut(&mut app).context("admin app already shared")?.telemetry = Some(telemetry_service);
                            let ca = env::var_os("OPENWAF_UPSTREAM_CA_FILE")
                                .map(std::path::PathBuf::from);
                            let services = openwaf_gateway::discovery::Service::from_env(
                                context.clone(),
                                ca.as_deref(),
                            )?;
                            Arc::get_mut(&mut app)
                                .context("admin app already shared")?
                                .discovery = Some(Arc::new(services));
                            let listener = tokio::net::TcpListener::bind(listener)
                                .await
                                .context("bind managed Admin API")?;
                            Ok::<_, anyhow::Error>((db, app, listener))
                        };
                        let (db, app, listener) =
                            tokio::time::timeout(Duration::from_secs(15), init)
                                .await
                                .context("admin startup deadline")??;
                        let store = app
                            .config
                            .as_ref()
                            .context("missing managed snapshot")?
                            .store
                            .clone();
                        let ca =
                            env::var_os("OPENWAF_UPSTREAM_CA_FILE").map(std::path::PathBuf::from);
                        let health = Arc::new(openwaf_gateway::upstream::Service::new(
                            context.clone(),
                            ca.as_deref(),
                            health_requests.clone(),
                        )?);
                        let health_store = store.clone();
                        if send.send(Ok(store)).is_err() {
                            return Ok(());
                        }
                        let history = app.telemetry.as_ref().and_then(|s| s.history.clone());
                        let history_status = history.clone();
                        let rollup_history = history.clone();
                        let rollup_hub = telemetry.clone();
                        let history_logs = telemetry.logs.subscribe();
                        let (history_stop, history_stopped) = tokio::sync::watch::channel(false);
                        let (hub_stop, hub_stopped) = tokio::sync::watch::channel(false);
                        let rollup_stopped = history_stopped.clone();
                        let rollup_writer = async move { match rollup_history { Some(h) => h.run_rollups(rollup_hub, rollup_stopped).await, None => std::future::pending::<()>().await } };
                        let writer = async move {
                            match history {
                                Some(history) => history.run_until(history_logs, history_stopped).await,
                                None => std::future::pending::<()>().await,
                            }
                        };
                        let aggregator = telemetry.clone().run_until(telemetry_receiver, hub_stopped);
                        tokio::pin!(writer, aggregator, rollup_writer);
                        let uptime_app = app.clone();
                        let shadow=uptime_app.shadow.clone().context("missing shadow service")?;
                        let uptime_epoch = telemetry.epoch.clone();
                        let (certificate_stop,certificate_stopped)=tokio::sync::watch::channel(false);
                        let certificate_app=app.clone();
                        let mut certificates=Box::pin(async move {openwaf_admin::certificates::run(&certificate_app,certificate_stopped).await});
                        let mut certificates_done=false;
                        let mut rollup_done = false;
                        let mut writer_done = false;
                        let mut aggregator_done = false;
                        let result = tokio::select! {
                            _ = openwaf_admin::statistics::run(&db, telemetry.clone()) => Err(anyhow::anyhow!("statistics writer stopped")),
                            _ = &mut certificates => {certificates_done=true;Err(anyhow::anyhow!("certificate owner stopped"))},
                            _ = openwaf_admin::applications::run(&uptime_app) => Err(anyhow::anyhow!("applications janitor stopped")),
                            _ = shadow.run() => Err(anyhow::anyhow!("shadow service stopped")),
                            _ = openwaf_admin::abuse::run(&uptime_app) => Err(anyhow::anyhow!("incident service stopped")),
                            _ = openwaf_admin::telegram::run(&uptime_app) => Err(anyhow::anyhow!("Telegram service stopped")),
                            _ = openwaf_admin::operations::sample(&uptime_app) => Err(anyhow::anyhow!("endpoint sampler stopped")),
                            _ = uptime_app.uptime.run(&uptime_app, &uptime_epoch) => Err(anyhow::anyhow!("uptime sampler stopped")),
                            _ = &mut rollup_writer => {rollup_done = true; Err(anyhow::anyhow!("rollup writer stopped"))},
                            _ = &mut writer => { writer_done = true; Err(anyhow::anyhow!("history writer stopped")) },
                            result = serve(app.clone(), listener, stopped) => result,
                            result = health.run_with_discovery(health_store, app.discovery.clone()) => result,
                            _ = &mut aggregator => { aggregator_done = true; Err(anyhow::anyhow!("telemetry owner stopped")) },
                        };
                        certificate_stop.send_replace(true);
                        if !certificates_done {tokio::time::timeout(Duration::from_secs(30), &mut certificates).await.context("certificate shutdown deadline")?;}
                        drop(certificates);
                        hub_stop.send_replace(true);
                        if !aggregator_done {
                            tokio::time::timeout(Duration::from_secs(2), &mut aggregator).await.context("telemetry drain deadline")?;
                        }
                        history_stop.send_replace(true);
                        if let Some(history) = history_status {
                            if !rollup_done { tokio::time::timeout(Duration::from_secs(7), &mut rollup_writer).await.context("rollup flush deadline")?; }
                            if !writer_done {
                                tokio::time::timeout(Duration::from_secs(9), &mut writer).await.context("history flush deadline")?;
                            }
                            let health = history.health.snapshot();
                            eprintln!("runtime component=clickhouse_history state=stopped dropped_logs={} backlog={} degraded={}", health.dropped, health.backlog, health.degraded);
                        }
                        if openwaf_admin::statistics::save(&db, &telemetry).await.is_err() {
                            eprintln!("runtime component=statistics_checkpoint state=degraded reason=write_failed");
                        }
                        eprintln!("runtime component=telemetry state=stopped dropped_logs={}", telemetry.totals().dropped_logs);
                        // The sampler's App clone owns the configuration lease connection.
                        // Release it after cancellation before waiting for pool shutdown.
                        drop(uptime_app);
                        tokio::time::timeout(Duration::from_secs(3), db.close())
                            .await
                            .context("managed DB close deadline")?;
                        result
                    });
                    runtime.shutdown_timeout(Duration::from_secs(2));
                    result
                })();
                if let Err(error) = result {
                    let _ = send.try_send(Err(error.to_string()));
                    eprintln!("runtime component=admin_api state=stopped reason=startup_or_runtime_failure");
                }
            })
            .context("start admin control-plane owner")?;
        match ready.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(store)) => Ok(Some(Self {
                store,
                stop: Some(stop),
                worker: Some(worker),
            })),
            result => {
                let _ = stop.send(());
                if worker.is_finished() {
                    let _ = worker.join();
                }
                match result {
                    Ok(Err(error)) => anyhow::bail!("managed Admin startup failed: {error}"),
                    _ => anyhow::bail!("managed Admin startup unavailable"),
                }
            }
        }
    }
}
// Runs once on the startup thread, before configuration validation or workers.
// No Docker access, DNS, network requests or interface reads on the hot path.
fn listener_ips(configured: &str, discover: bool) -> Result<Vec<IpAddr>> {
    let mut ips = BTreeSet::new();
    for value in configured.split(',').filter(|v| !v.is_empty()) {
        ips.insert(
            value
                .parse()
                .context("invalid local listener IP inventory")?,
        );
        ensure!(ips.len() <= 128, "local listener IP inventory exceeds 128");
    }
    if discover {
        for interface in
            nix::ifaddrs::getifaddrs().context("cannot read local network interfaces")?
        {
            if let Some(address) = interface.address {
                let ip = address
                    .as_sockaddr_in()
                    .map(|v| IpAddr::V4(v.ip()))
                    .or_else(|| address.as_sockaddr_in6().map(|v| IpAddr::V6(v.ip())));
                if let Some(ip) = ip {
                    ips.insert(ip);
                    ensure!(ips.len() <= 128, "local listener IP inventory exceeds 128");
                }
            }
        }
    }
    Ok(ips.into_iter().collect())
}

async fn serve(
    app: Arc<App>,
    listener: tokio::net::TcpListener,
    mut stop: oneshot::Receiver<()>,
) -> Result<()> {
    let (drain, drained) = oneshot::channel::<()>();
    let server = axum_server(app.clone(), listener, drained);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result?,
        _ = &mut stop => {
            if let Some(service) = &app.telemetry { service.shutdown(); }
            let _ = drain.send(());
            match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
                Ok(result) => result?,
                Err(_) => eprintln!("runtime component=admin_api_shutdown state=degraded reason=drain_deadline"),
            }
        }
    }
    Ok(())
}
async fn axum_server(
    app: Arc<App>,
    listener: tokio::net::TcpListener,
    stop: oneshot::Receiver<()>,
) -> Result<()> {
    axum::serve(
        BoundedListener::new(listener),
        router(app).into_make_service_with_connect_info::<ConnectionInfo>(),
    )
    .with_graceful_shutdown(async {
        let _ = stop.await;
    })
    .into_future()
    .await
    .context("managed Admin HTTP server")
}
impl Drop for Managed {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(55);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                if worker.join().is_err() {
                    eprintln!("runtime component=admin_owner state=failed reason=worker_panicked");
                }
            } else {
                eprintln!("runtime component=admin_owner state=degraded reason=shutdown_deadline");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_inventory_blocks_own_listener_and_keeps_other_ports_available() {
        let ips = listener_ips("127.0.0.1,127.0.0.1,::1,192.0.2.9", true).unwrap();
        assert!(ips.contains(&"192.0.2.9".parse().unwrap()));
        assert_eq!(ips.iter().filter(|ip| ip.is_loopback()).count(), 2);
        let context = ConfigContext {
            listeners: vec!["0.0.0.0:8443".parse().unwrap()],
            local_ips: ips.clone(),
        };
        // Includes the dynamically assigned Docker/host interface addresses and IPv6.
        for ip in ips {
            assert!(context.denies(SocketAddr::new(ip, 8443)));
            assert!(!context.denies(SocketAddr::new(ip, 3000)));
        }
        assert!(!context.denies("192.0.2.10:8443".parse().unwrap()));
    }

    #[test]
    fn manual_inventory_remains_explicit_and_bounded() {
        assert_eq!(listener_ips("192.0.2.9", false).unwrap().len(), 1);
        assert!(listener_ips("not-an-ip", false).is_err());
        let too_many = (1..=129)
            .map(|n| format!("192.0.2.{n}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(listener_ips(&too_many, false).is_err());
    }
}
