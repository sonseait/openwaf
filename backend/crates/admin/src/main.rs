#![forbid(unsafe_code)]
use anyhow::{Context, Result, ensure};
use openwaf_admin::{
    App, connect,
    crypto::MasterKey,
    router,
    transport::{BoundedListener, ConnectionInfo},
};
use std::{env, future::IntoFuture, net::SocketAddr, path::Path, time::Duration};

fn main() {
    // Load environment before Tokio starts worker threads.
    let result = openwaf_env::load().and_then(|()| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(run())
    });
    if let Err(error) = result {
        // Database URLs, payloads, password hashes and session cookies never logged.
        eprintln!("OpenWAF admin failed: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    if env::args_os().len() == 2 && env::args().nth(1).as_deref() == Some("bootstrap-certificates")
    {
        return tokio::select! { result=openwaf_admin::certificate_bootstrap::provision()=>result, _=shutdown()=>Ok(()) };
    }
    ensure!(
        env::args_os().len() == 1,
        "unsupported admin command; supported startup command: bootstrap-certificates"
    );
    let url = env::var("OPENWAF_DATABASE_URL").context("OPENWAF_DATABASE_URL is required")?;
    let key_path = env::var("OPENWAF_ADMIN_MASTER_KEY_FILE")
        .context("OPENWAF_ADMIN_MASTER_KEY_FILE is required")?;
    let key = MasterKey::load(Path::new(&key_path))?;
    let db = connect(&url).await?;
    let origin = env::var("OPENWAF_ADMIN_ORIGIN")
        .context("OPENWAF_ADMIN_ORIGIN is required (HTTPS origin)")?;
    let listener: SocketAddr = env::var("OPENWAF_ADMIN_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:9090".into())
        .parse()
        .context("invalid admin listener")?;
    ensure!(
        listener.ip().is_loopback() && listener.port() != 0,
        "admin HTTP listener must be loopback behind an HTTPS terminator"
    );
    let app = App::new(db.clone(), key, origin).await?;
    let listener = tokio::net::TcpListener::bind(listener)
        .await
        .context("bind admin listener")?;
    eprintln!("OpenWAF admin ready (loopback HTTP; external HTTPS required)");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(
        BoundedListener::new(listener),
        router(app).into_make_service_with_connect_info::<ConnectionInfo>(),
    )
    .with_graceful_shutdown(async {
        let _ = stopped.await;
    })
    .into_future();
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result.context("admin server failed")?,
        _ = shutdown() => {
            let _ = stop.send(());
            tokio::time::timeout(Duration::from_secs(5), &mut server)
                .await.context("admin HTTP drain deadline")?
                .context("admin server failed")?;
        }
    }
    tokio::time::timeout(Duration::from_secs(5), db.close())
        .await
        .context("admin database shutdown deadline")?;
    Ok(())
}
async fn shutdown() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(_) => {
            eprintln!("admin signal registration failed");
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => if result.is_err() { eprintln!("admin interrupt listener failed"); },
        _ = term.recv() => {},
    }
}
