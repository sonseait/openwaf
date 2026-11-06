//! One owned polling thread; no filesystem work on Pingora's executor/handshake.
use anyhow::{Context, Result};
use openwaf_tls::{Reload, Store};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

pub(super) struct Reloader {
    stop: Option<mpsc::SyncSender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Reloader {
    pub(super) fn start(store: Arc<Store>, path: PathBuf) -> Result<Self> {
        let (stop, receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new().name("tls-reload".into()).spawn(move || {
            let mut last_error = None;
            loop {
                match receive.recv_timeout(Duration::from_secs(1)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                match store.reload(&path) {
                    Ok(Reload::Applied { revision, certificates }) => {
                        eprintln!("TLS snapshot applied: revision={revision}, certificates={certificates}");
                        last_error = None;
                    }
                    Ok(Reload::Unchanged) => {
                        if last_error.take().is_some() {
                            eprintln!("TLS reload source recovered: active_revision={}", store.revision());
                        }
                    }
                    Err(error) => {
                        // Report transitions, not once per tick. Error messages
                        // never include PEM, private keys, hostname or raw input.
                        if last_error.as_ref() != Some(&error) {
                            eprintln!("TLS reload rejected: {error}; active_revision={}", store.revision());
                        }
                        last_error = Some(error);
                    }
                }
            }
        }).context("start TLS reload worker")?;
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
        })
    }
}

impl Drop for Reloader {
    fn drop(&mut self) {
        // Channel close wakes recv_timeout immediately, including startup failure.
        self.stop.take();
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                if worker.join().is_err() {
                    eprintln!("TLS reload worker panicked during shutdown");
                }
            } else {
                // Blocking filesystem IO cannot be force-cancelled safely. The
                // thread retains its Arc; process exit provides the final bound.
                eprintln!("TLS reload worker exceeded shutdown deadline");
            }
        }
    }
}
