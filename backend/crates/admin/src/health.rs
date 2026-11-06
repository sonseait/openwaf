//! Aggregate control-plane observations without claiming dependency health from
//! gateway reachability. All checks are outside the proxy path and bounded.
use super::*;
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/v1/health/system", get(snapshot))
}
pub(super) async fn acme(app: &App) -> serde_json::Value {
    let managed = app
        .certificates
        .worker_health(app.config.is_some() && app.application_tls.is_some());
    let managed = worker_health(managed, openwaf_telemetry::now_ms());
    let applications = app.application_certificate_health.lock()
        .map(|health| worker_health(health.clone(), openwaf_telemetry::now_ms()))
        .unwrap_or_else(|_| serde_json::json!({"state":"unavailable","reason":"certificate_worker_health_unavailable"}));
    let schedules = schedule_health(std::env::var_os("OPENWAF_ACME_HEALTH_FILES").as_deref()).await;
    let mut sources = serde_json::json!({"certificate_requests":managed,"applications":applications,"schedules":schedules,"bootstrap":bootstrap_health().await});
    // The worker heartbeat proves supervisor availability, not successful issuance.
    // Failed jobs remain degraded even when the supervisor itself is available.
    if ["certificate_requests", "applications"]
        .iter()
        .any(|source| sources[source]["state"] != "not_configured")
    {
        let failed = tokio::time::timeout(Duration::from_secs(2), sqlx::query_as::<_, (bool, bool)>(
            "SELECT EXISTS(SELECT 1 FROM certificate_requests WHERE state='degraded'), EXISTS(SELECT 1 FROM application_certificates WHERE state='degraded')"
        ).fetch_one(&app.db)).await;
        match failed {
            Ok(Ok((requests, applications))) => {
                for (source, failed) in [
                    ("certificate_requests", requests),
                    ("applications", applications),
                ] {
                    if failed && sources[source]["state"] != "not_configured" {
                        sources[source]["state"] = "degraded".into();
                        sources[source]["reason"] = "certificate_jobs_degraded".into();
                    }
                }
            }
            _ => {
                for source in ["certificate_requests", "applications"] {
                    if sources[source]["state"] != "not_configured" {
                        sources[source]["state"] = "unavailable".into();
                        sources[source]["reason"] = "certificate_jobs_unavailable".into();
                    }
                }
            }
        }
    }
    acme_summary(sources)
}

static BOOTSTRAP_HEALTH_READ: Semaphore = Semaphore::const_new(1);

async fn bootstrap_health() -> serde_json::Value {
    let Some(root) = std::env::var_os("OPENWAF_BOOTSTRAP_PROVIDER_ROOT") else {
        return serde_json::json!({"state":"not_configured"});
    };
    let Ok(permit) = BOOTSTRAP_HEALTH_READ.try_acquire() else {
        return serde_json::json!({"state":"unavailable","reason":"bootstrap_observation_unavailable"});
    };
    let read = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let _permit = permit;
        let bytes =
            crypto::private_file(&std::path::PathBuf::from(root).join("health.json"), 4096)?;
        Ok(serde_json::from_slice(&bytes)?)
    });
    let value = match tokio::time::timeout(Duration::from_secs(2), read).await {
        Ok(Ok(Ok(value))) => value,
        _ => {
            return serde_json::json!({"state":"unavailable","reason":"bootstrap_observation_unavailable"});
        }
    };
    bootstrap_observation(value, openwaf_telemetry::now_ms())
}

fn bootstrap_observation(value: serde_json::Value, now: u64) -> serde_json::Value {
    let stale = value["observed_at_unix_ms"]
        .as_u64()
        .is_none_or(|time| time > now || now - time > 30_000);
    let state = if stale {
        "unavailable"
    } else if value["state"] == "current"
        && value["tls_state"] == "current"
        && value["dns_state"] == "complete"
        && value["provider_state"] == "reserved"
        && ["current", "renewing"].contains(&value["renewal_state"].as_str().unwrap_or_default())
    {
        "healthy"
    } else {
        "degraded"
    };
    serde_json::json!({"state":state,"source":"admin_bootstrap","stale":stale,"observed_at_unix_ms":value["observed_at_unix_ms"],"bootstrap_state":value["state"],"reason":value["reason"],"dns_state":value["dns_state"],"tls_state":value["tls_state"],"renewal_state":value["renewal_state"],"provider_state":value["provider_state"],"ready":value["ready"]})
}

fn worker_health(mut value: serde_json::Value, now: u64) -> serde_json::Value {
    let state = value["state"].as_str().unwrap_or("unknown");
    if ["disabled", "not_configured"].contains(&state) {
        value["state"] = "not_configured".into();
        return value;
    }
    // One shared owner may run two 210s children plus bounded cleanup and a 30s tick.
    let stale = value["observed_at_unix_ms"]
        .as_u64()
        .is_none_or(|time| time > now || now.saturating_sub(time) > 600_000);
    let state = if stale {
        "unavailable"
    } else if state == "available" {
        "healthy"
    } else {
        "degraded"
    };
    value["state"] = state.into();
    value["stale"] = stale.into();
    value
}

fn acme_summary(sources: serde_json::Value) -> serde_json::Value {
    let configured: Vec<_> = sources
        .as_object()
        .into_iter()
        .flat_map(|sources| sources.values())
        .filter(|value| value["state"] != "not_configured")
        .collect();
    let state = if configured.is_empty() {
        "not_configured"
    } else if configured.iter().all(|value| value["state"] == "healthy") {
        "healthy"
    } else {
        "degraded"
    };
    serde_json::json!({"state":state,"source":"acme_workers","scope":"worker_and_job_observations","schedules":sources["schedules"]["schedules"].as_array().cloned().unwrap_or_default(),"sources":sources})
}

async fn schedule_health(paths: Option<&std::ffi::OsStr>) -> serde_json::Value {
    let Some(paths) = paths else {
        return serde_json::json!({"state":"not_configured"});
    };
    let paths: Vec<_> = paths
        .to_string_lossy()
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect();
    if paths.is_empty()
        || paths.len() > 8
        || paths
            .iter()
            .any(|path| !std::path::Path::new(path).is_absolute())
    {
        return serde_json::json!({"state":"degraded","reason":"invalid_health_file_inventory"});
    }
    let mut schedules = Vec::new();
    let mut healthy = true;
    for path in paths {
        let read = async {
            use tokio::io::AsyncReadExt;
            let file = tokio::fs::File::open(path).await.ok()?;
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes).await.ok()?;
            if bytes.len() > 4096 {
                return None;
            }
            let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let observed = value["observed_at_unix_ms"].as_u64()?;
            let state = value["state"].as_str()?;
            Some(
                serde_json::json!({"observed_at_unix_ms":observed,"state":state,"stale":observed > openwaf_telemetry::now_ms() || openwaf_telemetry::now_ms().saturating_sub(observed)>20000}),
            )
        };
        let value = tokio::time::timeout(Duration::from_millis(200), read)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| serde_json::json!({"state":"unavailable","stale":true}));
        if value["stale"] == true || !["healthy", "renewing"].iter().any(|s| value["state"] == *s) {
            healthy = false;
        }
        schedules.push(value);
    }
    serde_json::json!({"state":if healthy{"healthy"}else{"degraded"},"schedules":schedules})
}
fn collector_source(
    inventory: Result<Arc<discovery::Inventory>, discovery::Failure>,
) -> serde_json::Value {
    let Ok(inventory) = inventory else {
        return serde_json::json!({"state":"unavailable","reason":"collector_unavailable","observed_at_unix_ms":null,"stale":true,"error":"collector_unavailable"});
    };
    let events_failed = inventory.docker_events_connected == Some(false);
    let state = if !inventory.collector_available {
        "unavailable"
    } else if inventory.stale || inventory.error.is_some() || events_failed {
        "degraded"
    } else {
        "healthy"
    };
    serde_json::json!({"state":state,"collector_available":inventory.collector_available,"observed_at_unix_ms":inventory.observed_at_unix_ms,"stale":inventory.stale,"error":inventory.error,"docker_events_connected":inventory.docker_events_connected,"reason":inventory.error.or(if events_failed {Some("docker_events_unavailable")} else if inventory.stale {Some("source_stale")} else {None})})
}

pub(super) async fn collector(app: &App) -> serde_json::Value {
    let Some(backend) = &app.discovery else {
        return serde_json::json!({"state":"not_configured"});
    };
    let observe = async |kind| {
        collector_source(
            tokio::time::timeout(Duration::from_secs(3), backend.inventory(kind))
                .await
                .unwrap_or(Err(discovery::Failure::Unavailable)),
        )
    };
    let (host, docker) = tokio::join!(
        observe(discovery::Kind::HostPorts),
        observe(discovery::Kind::Docker)
    );
    let state = if host["state"] == "healthy" && docker["state"] == "healthy" {
        "healthy"
    } else if host["state"] == "unavailable" && docker["state"] == "unavailable" {
        "unavailable"
    } else {
        "degraded"
    };
    serde_json::json!({"state":state,"sources":{"host_ports":host,"docker":docker}})
}

async fn snapshot(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let db = async {
        matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                sqlx::query("SELECT 1").execute(&app.db)
            )
            .await,
            Ok(Ok(_))
        )
    };
    let (db, collector, acme) = tokio::join!(db, collector(&app), acme(&app));
    let now = openwaf_telemetry::now_ms();
    let service = app.telemetry.as_ref();
    let metrics = service.map(|s| s.hub.metrics.borrow().clone());
    let fresh = metrics
        .as_ref()
        .is_some_and(|m| now.saturating_sub(m.observed_at_unix_ms) <= 3000);
    let diagnostics = service
        .and_then(|s| s.diagnostics.as_ref())
        .map(|d| d())
        .unwrap_or_default();
    let history = service
        .and_then(|s| s.history.as_ref())
        .map(|h| h.health.snapshot());
    let loss = metrics.as_ref().is_some_and(|m| m.totals.dropped_logs > 0)
        || history.as_ref().is_some_and(|h| h.dropped > 0);
    let monitoring_degraded = !fresh || loss || history.as_ref().is_some_and(|h| h.degraded);
    Ok(Json(
        serde_json::json!({"observed_at_unix_ms":now,"source":"admin_and_gateway","serving":{"state":if fresh{"running"}else{"unknown"},"evidence":"gateway aggregator heartbeat; endpoint health is separate"},"monitoring":{"state":if monitoring_degraded{"degraded"}else{"healthy"},"known_data_loss":loss,"last_heartbeat_unix_ms":metrics.as_ref().map(|m|m.observed_at_unix_ms)},"components":{"gateway":{"state":if fresh{"healthy"}else{"unknown"}},"waf_workers":{"state":if !fresh{"unknown"}else if diagnostics["waf"]["healthy"]==true{"healthy"}else{"degraded"},"details":diagnostics["waf"]},"postgresql":{"state":if db{"healthy"}else{"unavailable"}},"clickhouse":history.map(|h|serde_json::json!({"state":if h.degraded{"degraded"}else{"healthy"},"details":h})).unwrap_or_else(||serde_json::json!({"state":"not_configured"})),"collector":collector,"crowdsec":if diagnostics["crowdsec"].is_null(){serde_json::json!({"state":"not_configured"})}else{serde_json::json!({"state":if diagnostics["crowdsec"]["degraded"]==true || diagnostics["crowdsec"]["checkpoint_degraded"]==true{"degraded"}else{"healthy"},"details":diagnostics["crowdsec"]})},"acme":acme,"tls":{"state":if diagnostics["tls"].is_null(){"not_configured"}else{"observed"},"details":diagnostics["tls"]}}}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bootstrap_distinguishes_loaded_cert_from_renewal_health_and_staleness() {
        let now = 50_000;
        let mut value = json!({"state":"current","dns_state":"complete","tls_state":"current","provider_state":"reserved","renewal_state":"current","observed_at_unix_ms":now,"ready":true});
        assert_eq!(
            bootstrap_observation(value.clone(), now)["state"],
            "healthy"
        );
        for state in ["degraded", "starting", "unavailable", "pending"] {
            value["renewal_state"] = state.into();
            assert_eq!(
                bootstrap_observation(value.clone(), now)["state"],
                "degraded"
            );
        }
        value["renewal_state"] = "renewing".into();
        assert_eq!(
            bootstrap_observation(value.clone(), now)["state"],
            "healthy"
        );
        assert_eq!(
            bootstrap_observation(value.clone(), now + 30_001)["state"],
            "unavailable"
        );
        assert_eq!(
            bootstrap_observation(value.clone(), now - 1)["state"],
            "unavailable"
        );
        value["state"] = "degraded".into();
        value["reason"] = "bootstrap_dns_failed".into();
        let failed = bootstrap_observation(value, now);
        assert_eq!(failed["state"], "degraded");
        assert_eq!(failed["ready"], true);
        assert_eq!(failed["reason"], "bootstrap_dns_failed");
    }
    #[test]
    fn managed_acme_does_not_require_external_schedule_files_or_hide_failures() {
        let now = 1_000_000;
        let mut sources = json!({
            "certificate_requests":worker_health(json!({"state":"available","observed_at_unix_ms":now}),now),
            "applications":worker_health(json!({"state":"disabled"}),now),
            "schedules":{"state":"not_configured"}
        });
        assert_eq!(acme_summary(sources.clone())["state"], "healthy");
        sources["schedules"] =
            json!({"state":"degraded","schedules":[{"state":"unavailable","stale":true}]});
        let summary = acme_summary(sources.clone());
        assert_eq!(summary["state"], "degraded");
        assert_eq!(summary["schedules"][0]["state"], "unavailable");
        sources["schedules"] = json!({"state":"not_configured"});
        sources["certificate_requests"] =
            json!({"state":"degraded","reason":"certificate_jobs_degraded"});
        assert_eq!(acme_summary(sources.clone())["state"], "degraded");
        sources["certificate_requests"] = json!({"state":"not_configured"});
        assert_eq!(acme_summary(sources)["state"], "not_configured");
    }

    #[test]
    fn worker_health_allows_bounded_child_work_but_rejects_stale_or_future_observations() {
        let now = 1_000_000;
        for age in [0, 30_000, 500_000, 600_000] {
            assert_eq!(
                worker_health(
                    json!({"state":"available","observed_at_unix_ms":now-age}),
                    now
                )["state"],
                "healthy"
            );
        }
        for observed in [now - 600_001, now + 1] {
            let health = worker_health(
                json!({"state":"available","observed_at_unix_ms":observed}),
                now,
            );
            assert_eq!(health["state"], "unavailable");
            assert_eq!(health["stale"], true);
        }
        assert_eq!(
            worker_health(json!({"state":"starting","observed_at_unix_ms":now}), now)["state"],
            "degraded"
        );
        assert_eq!(
            worker_health(json!({"state":"degraded"}), now)["state"],
            "unavailable"
        );
    }

    #[test]
    fn collector_preserves_docker_failure_and_distinguishes_event_outage_from_inventory() {
        let mut inventory = discovery::Inventory {
            schema_version: 1,
            source: discovery::Kind::Docker,
            collection_scope: "collector_network_namespace",
            collector_available: true,
            docker_events_connected: Some(false),
            stale: true,
            error: Some("docker_refresh_failed"),
            observed_at_unix_ms: Some(42),
            items: json!([]),
            candidates: vec![],
            candidates_truncated: false,
        };
        let failed = collector_source(Ok(Arc::new(inventory.clone())));
        assert_eq!(failed["state"], "degraded");
        assert_eq!(failed["reason"], "docker_refresh_failed");
        assert_eq!(failed["observed_at_unix_ms"], 42);
        inventory.stale = false;
        inventory.error = None;
        let events = collector_source(Ok(Arc::new(inventory.clone())));
        assert_eq!(events["state"], "degraded");
        assert_eq!(events["reason"], "docker_events_unavailable");
        assert_eq!(events["stale"], false);
        inventory.docker_events_connected = None;
        inventory.source = discovery::Kind::HostPorts;
        assert_eq!(
            collector_source(Ok(Arc::new(inventory.clone())))["state"],
            "healthy"
        );
        inventory.collector_available = false;
        assert_eq!(
            collector_source(Ok(Arc::new(inventory)))["state"],
            "unavailable"
        );
        assert_eq!(
            collector_source(Err(discovery::Failure::Unavailable))["state"],
            "unavailable"
        );
    }

    #[tokio::test]
    async fn external_schedules_validate_inventory_freshness_and_file_limits() {
        assert_eq!(schedule_health(None).await["state"], "not_configured");
        for paths in [
            "",
            "relative.json",
            "/health.json,",
            &["/health.json"; 9].join(","),
        ] {
            assert_eq!(
                schedule_health(Some(paths.as_ref())).await["reason"],
                "invalid_health_file_inventory"
            );
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("health.json");
        let now = openwaf_telemetry::now_ms();
        for (value, expected) in [
            (
                json!({"state":"healthy","observed_at_unix_ms":now}),
                "healthy",
            ),
            (
                json!({"state":"renewing","observed_at_unix_ms":now}),
                "healthy",
            ),
            (
                json!({"state":"healthy","observed_at_unix_ms":now-21_000}),
                "degraded",
            ),
            (
                json!({"state":"healthy","observed_at_unix_ms":now+60_000}),
                "degraded",
            ),
            (
                json!({"state":"exhausted","observed_at_unix_ms":now}),
                "degraded",
            ),
        ] {
            tokio::fs::write(&path, value.to_string())
                .await
                .expect("write observation");
            assert_eq!(
                schedule_health(Some(path.as_os_str())).await["state"],
                expected
            );
        }
        tokio::fs::write(&path, vec![b'x'; 4097])
            .await
            .expect("write oversized");
        assert_eq!(
            schedule_health(Some(path.as_os_str())).await["schedules"][0]["state"],
            "unavailable"
        );
        tokio::fs::remove_file(&path)
            .await
            .expect("remove observation");
        assert_eq!(
            schedule_health(Some(path.as_os_str())).await["schedules"][0]["state"],
            "unavailable"
        );
    }
}
