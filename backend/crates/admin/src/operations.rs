//! Authenticated operational controls, persisted before local publication.
use super::*;
use axum::extract::Query;
use openwaf_config::operations::{Mode, Operations};
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/operations/endpoints", get(status).put(update))
        .route("/api/v1/operations/endpoints/force-disconnect", post(force))
        .route("/api/v1/operations/endpoints/history", post(history))
}
fn store(app: &App) -> ApiResult<&Arc<openwaf_config::Store>> {
    Ok(&app.config.as_ref().ok_or(Error::Unavailable)?.store)
}
pub async fn load(db: &PgPool, store: &openwaf_config::Store) -> Result<()> {
    for row in
        sqlx::query("SELECT endpoint_key,mode,revision,reason,deadline_unix_ms FROM endpoint_operations LIMIT 4096")
            .fetch_all(db)
            .await?
    {
        let mode: Mode = serde_json::from_value(serde_json::Value::String(row.try_get("mode")?))?;
        store.1.set_with_deadline(
            row.try_get("endpoint_key")?,
            mode,
            row.try_get("revision")?,
            row.try_get("reason")?,
            row.try_get::<Option<i64>, _>("deadline_unix_ms")?.map(|v| v as u64),
        );
    }
    Ok(())
}
#[derive(Default, Deserialize)]
struct StatusQuery {
    #[serde(default)]
    summary: bool,
}
async fn status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let store = store(&app)?;
    let snapshot = store.load();
    Ok(Json(endpoint_status(&snapshot, &store.1, query.summary)))
}
fn endpoint_status(
    snapshot: &openwaf_config::Snapshot,
    operations: &Operations,
    summary: bool,
) -> serde_json::Value {
    let observed_at = openwaf_telemetry::now_ms();
    let diagnostics = snapshot.health.status();
    let by_index: std::collections::BTreeMap<_, _> = diagnostics
        .iter()
        .map(|d| ((d.upstream, d.endpoint), d))
        .collect();
    let mut endpoints = Vec::new();
    for (ui, upstream) in snapshot.document.upstreams.iter().enumerate() {
        let keys: Vec<_> = upstream
            .endpoints
            .iter()
            .map(|e| Operations::key(&upstream.id, e))
            .collect();
        let eligible: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(ei, key)| {
                operations.eligible(key) && by_index.get(&(ui, ei)).is_some_and(|d| d.available)
            })
            .collect();
        let eligible_count = eligible.iter().filter(|v| **v).count();
        for (ei, endpoint) in upstream.endpoints.iter().enumerate() {
            let alternatives = eligible_count - usize::from(eligible[ei]);
            let mut value = serde_json::json!({
                "key": keys[ei], "upstream_id": upstream.id,
                "address": endpoint.address, "protocol": endpoint.protocol,
                "eligible_alternatives": alternatives,
                "expected_downtime": alternatives == 0,
                "single_endpoint": upstream.endpoints.len() == 1,
                "slow_start_ms": upstream.balancing.slow_start_ms
            });
            if summary {
                // Join identity and health within this retained config snapshot.
                // DNS/address-level details remain available through history/full status.
                value["health"] = by_index
                    .get(&(ui, ei))
                    .map_or(serde_json::Value::Null, |d| {
                        serde_json::json!({
                            "available": d.available, "reason": d.reason, "phase": d.phase,
                            "checked_at_ms": d.checked_at_ms, "valid_for_ms": d.valid_for_ms,
                            "latency_ms": d.last_check.as_ref().map(|check| check.latency_ms)
                        })
                    });
            }
            endpoints.push(value);
        }
    }
    let mut value = serde_json::json!({
        "observed_at_unix_ms": observed_at, "source": "gateway",
        "config_version": snapshot.version, "endpoints": endpoints,
        "operations": operations.status()
    });
    if !summary {
        value["diagnostics"] = serde_json::json!(diagnostics);
    }
    value
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    key: String,
    mode: Mode,
    expected_revision: i64,
    reason: String,
    #[serde(default)]
    deadline_unix_ms: Option<u64>,
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Change>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    let store = store(&app)?;
    let now = openwaf_telemetry::now_ms();
    if input.deadline_unix_ms.is_some_and(|v| {
        input.mode == Mode::Active || v <= now || v > now.saturating_add(7 * 86400000)
    }) || input.expected_revision < 0
        || input.expected_revision == i64::MAX
        || input.reason.trim().is_empty()
        || input.reason.len() > 256
        || input.reason.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    let snapshot = store.load();
    if !snapshot.document.upstreams.iter().any(|u| {
        u.endpoints
            .iter()
            .any(|e| Operations::key(&u.id, e) == input.key)
    }) {
        return Err(Error::NotFound);
    }
    let mode = serde_json::to_value(input.mode).map_err(|_| Error::Invalid)?;
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331120205)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM endpoint_operations")
        .fetch_one(&mut *tx)
        .await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT revision FROM endpoint_operations WHERE endpoint_key=$1 FOR UPDATE",
    )
    .bind(&input.key)
    .fetch_optional(&mut *tx)
    .await?;
    if current.is_none() && count >= 4096 {
        return Err(Error::Unavailable);
    }
    if current.unwrap_or(0) != input.expected_revision {
        return Err(Error::Conflict);
    }
    let result=sqlx::query("INSERT INTO endpoint_operations(endpoint_key,mode,revision,reason,deadline_unix_ms) VALUES($1,$2,1,$3,$5) ON CONFLICT(endpoint_key) DO UPDATE SET mode=$2, revision=endpoint_operations.revision+1, reason=$3,deadline_unix_ms=$5,updated_at=now() WHERE endpoint_operations.revision=$4")
 .bind(&input.key).bind(mode.as_str()).bind(&input.reason).bind(input.expected_revision).bind(input.deadline_unix_ms.map(|v|v as i64)).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "endpoint.mode_changed",
        &input.key,
        None,
    )
    .await?;
    tx.commit().await?;
    let revision = input.expected_revision + 1;
    store.1.set_with_deadline(
        input.key,
        input.mode,
        revision,
        input.reason,
        input.deadline_unix_ms,
    );
    Ok(Json(serde_json::json!({"revision":revision})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    key: String,
}
async fn force(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Key>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let store = store(&app)?;
    if input.key.len() > 1024 {
        return Err(Error::Invalid);
    }
    let snapshot = store.load();
    if !snapshot.document.upstreams.iter().any(|u| {
        u.endpoints
            .iter()
            .any(|e| Operations::key(&u.id, e) == input.key)
    }) {
        return Err(Error::NotFound);
    }
    let mut tx = app.db.begin().await?;
    audit(
        &mut tx,
        Some(auth.id),
        "endpoint.force_disconnect",
        &input.key,
        None,
    )
    .await?;
    tx.commit().await?;
    if !store.1.force(&input.key) {
        return Err(Error::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Key>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    if input.key.len() > 1024 {
        return Err(Error::Invalid);
    }
    let rows=sqlx::query("SELECT diagnostic FROM endpoint_checks WHERE endpoint_key=$1 AND observed_at>now()-interval '7 days' ORDER BY observed_at DESC LIMIT 100").bind(input.key).fetch_all(&app.db).await?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| r.try_get("diagnostic"))
        .collect::<std::result::Result<_, _>>()?;
    Ok(Json(
        serde_json::json!({"items":items,"limit":100,"source":"gateway"}),
    ))
}
pub async fn sample(app: &App) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if !tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::investigation::observe_certificates(app),
        )
        .await
        .is_ok_and(|r| r.is_ok())
        {
            eprintln!("certificate change observations unavailable");
        }
        let Some(plane) = &app.config else {
            continue;
        };
        let snapshot = plane.store.load();
        for status in snapshot.health.status() {
            let Some(upstream) = snapshot.document.upstreams.get(status.upstream) else {
                continue;
            };
            let Some(endpoint) = upstream.endpoints.get(status.endpoint) else {
                continue;
            };
            let value = serde_json::json!({"observed_at_unix_ms":openwaf_telemetry::now_ms(),"config_version":snapshot.version,"status":status});
            if sqlx::query("INSERT INTO endpoint_checks(endpoint_key,diagnostic) VALUES($1,$2)")
                .bind(Operations::key(&upstream.id, endpoint))
                .bind(value)
                .execute(&app.db)
                .await
                .is_err()
            {
                break;
            }
        }
        if sqlx::query("DELETE FROM endpoint_checks WHERE observed_at<now()-interval '7 days'")
            .execute(&app.db)
            .await
            .is_err()
        {
            eprintln!("endpoint diagnostic retention unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openwaf_config::{Context, Snapshot, Store, health};

    fn fixture() -> Store {
        let document = serde_json::from_value(serde_json::json!({
            "upstreams": [
                {"id":"first", "endpoints":[
                    {"address":"192.0.2.10:8080", "protocol":"http"},
                    {"address":"192.0.2.11:8080", "protocol":"http"}
                ]},
                {"id":"second", "endpoints":[
                    {"address":"192.0.2.10:8080", "protocol":"http"}
                ]}
            ]
        }))
        .unwrap();
        Store::new(
            Snapshot::prepare(
                7,
                document,
                &Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn summary_joins_health_to_identity_without_config_or_address_details() {
        let store = fixture();
        let snapshot = store.load();
        let address = "192.0.2.10:8080".parse().unwrap();
        snapshot.health.observe(
            0,
            0,
            health::Observation {
                addresses: vec![address],
                expires: Instant::now() + Duration::from_secs(30),
                checked_at_ms: 1234,
                reason: "healthy",
                diagnostic: Some(health::Diagnostic {
                    latency_ms: 42,
                    resolved_addresses: 16,
                    complete: true,
                    addresses: (0..16)
                        .map(|_| health::AddressCheck {
                            address,
                            accepted: true,
                            tcp: "ok",
                            tls: "not_required",
                            http: "ok",
                            http_status: Some(200),
                            error: None,
                            latency_ms: 42,
                        })
                        .collect(),
                }),
            },
        );
        let full = endpoint_status(&snapshot, &store.1, false);
        let summary = endpoint_status(&snapshot, &store.1, true);
        assert_eq!(summary["config_version"], 7);
        assert_eq!(summary["source"], "gateway");
        assert!(summary["observed_at_unix_ms"].as_u64().unwrap() > 0);
        assert_eq!(summary["operations"], full["operations"]);
        let first = &summary["endpoints"][0];
        assert_eq!(first["health"]["available"], true);
        assert_eq!(first["health"]["checked_at_ms"], 1234);
        assert_eq!(first["health"]["latency_ms"], 42);
        assert!(first["health"]["valid_for_ms"].as_u64().unwrap() > 0);
        assert!(first["health"].get("addresses").is_none());
        assert!(first["health"].get("last_check").is_none());
        // The same address in another pool must not inherit the first's health.
        assert_eq!(summary["endpoints"][2]["health"]["phase"], "pending");
        assert_eq!(summary["endpoints"][2]["health"]["available"], false);
        assert_ne!(first["key"], summary["endpoints"][2]["key"]);
        assert!(summary.get("diagnostics").is_none());
        assert!(summary.get("draft").is_none());
        assert!(full["endpoints"][0].get("health").is_none());
        assert_eq!(
            full["diagnostics"][0]["last_check"]["addresses"]
                .as_array()
                .unwrap()
                .len(),
            16
        );
        assert!(
            serde_json::to_vec(&summary).unwrap().len() < serde_json::to_vec(&full).unwrap().len()
        );
    }

    #[test]
    fn summary_preserves_maintenance_eligibility_and_snapshot_identity() {
        let store = fixture();
        let snapshot = store.load();
        for (ei, endpoint) in snapshot.document.upstreams[0].endpoints.iter().enumerate() {
            snapshot.health.publish(
                0,
                ei,
                vec![endpoint.address.socket().unwrap()],
                Instant::now() + Duration::from_secs(30),
                1234,
                "healthy",
            );
        }
        let before = endpoint_status(&snapshot, &store.1, true);
        assert_eq!(before["endpoints"][0]["eligible_alternatives"], 1);
        let key = before["endpoints"][1]["key"].as_str().unwrap().to_owned();
        store
            .1
            .set(key.clone(), Mode::Drain, 1, "maintenance".into());
        let after = endpoint_status(&snapshot, &store.1, true);
        assert_eq!(after["endpoints"][0]["eligible_alternatives"], 0);
        assert_eq!(after["endpoints"][0]["expected_downtime"], true);
        assert_eq!(after["endpoints"][1]["eligible_alternatives"], 1);
        assert!(
            after["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["key"] == key && o["mode"] == "drain")
        );
        let mut reordered = snapshot.document.clone();
        reordered.upstreams.reverse();
        store.publish(
            Snapshot::prepare(
                8,
                reordered,
                &Context {
                    listeners: vec![],
                    local_ips: vec![],
                },
            )
            .unwrap(),
        );
        // A retained request snapshot is unaffected by publication/reordering.
        assert_eq!(
            endpoint_status(&snapshot, &store.1, true)["config_version"],
            7
        );
        let current = endpoint_status(&store.load(), &store.1, true);
        assert_eq!(current["config_version"], 8);
        let moved = current["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["key"] == key)
            .unwrap();
        assert_eq!(moved["health"]["phase"], "pending");
    }
}
