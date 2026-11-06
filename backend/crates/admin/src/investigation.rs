//! Read-only route investigation. Historical documents are never prepared/applied.
use super::*;
use axum::extract::Query;
use openwaf_config::{Document, Timeouts};
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/routes/{id}", get(route))
        .route("/api/v1/telemetry/routes", get(route_statistics))
        .route("/api/v1/history/statistics", get(statistics))
        .route("/api/v1/history/top", get(top))
        .route("/api/v1/history/changes", get(changes))
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: Option<i64>,
    #[serde(default)]
    draft: bool,
}
fn query_error(error: openwaf_storage::QueryError) -> Error {
    match error {
        openwaf_storage::QueryError::Invalid => Error::Invalid,
        openwaf_storage::QueryError::Unavailable => Error::Unavailable,
    }
}
fn description(document: &Document, id: &str) -> ApiResult<serde_json::Value> {
    let route = document
        .routes
        .iter()
        .find(|r| r.id == id)
        .ok_or(Error::NotFound)?;
    let upstream = document.upstreams.iter().find(|u| u.id == route.upstream);
    let defaults = Timeouts::default();
    let timeouts = route
        .timeouts
        .as_ref()
        .or_else(|| upstream.map(|u| &u.timeouts))
        .unwrap_or(&defaults);
    let mut route_value = serde_json::to_value(route).map_err(|_| Error::Unavailable)?;
    if route.password_protect.is_some() {
        route_value["password_protect"] = serde_json::json!({"configured":true});
    }
    Ok(
        serde_json::json!({"route":route_value,"global_rules":document.global_rules,"upstream":upstream,
        "effective_timeouts":{"total_ms":route.retry.total_timeout_ms.unwrap_or(timeouts.total_ms).min(timeouts.total_ms),"request_body_idle_ms":route.body.as_ref().map_or(30000,|body|body.idle_timeout_ms),"drain_ms":5000,"connect_ms":timeouts.connect_ms,"tls_ms":timeouts.tls_ms.unwrap_or(timeouts.connect_ms),"header_ms":timeouts.header_ms.unwrap_or(timeouts.read_ms),"response_idle_ms":timeouts.response_idle_ms.unwrap_or(timeouts.read_ms),"read_ms":timeouts.read_ms,"write_ms":timeouts.write_ms,"pool_idle_ms":timeouts.idle_ms},
        "sources":{"timeouts":if route.timeouts.is_some(){"route"}else if upstream.is_some(){"upstream"}else{"default"},"waf":if route.waf.is_some(){"route"}else{"runtime_default_not_collected"},"retry_total":if route.retry.total_timeout_ms.is_some(){"route_retry_clamped_by_timeouts"}else{"timeouts"},"request_body_idle":if route.body.is_some(){"route_body"}else{"default"},"access":"global_and_route","profile":"copied_template_not_runtime_inheritance"}}),
    )
}
async fn route(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(selection): Query<Selection>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    if id.is_empty()
        || id.len() > 128
        || (selection.draft && selection.version.is_some())
        || selection.version.is_some_and(|v| v < 0)
    {
        return Err(Error::Invalid);
    }
    let plane = app.config.as_ref().ok_or(Error::Unavailable)?;
    let active = plane.store.load();
    let (document, version, source) = if selection.draft {
        let doc: serde_json::Value =
            sqlx::query_scalar("SELECT draft FROM config_state WHERE singleton=true")
                .fetch_one(&app.db)
                .await?;
        (
            openwaf_config::resources::persisted_document(doc).map_err(|_| Error::Unavailable)?,
            None,
            "saved_draft",
        )
    } else if let Some(version) = selection.version {
        let doc: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT document FROM config_versions WHERE version=$1")
                .bind(version)
                .fetch_optional(&app.db)
                .await?;
        (
            openwaf_config::resources::persisted_document(doc.ok_or(Error::NotFound)?)
                .map_err(|_| Error::Unavailable)?,
            Some(version),
            "historical_config",
        )
    } else {
        (active.document.clone(), Some(active.version), "active")
    };
    let mut value = description(&document, &id)?;
    value["source"] = source.into();
    value["config_version"] = version.into();
    value["active_version"] = active.version.into();
    value["observed_at_unix_ms"] = openwaf_telemetry::now_ms().into();
    if source == "active" {
        let index = document
            .upstreams
            .iter()
            .position(|u| u.id == value["route"]["upstream"]);
        value["upstream_health"] = serde_json::to_value(
            active
                .health
                .status()
                .into_iter()
                .filter(|s| Some(s.upstream) == index)
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error::Unavailable)?;
    } else {
        value["upstream_health"] = serde_json::Value::Null;
    }
    Ok(Json(value))
}
async fn route_statistics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let hub = &app.telemetry.as_ref().ok_or(Error::Unavailable)?.hub;
    Ok(Json(
        serde_json::json!({"schema_version":1,"source":"route_counters","epoch":hub.epoch,"observed_at_unix_ms":openwaf_telemetry::now_ms(),"capacity":openwaf_telemetry::routes::CAPACITY,"overflow_requests":hub.routes.overflow_requests.load(std::sync::atomic::Ordering::Relaxed),"reset":"process_restart","retirement":"slots_retained_until_restart","coverage_scopes":openwaf_telemetry::routes::SCOPES,"items":hub.routes.samples()}),
    ))
}
async fn statistics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(input): Query<openwaf_storage::rollup::StatisticsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    app.telemetry
        .as_ref()
        .and_then(|s| s.history.as_ref())
        .ok_or(Error::Unavailable)?
        .statistics(input)
        .await
        .map(Json)
        .map_err(query_error)
}
async fn top(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(input): Query<openwaf_storage::Query>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let history = app
        .telemetry
        .as_ref()
        .and_then(|s| s.history.as_ref())
        .ok_or(Error::Unavailable)?;
    tokio::time::timeout(Duration::from_secs(7), history.investigation_top(input))
        .await
        .map_err(|_| Error::Unavailable)?
        .map(Json)
        .map_err(query_error)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeQuery {
    start_ms: i64,
    end_ms: i64,
    version: Option<i64>,
}
async fn changes(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(input): Query<ChangeQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    if input.start_ms < 0
        || input.start_ms >= input.end_ms
        || input.end_ms - input.start_ms > 30 * 86_400_000
        || input.end_ms > openwaf_telemetry::now_ms() as i64 + 60_000
    {
        return Err(Error::Invalid);
    }
    let rows=sqlx::query("SELECT id, action, target, (extract(epoch FROM occurred_at)*1000)::bigint AS timestamp_ms FROM admin_audit WHERE occurred_at >= to_timestamp($1::double precision/1000) AND occurred_at < to_timestamp($2::double precision/1000) AND ($3::text IS NULL OR target=$3) ORDER BY occurred_at DESC,id DESC LIMIT 101").bind(input.start_ms).bind(input.end_ms).bind(input.version.map(|v|format!("proxy/version/{v}"))).fetch_all(&app.db).await?;
    let more = rows.len() > 100;
    let mut items=rows.into_iter().take(100).map(|r|Ok(serde_json::json!({"id":r.try_get::<i64,_>("id")?,"action":r.try_get::<String,_>("action")?,"target":r.try_get::<String,_>("target")?,"timestamp_ms":r.try_get::<i64,_>("timestamp_ms")?}))).collect::<std::result::Result<Vec<_>,sqlx::Error>>()?;
    // Finite observation slice. Never infer a transition across missing/stale
    // checks, a configuration change or more than three sampling intervals.
    let checks=sqlx::query("SELECT endpoint_key, diagnostic FROM endpoint_checks WHERE observed_at >= to_timestamp($1::double precision/1000) AND observed_at < to_timestamp($2::double precision/1000) ORDER BY observed_at DESC LIMIT 1001").bind(input.start_ms).bind(input.end_ms).fetch_all(&app.db).await?;
    let checks_truncated = checks.len() > 1000;
    let mut previous = std::collections::BTreeMap::new();
    for (index, row) in checks.into_iter().take(1000).rev().enumerate() {
        let key: String = row.try_get("endpoint_key")?;
        let d: serde_json::Value = row.try_get("diagnostic")?;
        let time = d["observed_at_unix_ms"].as_u64();
        let version = d["config_version"].as_i64();
        if d["status"]["checked_at_ms"].is_null()
            || d["status"]["valid_for_ms"].as_u64().unwrap_or(0) == 0
        {
            previous.remove(&key);
            continue;
        }
        if let (Some(time), Some(version), Some(available)) =
            (time, version, d["status"]["available"].as_bool())
            && let Some((old_time, old_version, old_available)) =
                previous.insert(key.clone(), (time, version, available))
            && time > old_time
            && time - old_time <= 90_000
            && version == old_version
            && available != old_available
            && input.version.is_none_or(|v| v == version)
        {
            items.push(serde_json::json!({"id":-(index as i64)-1,"action":if available {"upstream.recovered_observed"}else{"upstream.down_observed"},"target":key,"timestamp_ms":time,"config_version":version,"source":"endpoint_checks"}));
        }
    }
    let certificates=sqlx::query("SELECT id,action,target,config_version,(extract(epoch FROM observed_at)*1000)::bigint AS timestamp_ms FROM statistics_changes WHERE observed_at >= to_timestamp($1::double precision/1000) AND observed_at < to_timestamp($2::double precision/1000) AND ($3::bigint IS NULL OR config_version=$3) ORDER BY observed_at DESC,id DESC LIMIT 101").bind(input.start_ms).bind(input.end_ms).bind(input.version).fetch_all(&app.db).await?;
    let certificate_truncated = certificates.len() > 100;
    for r in certificates.into_iter().take(100) {
        items.push(serde_json::json!({"id":r.try_get::<i64,_>("id")?.saturating_add(1_000_000_000_000_000),"action":r.try_get::<String,_>("action")?,"target":r.try_get::<String,_>("target")?,"timestamp_ms":r.try_get::<i64,_>("timestamp_ms")?,"config_version":r.try_get::<i64,_>("config_version")?,"source":"certificate_metadata_observations"}));
    }
    items.sort_by_key(|item| std::cmp::Reverse(item["timestamp_ms"].as_i64().unwrap_or(0)));
    let truncated = items.len() > 100;
    items.truncate(100);
    Ok(Json(
        serde_json::json!({"source":"postgresql_audit","start_ms":input.start_ms,"end_ms":input.end_ms,"items":items,"may_have_more":more||truncated||checks_truncated||certificate_truncated,"observed_at_unix_ms":openwaf_telemetry::now_ms(),"endpoint_transitions":"bounded_observed_changes","endpoint_check_slice_limit":1000,"endpoint_check_slice_truncated":checks_truncated,"causation":"not_established"}),
    ))
}
/// Existing endpoint sampler owns this work. Metadata changes are observations,
/// not proof of public CA issuance/ACME success. Persist baseline across restart.
pub(super) async fn observe_certificates(app: &App) -> Result<()> {
    let Some(config) = &app.config else {
        return Ok(());
    };
    let version = config.store.load().version;
    let statuses = app
        .application_tls
        .as_ref()
        .map_or_else(Vec::new, |tls| tls.certificates());
    anyhow::ensure!(statuses.len() <= 256, "certificate observation capacity");
    let mut tx = app.db.begin().await?;
    for status in statuses {
        persist_certificate(&mut tx, &status, version).await?;
    }
    sqlx::query("DELETE FROM statistics_certificates WHERE observed_at<now()-interval '30 days' OR hostname IN (SELECT hostname FROM statistics_certificates ORDER BY observed_at DESC,hostname OFFSET 256)").execute(&mut *tx).await?;
    sqlx::query("DELETE FROM statistics_changes WHERE observed_at<now()-interval '30 days' OR id IN (SELECT id FROM statistics_changes ORDER BY id DESC OFFSET 10000)").execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn persist_certificate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    status: &openwaf_tls::CertificateStatus,
    version: i64,
) -> Result<()> {
    let metadata = serde_json::to_value(status)?;
    let old: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT metadata FROM statistics_certificates WHERE hostname=$1 FOR UPDATE",
    )
    .bind(&status.hostname)
    .fetch_optional(&mut **tx)
    .await?;
    if old.as_ref().is_some_and(|old| *old != metadata) {
        let action = if old
            .as_ref()
            .and_then(|o| o["valid_from_unix_s"].as_i64())
            .is_some_and(|t| status.valid_from_unix_s > t)
        {
            "certificate.renewal_observed"
        } else {
            "certificate.metadata_changed"
        };
        let result = sqlx::query(
            "INSERT INTO statistics_changes(action,target,config_version) VALUES($1,$2,$3)",
        )
        .bind(action)
        .bind(&status.hostname)
        .bind(version)
        .execute(&mut **tx)
        .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "certificate marker not written"
        );
    }
    let result=sqlx::query("INSERT INTO statistics_certificates(hostname,metadata) VALUES($1,$2) ON CONFLICT(hostname) DO UPDATE SET metadata=excluded.metadata,observed_at=now()").bind(&status.hostname).bind(metadata).execute(&mut **tx).await?;
    anyhow::ensure!(
        result.rows_affected() == 1,
        "certificate baseline not written"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn investigation_url_numeric_filters_deserialize_with_existing_queries() {
        let uri:axum::http::Uri="/api/v1/history/traffic?start_ms=1&end_ms=2&limit=100&route_id=record&config_version=1&rule_id=941101&status_class=4".parse().expect("URI");
        let axum::extract::Query(query) =
            axum::extract::Query::<openwaf_storage::Query>::try_from_uri(&uri).expect("URL query");
        assert_eq!(query.config_version, Some(1));
        assert_eq!(query.rule_id, Some(941101));
        assert!(query.validate().is_ok());
    }
    #[test]
    fn historical_configuration_is_not_resolved_using_current_snapshot() {
        let old:Document=serde_json::from_value(serde_json::json!({"routes":[{"id":"r","hostname":"old.test","path":"/","path_match":"prefix","upstream":"backend","timeouts":{"connect_ms":123}}],"upstreams":[]})).expect("doc");
        let value =
            description(&old, "r").unwrap_or_else(|_| panic!("route description unavailable"));
        assert_eq!(value["effective_timeouts"]["connect_ms"], 123);
        assert_eq!(value["effective_timeouts"]["tls_ms"], 123);
        assert_eq!(value["sources"]["timeouts"], "route");
        let mut custom = old.clone();
        custom.routes[0].retry.total_timeout_ms = Some(1000);
        let value2 =
            description(&custom, "r").unwrap_or_else(|_| panic!("custom route unavailable"));
        assert_eq!(value2["effective_timeouts"]["total_ms"], 1000);
        assert_eq!(value2["effective_timeouts"]["request_body_idle_ms"], 30000);
        assert_eq!(value["sources"]["waf"], "runtime_default_not_collected");
        assert!(matches!(description(&old, "deleted"), Err(Error::NotFound)));
    }
    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via OPENWAF_STATISTICS_TEST_DATABASE_URL"]
    async fn postgres_certificate_baseline_does_not_invent_renewal_on_restart() {
        let url =
            std::env::var("OPENWAF_STATISTICS_TEST_DATABASE_URL").expect("isolated PostgreSQL");
        let db = sqlx::PgPool::connect(&url).await.expect("db");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("migrations");
        let mut tx = db.begin().await.expect("transaction");
        sqlx::query("DELETE FROM statistics_changes WHERE target='marker.test'")
            .execute(&mut *tx)
            .await
            .expect("cleanup");
        sqlx::query("DELETE FROM statistics_certificates WHERE hostname='marker.test'")
            .execute(&mut *tx)
            .await
            .expect("baseline cleanup");
        let mut status = openwaf_tls::CertificateStatus {
            hostname: "marker.test".into(),
            dns_names: vec!["marker.test".into()],
            valid_from_unix_s: 100,
            valid_until_unix_s: 200,
        };
        persist_certificate(&mut tx, &status, 1)
            .await
            .expect("initial observation");
        tx.commit().await.expect("commit");
        let mut tx = db.begin().await.expect("restart transaction");
        persist_certificate(&mut tx, &status, 2)
            .await
            .expect("unchanged certificate after restart");
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM statistics_changes WHERE target='marker.test'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("count");
        assert_eq!(count, 0);
        status.valid_from_unix_s = 150;
        status.valid_until_unix_s = 250;
        persist_certificate(&mut tx, &status, 3)
            .await
            .expect("changed validity");
        let action: String =
            sqlx::query_scalar("SELECT action FROM statistics_changes WHERE target='marker.test'")
                .fetch_one(&mut *tx)
                .await
                .expect("one marker");
        assert_eq!(action, "certificate.renewal_observed");
        tx.rollback()
            .await
            .expect("rollback marker and baseline together");
        let old: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM statistics_certificates WHERE hostname='marker.test'",
        )
        .fetch_one(&db)
        .await
        .expect("old baseline retained");
        assert_eq!(old["valid_from_unix_s"], 100);
        db.close().await;
    }
}
