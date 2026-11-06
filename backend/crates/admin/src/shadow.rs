//! Shadow sessions never apply a policy or send upstream traffic.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    #[serde(skip)]
    pub inspection_scope: String,
    pub route_id: String,
    pub policy: openwaf_config::waf::Policy,
    #[serde(default = "sampling")]
    pub sampling_percent: u8,
    #[serde(default = "duration")]
    pub duration_ms: u64,
}
fn sampling() -> u8 {
    10
}
fn duration() -> u64 {
    1800000
}
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn start(&self, input: Start, version: i64)
    -> std::result::Result<serde_json::Value, ()>;
    fn status(&self) -> serde_json::Value;
    fn stop(&self);
    async fn run(&self);
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/api/v1/security/shadow",
            get(status).post(start).delete(stop),
        )
        .route("/api/v1/security/exclusions", get(exclusions))
}
async fn status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let mut status = app.shadow.as_ref().ok_or(Error::Unavailable)?.status();
    let active_version = app
        .config
        .as_ref()
        .ok_or(Error::Unavailable)?
        .store
        .load()
        .version;
    status["active_config_version"] = active_version.into();
    status["config_changed"] = status["config_version"]
        .as_i64()
        .is_some_and(|v| v != active_version)
        .into();
    if status["config_changed"] == true {
        status["conclusion_limited"] = true.into();
    }
    status["observed_at_unix_ms"] = openwaf_telemetry::now_ms().into();
    Ok(Json(status))
}
async fn start(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(mut input): Json<Start>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    if !(1..=100).contains(&input.sampling_percent)
        || !(1000..=86400000).contains(&input.duration_ms)
        || input.policy.validate().is_err()
    {
        return Err(Error::Invalid);
    }
    let plane = app.config.as_ref().ok_or(Error::Unavailable)?;
    let snapshot = plane.store.load();
    if !snapshot
        .document
        .routes
        .iter()
        .any(|r| r.id == input.route_id)
    {
        return Err(Error::NotFound);
    }
    let route = snapshot
        .document
        .routes
        .iter()
        .find(|r| r.id == input.route_id)
        .ok_or(Error::NotFound)?;
    input.inspection_scope = if route
        .body
        .as_ref()
        .is_some_and(|b| b.inspection == openwaf_config::retry::Inspection::HeadersQueryOnly)
    {
        "headers_query_only"
    } else {
        "full_except_multipart"
    }
    .into();
    let mut tx = app.db.begin().await?;
    audit(
        &mut tx,
        Some(auth.id),
        "shadow.start_requested",
        &input.route_id,
        None,
    )
    .await?;
    tx.commit().await?;
    let result = app
        .shadow
        .as_ref()
        .ok_or(Error::Unavailable)?
        .start(input, snapshot.version)
        .await
        .map_err(|_| Error::Conflict)?;
    Ok(Json(result))
}
async fn stop(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let mut tx = app.db.begin().await?;
    audit(&mut tx, Some(auth.id), "shadow.stopped", "shadow", None).await?;
    tx.commit().await?;
    app.shadow.as_ref().ok_or(Error::Unavailable)?.stop();
    Ok(StatusCode::NO_CONTENT)
}

async fn exclusions(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let snapshot = app.config.as_ref().ok_or(Error::Unavailable)?.store.load();
    let now = openwaf_telemetry::now_ms();
    let routes: Vec<_> = snapshot.document.routes.iter().enumerate().filter_map(|(i,r)|r.waf.as_ref().map(|p|serde_json::json!({"route_id":r.id,"mode":p.mode,"summary":snapshot.waf_usage[i].summary(p,now)}))).collect();
    Ok(Json(
        serde_json::json!({"source":"gateway","observed_at_unix_ms":now,"config_version":snapshot.version,"scope":"active_config_process_lifetime","routes":routes,"matched_data_collected":false}),
    ))
}
