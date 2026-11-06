//! Session-protected, bounded SSE. Authentication is rechecked while streaming.
use super::*;
use axum::response::{
    Sse,
    sse::{Event, KeepAlive},
};
use futures_util::stream;
use openwaf_telemetry::Hub;
use std::convert::Infallible;
use tokio::sync::{OwnedSemaphorePermit, broadcast};

pub struct Service {
    pub bodies: Option<Arc<openwaf_storage::bodies::Service>>,
    pub hub: Arc<Hub>,
    pub history: Option<Arc<openwaf_storage::History>>,
    pub prometheus: Option<Arc<openwaf_storage::Prometheus>>,
    pub diagnostics: Option<Arc<dyn Fn() -> serde_json::Value + Send + Sync>>,
    pub scrape_token: Option<zeroize::Zeroizing<Vec<u8>>>,
    clients: Arc<Semaphore>,
    stopped: tokio::sync::watch::Sender<bool>,
}
impl Service {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self {
            bodies: None,
            hub,
            history: None,
            prometheus: None,
            diagnostics: None,
            scrape_token: None,
            clients: Arc::new(Semaphore::new(16)),
            stopped: tokio::sync::watch::channel(false).0,
        }
    }
    pub fn shutdown(&self) {
        self.stopped.send_replace(true);
    }
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/telemetry", get(snapshot))
        .route("/api/v1/telemetry/hosts", get(hosts))
        .route("/api/v1/telemetry/window", get(window))
        .route("/api/v1/requests/{id}", get(request))
        .route("/api/v1/requests/{id}/body", get(request_body))
        .route("/api/v1/events/metrics", get(metrics))
        .route("/api/v1/events/logs", get(logs))
        .route("/metrics", get(prometheus))
        .route("/api/v1/history/traffic", get(history))
        .route("/api/v1/history/metrics", get(metrics_history))
        .route("/api/v1/telemetry/storage", get(storage))
        .route("/api/v1/telemetry/dependencies", get(dependencies))
}
async fn dependencies(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let source = app
        .telemetry
        .as_ref()
        .and_then(|s| s.diagnostics.as_ref())
        .ok_or(Error::Unavailable)?;
    Ok(Json(source()))
}
/// All labels come from fixed server constants, never route IDs or clients.
fn resource_metrics(values: &serde_json::Value) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (resource, pointer) in [
        ("requests", "/admission/requests"),
        ("connections", "/admission/connections"),
        ("handshakes", "/admission/handshakes"),
        ("headers", "/admission/headers"),
        ("retry", "/retry_capacity"),
    ] {
        for field in ["active", "high_water", "admitted", "rejected"] {
            if let Some(n) = values
                .pointer(&format!("{pointer}/{field}"))
                .and_then(|v| v.as_u64())
            {
                let _ = writeln!(
                    out,
                    "openwaf_resource_{field}{{resource=\"{resource}\"}} {n}"
                );
            }
        }
    }
    for (index, class) in ["api", "upload", "stream", "critical"].iter().enumerate() {
        for field in ["active", "high_water", "admitted", "rejected"] {
            if let Some(n) = values["admission"]["classes"][index][field].as_u64() {
                let _ = writeln!(
                    out,
                    "openwaf_admission_class_{field}{{class=\"{class}\"}} {n}"
                );
            }
        }
        for kind in ["upload_slots", "stream_slots"] {
            for field in ["active", "high_water", "admitted", "rejected"] {
                if let Some(n) = values["admission"][kind][index][field].as_u64() {
                    let _ = writeln!(out, "openwaf_{kind}_{field}{{class=\"{class}\"}} {n}");
                }
            }
        }
        for field in ["keys", "high_water", "capacity_rejections"] {
            if let Some(n) = values["rate_limit"]["classes"][index][field].as_u64() {
                let _ = writeln!(out, "openwaf_rate_{field}{{class=\"{class}\"}} {n}");
            }
        }
    }
    for index in 0..8 {
        if let (Some(reason), Some(total)) = (
            values["admission"]["rejections"][index]["reason"].as_str(),
            values["admission"]["rejections"][index]["total"].as_u64(),
        ) {
            // Only our versioned fixed reason set is accepted as a label.
            if [
                "admission_global",
                "admission_class",
                "admission_route",
                "admission_client",
                "admission_keys",
                "admission_contention",
                "admission_upload",
                "admission_stream",
            ]
            .contains(&reason)
            {
                let _ = writeln!(
                    out,
                    "openwaf_admission_rejected_total{{reason=\"{reason}\"}} {total}"
                );
            }
        }
    }
    for (name, pointer) in [
        ("admitted_total", "/admission/admitted_total"),
        ("retry_slots", "/retry_slots"),
        ("rate_contention_total", "/rate_limit/contention_total"),
        ("health_active", "/health_capacity/active"),
        ("health_backlog", "/health_capacity/backlog"),
        ("health_deferred_total", "/health_capacity/deferred_total"),
        (
            "health_high_water_backlog",
            "/health_capacity/high_water_backlog",
        ),
        (
            "health_max_scheduling_delay_ms",
            "/health_capacity/max_scheduling_delay_ms",
        ),
        ("replay_memory_bytes", "/replay/memory_bytes"),
        ("replay_disk_bytes", "/replay/disk_bytes"),
        (
            "replay_high_water_memory_bytes",
            "/replay/high_water_memory_bytes",
        ),
        (
            "replay_high_water_disk_bytes",
            "/replay/high_water_disk_bytes",
        ),
        ("replay_io_slots", "/replay/io_slots"),
        ("replay_failures_total", "/replay/failures_total"),
        ("waf_registry_pools", "/waf_registry/pools"),
        ("waf_retired_pools", "/waf_registry/retired_pools"),
        ("waf_registry_queued", "/waf_registry/queued"),
        ("waf_registry_executing", "/waf_registry/executing"),
        (
            "waf_executing_after_cancel",
            "/waf_registry/executing_after_cancel",
        ),
        (
            "waf_completed_after_cancel",
            "/waf_registry/completed_after_cancel",
        ),
    ] {
        if let Some(n) = values.pointer(pointer).and_then(|v| v.as_u64()) {
            let _ = writeln!(out, "openwaf_{name} {n}");
        }
    }
    out
}

async fn metrics_history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<openwaf_storage::MetricsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let prometheus = app
        .telemetry
        .as_ref()
        .and_then(|s| s.prometheus.as_ref())
        .ok_or(Error::Unavailable)?;
    prometheus
        .query(query)
        .await
        .map(Json)
        .map_err(|e| match e {
            openwaf_storage::QueryError::Invalid => Error::Invalid,
            openwaf_storage::QueryError::Unavailable => Error::Unavailable,
        })
}
async fn history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<openwaf_storage::Query>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let history = app
        .telemetry
        .as_ref()
        .and_then(|s| s.history.as_ref())
        .ok_or(Error::Unavailable)?;
    history.query(query).await.map(Json).map_err(|e| match e {
        openwaf_storage::QueryError::Invalid => Error::Invalid,
        openwaf_storage::QueryError::Unavailable => Error::Unavailable,
    })
}
async fn storage(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    Ok(Json(service.history.as_ref().map_or_else(
        || serde_json::json!({"configured": false, "degraded": true}),
        |h| serde_json::json!(h.health.snapshot()),
    )))
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsFilter {
    host: Option<String>,
}
impl MetricsFilter {
    fn selected(&self, hub: &Hub) -> ApiResult<Option<Arc<openwaf_telemetry::hosts::Host>>> {
        self.host
            .as_ref()
            .map(|name| {
                if !openwaf_telemetry::hosts::valid_name(name) {
                    return Err(Error::Invalid);
                }
                hub.hosts.get(name).ok_or(Error::NotFound)
            })
            .transpose()
    }
}
async fn hosts(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    let mut hosts: Vec<_> = service
        .hub
        .hosts
        .iter()
        .map(|host| host.name.clone())
        .collect();
    hosts.sort();
    Ok(Json(
        serde_json::json!({"hosts": hosts, "capacity": openwaf_telemetry::hosts::CAPACITY, "overflow_requests": service.hub.hosts.overflow_requests.load(std::sync::atomic::Ordering::Relaxed), "observed_at_unix_ms": openwaf_telemetry::now_ms()}),
    ))
}
#[derive(serde::Deserialize)]
struct WindowFilter {
    host: Option<String>,
    path_prefix: Option<String>,
    window_seconds: Option<u64>,
}
async fn window(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(filter): axum::extract::Query<WindowFilter>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    let seconds = filter
        .window_seconds
        .unwrap_or(openwaf_telemetry::window::DEFAULT_WINDOW_SECONDS);
    openwaf_telemetry::window::Registry::validate(
        filter.host.as_deref(),
        filter.path_prefix.as_deref(),
        seconds,
    )
    .map_err(|_| Error::Invalid)?;
    let value = service.hub.window.snapshot(
        filter.host.as_deref(),
        filter.path_prefix.as_deref(),
        seconds,
        openwaf_telemetry::now_ms(),
    );
    Ok(Json(
        serde_json::to_value(value).map_err(|_| Error::Unavailable)?,
    ))
}
async fn snapshot(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(filter): axum::extract::Query<MetricsFilter>,
) -> ApiResult<Json<Arc<openwaf_telemetry::Metrics>>> {
    authenticate(&app, &headers, false).await?;
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    let host = filter.selected(&service.hub)?;
    Ok(Json(host.map_or_else(
        || service.hub.metrics.borrow().clone(),
        |host| host.metrics.borrow().clone(),
    )))
}
async fn prometheus(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    // Public dashboard routing preserves Host. Only local scrapes may address
    // this endpoint; session/token authentication below is still mandatory.
    let local_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<axum::http::uri::Authority>().ok())
        .is_some_and(|v| matches!(v.host(), "127.0.0.1" | "[::1]" | "localhost"));
    if !local_host {
        return Err(Error::NotFound);
    }
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    let trusted = service
        .scrape_token
        .as_ref()
        .zip(bearer)
        .is_some_and(|(expected, value)| {
            expected.len() == value.len() && openssl::memcmp::eq(expected, value.as_bytes())
        });
    if !trusted {
        authenticate(&app, &headers, false).await?;
    }
    let mut exported = service.hub.prometheus();
    use std::fmt::Write;
    if let Some(history) = &service.history {
        let health = history.health.snapshot();
        for (name, kind, value) in [
            ("history_degraded", "gauge", u64::from(health.degraded)),
            ("history_backlog", "gauge", health.backlog),
            ("history_dropped_total", "counter", health.dropped),
            ("history_written_total", "counter", health.written),
        ] {
            let _ = writeln!(
                exported,
                "# TYPE openwaf_{name} {kind}\nopenwaf_{name} {value}"
            );
        }
    }
    if let Some(diagnostics) = &service.diagnostics {
        let values = diagnostics();
        exported.push_str(&resource_metrics(&values));
        for (name, value) in [
            ("waf_queue_depth", values["waf"]["queued"].as_u64()),
            ("waf_executing", values["waf"]["executing"].as_u64()),
            (
                "crowdsec_degraded",
                values["crowdsec"]["degraded"].as_bool().map(u64::from),
            ),
        ] {
            if let Some(value) = value {
                let _ = writeln!(
                    exported,
                    "# TYPE openwaf_{name} gauge\nopenwaf_{name} {value}"
                );
            }
        }
    }
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        exported,
    )
        .into_response())
}

enum Source {
    Metrics(tokio::sync::watch::Receiver<Arc<openwaf_telemetry::Metrics>>),
    Logs(broadcast::Receiver<Arc<openwaf_telemetry::LiveLog>>),
}
struct Client {
    app: Arc<App>,
    headers: HeaderMap,
    epoch: String,
    _permit: OwnedSemaphorePermit,
    source: Source,
    heartbeat: tokio::time::Interval,
    initial: Option<Event>,
    sequence: u64,
    kind: &'static str,
    stopped: tokio::sync::watch::Receiver<bool>,
}
fn event(kind: &str, id: String, value: impl Serialize) -> Event {
    // All payloads are owned primitive metadata; encoding cannot contain secrets.
    Event::default()
        .event(kind)
        .id(id)
        .json_data(value)
        .unwrap_or_else(|_| Event::default().event("unavailable").data("{}"))
}
fn id(epoch: &str, kind: &str, sequence: u64) -> String {
    format!("{epoch}:{kind}:{sequence}")
}
async fn metrics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(filter): axum::extract::Query<MetricsFilter>,
) -> ApiResult<Response> {
    subscribe(app, headers, true, filter).await
}
async fn logs(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Response> {
    subscribe(app, headers, false, MetricsFilter::default()).await
}

async fn subscribe(
    app: Arc<App>,
    headers: HeaderMap,
    metrics: bool,
    filter: MetricsFilter,
) -> ApiResult<Response> {
    authenticate(&app, &headers, false).await?;
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    if *service.stopped.borrow() {
        return Err(Error::Unavailable);
    }
    let permit = service
        .clients
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable)?;
    let hub = service.hub.clone();
    let host = filter.selected(&hub)?;
    let metrics_sender = host.as_ref().map_or(&hub.metrics, |host| &host.metrics);
    let source = if metrics {
        Source::Metrics(metrics_sender.subscribe())
    } else {
        Source::Logs(hub.logs.subscribe())
    };
    let kind = if metrics { "metrics" } else { "logs" };
    let sequence = if metrics {
        metrics_sender.borrow().sequence
    } else {
        hub.log_sequence.load(std::sync::atomic::Ordering::Relaxed)
    };
    let epoch = if metrics {
        metrics_sender.borrow().epoch.clone()
    } else {
        hub.epoch.clone()
    };
    let current = id(&epoch, kind, sequence);
    let cursor = headers.get("last-event-id").and_then(|v| v.to_str().ok());
    if cursor.is_some_and(|v| v.len() > 128) {
        return Err(Error::Invalid);
    }
    let initial = event(
        "sync",
        current,
        serde_json::json!({"schema_version": 1, "epoch": epoch, "sequence": sequence, "gap": cursor.is_some_and(|c| c != id(&epoch, kind, sequence)), "reason": "no_replay", "snapshot": if metrics { Some(metrics_sender.borrow().clone()) } else { None }}),
    );
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await;
    let stopped = service.stopped.subscribe();
    let state = Client {
        app,
        headers,
        epoch,
        _permit: permit,
        source,
        heartbeat,
        initial: Some(initial),
        sequence,
        kind,
        stopped,
    };
    let stream = stream::unfold(state, |mut state| async move {
        if *state.stopped.borrow() {
            return None;
        }
        if let Some(event) = state.initial.take() {
            return Some((Ok::<_, Infallible>(event), state));
        }
        loop {
            tokio::select! {
                _ = state.stopped.changed() => return None,
                _ = state.heartbeat.tick() => {
                    if !matches!(tokio::time::timeout(Duration::from_secs(3), authenticate(&state.app, &state.headers, false)).await, Ok(Ok(_))) { return None; }
                    let event = event("heartbeat", id(&state.epoch, state.kind, state.sequence), serde_json::json!({"observed_at_unix_ms": openwaf_telemetry::now_ms()}));
                    return Some((Ok(event), state));
                }
                next = async {
                    match &mut state.source {
                        Source::Metrics(receiver) => {
                            receiver.changed().await.ok()?;
                            let metrics = receiver.borrow_and_update().clone();
                            Some((metrics.sequence, "metrics", serde_json::to_value(metrics).ok()?))
                        }
                        Source::Logs(receiver) => match receiver.recv().await {
                            Ok(log) => Some((log.sequence, "log", serde_json::to_value(log).ok()?)),
                            Err(broadcast::error::RecvError::Lagged(count)) => Some((state.sequence, "gap", serde_json::json!({"lost": count, "reason": "slow_consumer"}))),
                            Err(broadcast::error::RecvError::Closed) => None,
                        },
                    }
                } => {
                    let (sequence, kind, value) = next?;
                    if kind != "gap" && sequence <= state.sequence { continue; }
                    let gap = kind != "gap" && sequence > state.sequence + 1;
                    let previous = state.sequence;
                    state.sequence = sequence;
                    let event = event(kind, id(&state.epoch, state.kind, sequence), serde_json::json!({"gap": gap, "previous_sequence": previous, "data": value}));
                    return Some((Ok(event), state));
                }
            }
        }
    });
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

fn recording_marker(details: &str) -> Option<serde_json::Value> {
    let details: serde_json::Value = serde_json::from_str(details).ok()?;
    let record: openwaf_storage::bodies::Record =
        serde_json::from_value(details.get("body_recording")?.clone()).ok()?;
    serde_json::to_value(record.marker()).ok()
}

async fn request_body(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    authenticate(&app, &headers, false).await?;
    if !openwaf_telemetry::request_id::valid(&id) {
        return Err(Error::Invalid);
    }
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    let respond = |value: serde_json::Value| {
        let mut response = Json(value).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    };
    if let Some(record) = service
        .bodies
        .as_ref()
        .and_then(|bodies| bodies.lookup(&id))
    {
        return Ok(respond(
            serde_json::to_value(record).map_err(|_| Error::Unavailable)?,
        ));
    }
    if let Some(record) = service.hub.lookup(&id)
        && let Some(marker) = recording_marker(&record.details)
        && marker["request"]["status"] == "disabled"
        && marker["response"]["status"] == "disabled"
        && marker["query"]["status"] == "disabled"
    {
        return Ok(respond(marker));
    }
    let history = match &service.history {
        Some(history) => history.query_bodies(&id).await,
        None => Err(openwaf_storage::QueryError::Unavailable),
    };
    if let Ok(Some(record)) = &history {
        return Ok(respond(
            serde_json::to_value(record).map_err(|_| Error::Unavailable)?,
        ));
    }
    // Only bounded capture markers live in the ordinary traffic contract.
    let Json(value) = request(State(app.clone()), headers, Path(id)).await?;
    let Some(mut marker) = value["record"]["details"]
        .as_str()
        .and_then(recording_marker)
    else {
        return Ok(respond(
            serde_json::json!({"request":{"status":"unavailable","reason":"not_collected"},"response":{"status":"unavailable","reason":"not_collected"},"query":{"status":"unavailable","reason":"not_collected"}}),
        ));
    };
    let now = openwaf_telemetry::now_ms();
    let age = now.saturating_sub(marker["observed_at_unix_ms"].as_u64().unwrap_or(0));
    if marker["persistence"] == "pending" && history.is_err() {
        marker["persistence"] = serde_json::json!(if service.history.is_some() {
            "failed_or_uncertain"
        } else {
            "not_configured"
        });
        for key in ["request", "response", "query"] {
            if marker[key]["status"] == "pending" {
                marker[key]["status"] = serde_json::json!("unavailable");
                marker[key]["reason"] = serde_json::json!("history_unavailable");
            }
        }
    } else if marker["persistence"] == "pending" && age > 30000 {
        marker["persistence"] = serde_json::json!("dropped");
        for key in ["request", "response", "query"] {
            if marker[key]["status"] == "pending" {
                marker[key]["status"] = serde_json::json!("dropped");
                marker[key]["reason"] = serde_json::json!("capture_not_retained");
            }
        }
    }
    Ok(respond(marker))
}

async fn request(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    if !openwaf_telemetry::request_id::valid(&id) {
        return Err(Error::Invalid);
    }
    let service = app.telemetry.as_ref().ok_or(Error::Unavailable)?;
    if let Some(record) = service.hub.lookup(&id) {
        return Ok(Json(
            serde_json::json!({"source":"live_ring","record":record}),
        ));
    }
    let history = service.history.as_ref().ok_or(Error::Unavailable)?;
    let end = openwaf_telemetry::now_ms() + 1;
    let value = history
        .query(openwaf_storage::Query {
            start_ms: end.saturating_sub(7 * 86400000),
            end_ms: end,
            limit: 1,
            security_only: false,
            request_id: Some(id),
            host: None,
            path: None,
            country: None,
            ..Default::default()
        })
        .await
        .map_err(|_| Error::Unavailable)?;
    if let Some(record) = value["items"].as_array().and_then(|v| v.first()) {
        return Ok(Json(
            serde_json::json!({"source":"clickhouse","record":record,"health":value["health"]}),
        ));
    }
    Err(Error::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_filter_validation_bounds_host_prefix_and_window() {
        use openwaf_telemetry::window::Registry;
        assert!(Registry::validate(Some("EXAMPLE.test"), Some("/api"), 900).is_ok());
        assert!(Registry::validate(Some("example.test/path"), None, 900).is_err());
        assert!(Registry::validate(None, Some("/api?secret=value"), 900).is_err());
        assert!(Registry::validate(None, Some(&"x".repeat(2049)), 900).is_err());
        assert!(Registry::validate(None, None, 901).is_err());
    }

    #[test]
    fn recovered_markers_reject_malformed_shapes_and_omit_any_content() {
        for details in [
            "invalid",
            "{}",
            r#"{"body_recording":{}}"#,
            r#"{"body_recording":{"request":null}}"#,
        ] {
            assert!(recording_marker(details).is_none());
        }
        let side = serde_json::json!({"status":"pending","reason":null,"bytes":12,"content_type":"application/json","content":"must_not_appear_in_marker"});
        let details = serde_json::json!({"body_recording":{"request_id":"a".repeat(64),"observed_at_unix_ms":1,"request":side,"response":side,"query":side,"persistence":"pending"}}).to_string();
        let marker = recording_marker(&details).expect("typed marker");
        assert!(marker["request"]["content"].is_null());
        assert!(marker["response"]["content"].is_null());
        assert!(marker["query"]["content"].is_null());
        assert!(!marker.to_string().contains("must_not_appear_in_marker"));
    }

    #[test]
    fn metrics_scope_never_falls_back_to_global_for_invalid_or_unknown_host() {
        let (hub, _) = Hub::new();
        let mut request = hub.start("GET");
        request.host("app.test");
        assert!(
            MetricsFilter::default()
                .selected(&hub)
                .is_ok_and(|host| host.is_none())
        );
        let selected = MetricsFilter {
            host: Some("app.test".into()),
        }
        .selected(&hub)
        .ok()
        .flatten()
        .expect("host scope");
        assert_eq!(selected.name, "app.test");
        assert_ne!(
            id(&selected.metrics.borrow().epoch, "metrics", 1),
            id(&hub.epoch, "metrics", 1)
        );
        assert!(matches!(
            MetricsFilter {
                host: Some("unknown.test".into())
            }
            .selected(&hub),
            Err(Error::NotFound)
        ));
        for invalid in [
            "",
            "app.test/path",
            "https://app.test",
            "app.test\"",
            "APP.TEST",
        ] {
            assert!(matches!(
                MetricsFilter {
                    host: Some(invalid.into())
                }
                .selected(&hub),
                Err(Error::Invalid)
            ));
        }
    }
}
