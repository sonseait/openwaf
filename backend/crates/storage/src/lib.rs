//! Traffic history has independent, bounded failure and cancellation domains.
#![forbid(unsafe_code)]
pub mod bodies;
pub mod rollup;
use anyhow::{Result, ensure};
use openwaf_telemetry::LiveLog;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, broadcast};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS openwaf_traffic_v1 (epoch String, sequence UInt64, observed_at_unix_ms UInt64, method LowCardinality(String), status UInt16, latency_ms UInt64, config_version Int64, route_index Nullable(UInt64), forwarded Bool, blocked Bool, upstream_error Bool, request_id String DEFAULT '', details String DEFAULT '{}', observed_at DateTime MATERIALIZED toDateTime(intDiv(observed_at_unix_ms, 1000))) ENGINE = MergeTree ORDER BY (observed_at_unix_ms, epoch, sequence) TTL observed_at + INTERVAL 7 DAY DELETE";
const INSERT: &str = "INSERT INTO openwaf_traffic_v1 (epoch, sequence, observed_at_unix_ms, method, status, latency_ms, config_version, route_index, forwarded, blocked, upstream_error, request_id, details) FORMAT JSONEachRow";
pub const BATCH: usize = 100;
const RESPONSE_LIMIT: usize = 512 * 1024;
// 100 bounded 16-KiB detail strings, including JSON escaping and row metadata.
const HISTORY_RESPONSE_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub struct Health {
    degraded: AtomicBool,
    pub dropped: AtomicU64,
    pub written: AtomicU64,
    pub backlog: AtomicU64,
    last_success: AtomicU64,
    last_error: AtomicU64,
    last_http_status: AtomicU64,
}
#[derive(Serialize)]
pub struct Status {
    pub configured: bool,
    pub degraded: bool,
    pub dropped: u64,
    pub written: u64,
    pub backlog: u64,
    pub last_success_unix_ms: u64,
    pub last_error: Option<&'static str>,
    pub last_http_status: u64,
}
impl Health {
    pub fn snapshot(&self) -> Status {
        Status {
            configured: true,
            degraded: self.degraded.load(Relaxed),
            dropped: self.dropped.load(Relaxed),
            written: self.written.load(Relaxed),
            backlog: self.backlog.load(Relaxed),
            last_success_unix_ms: self.last_success.load(Relaxed),
            last_error: match self.last_error.load(Relaxed) {
                0 => None,
                1 => Some("transport_or_timeout"),
                2 => Some("http_status"),
                3 => Some("response_limit"),
                _ => Some("response_read"),
            },
            last_http_status: self.last_http_status.load(Relaxed),
        }
    }
}

pub struct History {
    client: reqwest::Client,
    url: reqwest::Url,
    pub health: Health,
    pub rollup_health: Health,
    queries: Arc<Semaphore>,
}
impl History {
    /// Address is operator-configured, never derived from a request or a log.
    /// Credentials are supplied as a sensitive header by the control plane.
    pub fn new(url: &str, user: Option<&str>, password: Option<&str>) -> Result<Arc<Self>> {
        let url =
            reqwest::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid history service URL"))?;
        ensure!(
            ["http", "https"].contains(&url.scheme())
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "history URL requires a plain HTTP(S) origin without credentials"
        );
        ensure!(
            url.scheme() == "https"
                || url.host_str().is_some_and(|h| h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())),
            "remote history requires HTTPS"
        );
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(user) = user {
            let mut value = reqwest::header::HeaderValue::from_str(user)
                .map_err(|_| anyhow::anyhow!("invalid history user"))?;
            value.set_sensitive(true);
            headers.insert("x-clickhouse-user", value);
        }
        if let Some(password) = password {
            let mut value = reqwest::header::HeaderValue::from_str(password)
                .map_err(|_| anyhow::anyhow!("invalid history password"))?;
            value.set_sensitive(true);
            headers.insert("x-clickhouse-key", value);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .pool_max_idle_per_host(2)
            .default_headers(headers)
            .build()
            .map_err(|_| anyhow::anyhow!("history HTTP client unavailable"))?;
        Ok(Arc::new(Self {
            client,
            url,
            health: Health {
                degraded: AtomicBool::new(true),
                ..Default::default()
            },
            rollup_health: Health {
                degraded: AtomicBool::new(true),
                ..Default::default()
            },
            queries: Arc::new(Semaphore::new(2)),
        }))
    }
    async fn execute(&self, query: &str, body: String) -> Result<Vec<u8>, ()> {
        let mut response = self
            .client
            .post(self.url.clone())
            .query(&[
                ("query", query),
                ("database", "default"),
                ("max_execution_time", "1"),
                ("max_result_bytes", "4194304"),
                ("max_memory_usage", "67108864"),
                ("max_threads", "1"),
                ("wait_end_of_query", "1"),
                ("buffer_size", "524288"),
            ])
            // ClickHouse rejects POST without framing, including an empty DDL/query body.
            .header(reqwest::header::CONTENT_LENGTH, body.len())
            .body(body)
            .send()
            .await
            .map_err(|_| {
                self.health.last_error.store(1, Relaxed);
            })?;
        self.health
            .last_http_status
            .store(u64::from(response.status().as_u16()), Relaxed);
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|v| v > HISTORY_RESPONSE_LIMIT as u64)
        {
            self.health
                .last_error
                .store(if response.status().is_success() { 3 } else { 2 }, Relaxed);
            return Err(());
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            self.health.last_error.store(4, Relaxed);
        })? {
            if chunk.len() > HISTORY_RESPONSE_LIMIT - data.len() {
                self.health.last_error.store(3, Relaxed);
                return Err(());
            }
            data.extend_from_slice(&chunk);
        }
        self.health.last_error.store(0, Relaxed);
        Ok(data)
    }
    pub async fn run(self: Arc<Self>, logs: broadcast::Receiver<Arc<LiveLog>>) {
        let (_owner, stop) = tokio::sync::watch::channel(false);
        self.run_until(logs, stop).await;
    }
    /// After the aggregator has stopped, finish the current batch and discard
    /// excess backlog explicitly. At most one final batch is sent; no ACK retry.
    pub async fn run_until(
        self: Arc<Self>,
        mut logs: broadcast::Receiver<Arc<LiveLog>>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut initialized = false;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut batch = Vec::with_capacity(BATCH);
        let mut draining = *stop.borrow();
        loop {
            if !draining {
                tokio::select! {
                    biased;
                    _ = stop.changed() => { draining = true; },
                    log = logs.recv(), if batch.len() < BATCH => match log {
                        Ok(log) => { batch.push(log); self.health.backlog.store(batch.len() as u64 + logs.len() as u64, Relaxed); if batch.len() < BATCH { continue; } },
                        Err(broadcast::error::RecvError::Lagged(count)) => { self.health.dropped.fetch_add(count, Relaxed); continue; },
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = tick.tick() => {},
                }
            }
            if draining {
                loop {
                    match logs.try_recv() {
                        Ok(log) if batch.len() < BATCH => batch.push(log),
                        Ok(_) => {
                            self.health.dropped.fetch_add(1, Relaxed);
                        }
                        Err(broadcast::error::TryRecvError::Lagged(n)) => {
                            self.health.dropped.fetch_add(n, Relaxed);
                        }
                        Err(_) => break,
                    }
                }
                self.health.backlog.store(batch.len() as u64, Relaxed);
                if batch.is_empty() {
                    break;
                }
                // Do not spend the stop budget creating/migrating a table.
                if !initialized {
                    self.health.dropped.fetch_add(batch.len() as u64, Relaxed);
                    self.health.degraded.store(true, Relaxed);
                    self.health.backlog.store(0, Relaxed);
                    break;
                }
            }
            // Retry schema creation on a later tick. Outage cannot stop live metrics.
            if !initialized {
                initialized = self.execute(SCHEMA, String::new()).await.is_ok();
                if initialized {
                    initialized = self.execute("ALTER TABLE openwaf_traffic_v1 ADD COLUMN IF NOT EXISTS request_id String DEFAULT '', ADD COLUMN IF NOT EXISTS details String DEFAULT '{}'", String::new()).await.is_ok();
                }
            }
            let mut success = initialized;
            // An idle tick must verify reachability/table access before clearing degraded.
            // A cached successful CREATE is not evidence that an outage has recovered.
            if initialized && batch.is_empty() {
                success = self
                    .execute("SELECT 1 FROM openwaf_traffic_v1 LIMIT 0", String::new())
                    .await
                    .is_ok();
            }
            if initialized && !batch.is_empty() {
                let mut body = String::new();
                for log in &batch {
                    match serde_json::to_string(log.as_ref()) {
                        Ok(row) => {
                            body.push_str(&row);
                            body.push('\n');
                        }
                        Err(_) => {
                            success = false;
                            break;
                        }
                    }
                }
                if success {
                    // No automatic insert retry: a lost ACK can mean the batch committed.
                    // Drop/uncertain counter makes that ambiguity visible instead of duplicating it.
                    success = self
                        .execute(INSERT, body)
                        .await
                        .is_ok_and(|reply| reply.is_empty());
                }
            }
            self.health.degraded.store(!success, Relaxed);
            if success {
                self.health.written.fetch_add(batch.len() as u64, Relaxed);
                self.health
                    .last_success
                    .store(openwaf_telemetry::now_ms(), Relaxed);
            } else {
                self.health.dropped.fetch_add(batch.len() as u64, Relaxed);
            }
            batch.clear();
            self.health.backlog.store(logs.len() as u64, Relaxed);
            if draining {
                break;
            }
        }
    }
    pub async fn query(&self, request: Query) -> Result<serde_json::Value, QueryError> {
        request.validate()?;
        let _permit = self
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Unavailable)?;
        let security = if request.security_only {
            "AND blocked = true"
        } else {
            ""
        };
        let request_id = request
            .request_id
            .as_ref()
            .map_or(String::new(), |id| format!("AND request_id = '{id}'"));
        let filters = request.filters_sql();
        // User text is encoded as hex data, never interpolated as SQL syntax.
        let query = format!(
            "SELECT epoch, sequence, observed_at_unix_ms, method, status, latency_ms, config_version, route_index, forwarded, blocked, upstream_error, request_id, details FROM openwaf_traffic_v1 WHERE observed_at_unix_ms >= {} AND observed_at_unix_ms < {} {security} {request_id} {filters} ORDER BY observed_at_unix_ms DESC, epoch DESC, sequence DESC LIMIT {} FORMAT JSON",
            request.start_ms, request.end_ms, request.limit
        );
        let bytes = self
            .execute(&query, String::new())
            .await
            .map_err(|_| QueryError::Unavailable)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| QueryError::Unavailable)?;
        if !value.get("data").is_some_and(|v| v.is_array()) {
            return Err(QueryError::Unavailable);
        }
        Ok(
            serde_json::json!({"source": "clickhouse", "observed_at_unix_ms": openwaf_telemetry::now_ms(), "start_ms": request.start_ms, "end_ms": request.end_ms, "limit": request.limit, "may_have_more": value["data"].as_array().is_some_and(|v| v.len() == request.limit), "items": value["data"], "health": self.health.snapshot()}),
        )
    }
}
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub start_ms: u64,
    pub end_ms: u64,
    pub limit: usize,
    #[serde(default)]
    pub security_only: bool,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub route_id: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub config_version: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub layer: Option<String>,
    #[serde(default)]
    pub rule_id: Option<u32>,
    #[serde(default)]
    pub status_class: Option<u16>,
}
#[derive(Debug)]
pub enum QueryError {
    Invalid,
    Unavailable,
}
impl Query {
    fn investigation(&self) -> Investigation {
        Investigation {
            route_id: self.route_id.clone(),
            client_ip: self.client_ip.clone(),
            config_version: self.config_version,
            action: self.action.clone(),
            layer: self.layer.clone(),
            rule_id: self.rule_id,
            status_class: self.status_class,
        }
    }
    fn filters_sql(&self) -> String {
        let mut filters = String::new();
        for (value, field, function) in [
            (&self.host, "host", "positionCaseInsensitiveUTF8"),
            (&self.path, "path", "position"),
        ] {
            if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
                let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
                filters.push_str(&format!(" AND {function}(JSONExtractString(details, 'metadata', 'request', '{field}'), unhex('{hex}')) > 0"));
            }
        }
        if let Some(country) = self.country.as_ref().filter(|value| !value.is_empty()) {
            let hex: String = country
                .to_ascii_uppercase()
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect();
            filters.push_str(&format!(" AND JSONExtractString(details, 'metadata', 'client', 'country_code') = unhex('{hex}')"));
        }
        filters.push_str(&self.investigation().sql());
        filters
    }
    pub fn validate(&self) -> Result<(), QueryError> {
        self.investigation().validate()?;
        if self.country.as_ref().is_some_and(|country| {
            !country.is_empty()
                && (country.len() != 2 || !country.bytes().all(|b| b.is_ascii_alphabetic()))
        }) || self.host.as_ref().is_some_and(|host| {
            host.len() > 253
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        }) || self.path.as_ref().is_some_and(|path| {
            path.len() > 2048
                || path
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '?' | '#'))
        }) || self
            .request_id
            .as_ref()
            .is_some_and(|id| !openwaf_telemetry::request_id::valid(id))
            || self.limit == 0
            || self.limit > 100
            || self.start_ms >= self.end_ms
            || self.end_ms - self.start_ms
                > if self.request_id.is_some() {
                    7 * 86_400_000
                } else {
                    86_400_000
                }
            || self.end_ms > openwaf_telemetry::now_ms() + 60_000
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}

/// Fixed PromQL selections: browsers cannot submit arbitrary queries or URLs.
pub struct Prometheus(Arc<History>);
impl Prometheus {
    pub fn new(url: &str) -> Result<Arc<Self>> {
        Ok(Arc::new(Self(History::new(url, None, None)?)))
    }
    pub async fn query(&self, request: MetricsQuery) -> Result<serde_json::Value, QueryError> {
        let now = openwaf_telemetry::now_ms() / 1000;
        if request.start >= request.end
            || request.end > now + 60
            || request.end - request.start > 86400
            || request.step < 15
            || request.step > 3600
            || (request.end - request.start).div_ceil(request.step) > 1000
        {
            return Err(QueryError::Invalid);
        }
        let query = match request.series.as_str() {
            "incoming" => "sum(rate(openwaf_incoming_total[1m]))",
            "forwarded" => "sum(rate(openwaf_forwarded_total[1m]))",
            "blocked" => "sum(rate(openwaf_blocked_total[1m]))",
            "latency_p95" => {
                "histogram_quantile(0.95, sum by (le) (rate(openwaf_request_duration_seconds_bucket[1m])))"
            }
            "active_requests" => "sum(openwaf_active_requests)",
            _ => return Err(QueryError::Invalid),
        };
        let query = if let Some(host) = &request.host {
            if request.series != "incoming" || !openwaf_telemetry::hosts::valid_name(host) {
                return Err(QueryError::Invalid);
            }
            format!("sum(rate(openwaf_host_incoming_total{{host=\"{host}\"}}[1m]))")
        } else {
            query.to_owned()
        };
        let _permit = self
            .0
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Unavailable)?;
        let url = self
            .0
            .url
            .join("api/v1/query_range")
            .map_err(|_| QueryError::Unavailable)?;
        let mut response = self
            .0
            .client
            .get(url)
            .query(&[
                ("query", query.to_string()),
                ("start", request.start.to_string()),
                ("end", request.end.to_string()),
                ("step", request.step.to_string()),
                ("timeout", "1s".into()),
            ])
            .send()
            .await
            .map_err(|_| QueryError::Unavailable)?;
        if !response.status().is_success() {
            return Err(QueryError::Unavailable);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| QueryError::Unavailable)?
        {
            if chunk.len() > RESPONSE_LIMIT - data.len() {
                return Err(QueryError::Unavailable);
            }
            data.extend_from_slice(&chunk);
        }
        let value: serde_json::Value =
            serde_json::from_slice(&data).map_err(|_| QueryError::Unavailable)?;
        if value["status"] != "success" || value["data"]["resultType"] != "matrix" {
            return Err(QueryError::Unavailable);
        }
        Ok(
            serde_json::json!({"source": "prometheus", "observed_at_unix_ms": openwaf_telemetry::now_ms(), "series": request.series, "start": request.start, "end": request.end, "step": request.step, "data": value["data"]}),
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsQuery {
    pub start: u64,
    pub end: u64,
    pub step: u64,
    pub series: String,
    #[serde(default)]
    pub host: Option<String>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_filters_bound_input_and_encode_user_text_as_data() {
        let mut query = Query {
            start_ms: 1,
            end_ms: 2,
            limit: 100,
            security_only: false,
            request_id: None,
            host: Some("APP.test".into()),
            path: Some("/a'_%\\test".into()),
            country: None,
            ..Default::default()
        };
        assert!(query.validate().is_ok());
        let sql = query.filters_sql();
        assert!(sql.contains(
            "positionCaseInsensitiveUTF8(JSONExtractString(details, 'metadata', 'request', 'host')"
        ));
        assert!(sql.contains("position(JSONExtractString(details, 'metadata', 'request', 'path')"));
        assert!(!sql.contains("APP.test"));
        assert!(!sql.contains("/a'_%\\test"));
        for path in ["/bad?query", "/bad#fragment", "/bad\npath"] {
            query.path = Some(path.into());
            assert!(query.validate().is_err());
        }
        query.path = Some("é".repeat(1025));
        assert!(query.validate().is_err());
        query.path = None;
        query.host = Some("a".repeat(254));
        assert!(query.validate().is_err());
        query.host = Some("example.test' OR 1=1".into());
        assert!(query.validate().is_err());
        query.host = Some(String::new());
        query.path = Some(String::new());
        assert!(query.validate().is_ok());
        assert!(query.filters_sql().is_empty());
    }

    #[test]
    fn history_country_filter_validates_and_normalizes_exact_codes() {
        let mut query: Query = serde_json::from_value(serde_json::json!({
            "start_ms": 1, "end_ms": 2, "limit": 100
        }))
        .expect("existing callers may omit country");
        assert!(query.validate().is_ok());
        assert!(query.filters_sql().is_empty());
        for code in ["VN", "vn", "vN"] {
            query.country = Some(code.into());
            assert!(query.validate().is_ok());
            assert_eq!(
                query.filters_sql(),
                " AND JSONExtractString(details, 'metadata', 'client', 'country_code') = unhex('564e')"
            );
        }
        for invalid in [
            "V",
            "VNM",
            "V1",
            "é",
            " VN",
            "VN ",
            "V\n",
            "%'",
            "VN' OR 1=1",
        ] {
            query.country = Some(invalid.into());
            assert!(query.validate().is_err(), "must reject {invalid:?}");
        }
        query.country = Some(String::new());
        assert!(query.validate().is_ok());
        assert!(query.filters_sql().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires an isolated ClickHouse at OPENWAF_TEST_CLICKHOUSE_URL"]
    async fn clickhouse_filters_host_path_and_country_before_limit() {
        let url = std::env::var("OPENWAF_TEST_CLICKHOUSE_URL").expect("isolated ClickHouse URL");
        let history = History::new(&url, None, None).expect("ClickHouse client");
        history
            .execute(SCHEMA, String::new())
            .await
            .expect("schema");
        history
            .execute("TRUNCATE TABLE openwaf_traffic_v1", String::new())
            .await
            .expect("isolated test table");
        let start_ms = openwaf_telemetry::now_ms() - 1000;
        let mut rows = String::new();
        for index in 0..110 {
            let (host, path) = match index {
                0 => ("app.test", "/Case/a'_%\\test"),
                1 => ("other.test", "/Case/a'_%\\test"),
                2 => ("app.test", "/case/another"),
                _ => ("noise.test", "/unrelated"),
            };
            let details = if index == 109 {
                "invalid JSON".to_owned()
            } else {
                serde_json::json!({"schema":9,"security_signals":{"status":"collected","observed_at_unix_ms":start_ms,"coverage":"full","entries":[{"source":"crs","reason":"rule_match","scope":"request","action":"would_block","rule_id":942100,"phase":2,"severity":2}],"truncated":true},"route_id":if index==0 {"target"}else{"noise"},"security_layer":"waf", "waf":{"findings":[{"rule_id":941101},{"rule_id":942100}]},"metadata": {
                    "request": {"host": host, "path": path},
                    "client": {"country_code": if index == 108 { None } else if index == 0 { Some("VN") } else { Some("US") }}
                }}).to_string()
            };
            let row = serde_json::json!({"epoch": "host-filter-test", "sequence": index + 1, "observed_at_unix_ms": start_ms + index, "method": "GET", "status": 200, "latency_ms": 1, "config_version": 1, "route_index": null, "forwarded": true, "blocked": false, "upstream_error": false, "request_id": "", "details": details});
            rows.push_str(&row.to_string());
            rows.push('\n');
        }
        history.execute(INSERT, rows).await.expect("fixtures");
        let mut query = Query {
            start_ms,
            end_ms: start_ms + 1000,
            limit: 1,
            security_only: false,
            request_id: None,
            host: Some("APP.TEST".into()),
            path: Some("/Case/a'_%\\test".into()),
            country: None,
            ..Default::default()
        };
        query.route_id = Some("target".into());
        query.config_version = Some(1);
        query.rule_id = Some(941101);
        query.action = Some("forwarded".into());

        let scoped = history
            .query(query.clone())
            .await
            .expect("exact investigation filters before LIMIT");
        assert_eq!(scoped["items"].as_array().expect("items").len(), 1);
        let restored: serde_json::Value = serde_json::from_str(
            scoped["items"][0]["details"]
                .as_str()
                .expect("stored details string"),
        )
        .expect("details JSON roundtrip");
        assert_eq!(
            restored["security_signals"]["entries"][0]["action"],
            "would_block"
        );
        assert_eq!(
            restored["security_signals"]["entries"][0]["rule_id"],
            942100
        );
        assert_eq!(restored["security_signals"]["coverage"], "full");
        assert_eq!(restored["security_signals"]["truncated"], true);
        assert_eq!(
            restored["security_signals"]["observed_at_unix_ms"],
            start_ms
        );
        let top = history
            .investigation_top(query.clone())
            .await
            .expect("top scoped records");
        assert_eq!(top["items"]["rules"].as_array().expect("rules").len(), 2);
        assert_eq!(top["items"]["routes"][0]["label"], "target");
        query.action = Some("blocked".into());
        assert!(
            history
                .query(query.clone())
                .await
                .expect("actual blocks only")["items"]
                .as_array()
                .expect("items")
                .is_empty()
        );
        query.route_id = None;
        query.config_version = None;
        query.rule_id = None;
        query.action = None;
        let result = history
            .query(query.clone())
            .await
            .expect("host and literal path");
        assert_eq!(result["items"].as_array().expect("items").len(), 1);
        assert!(result["items"][0]["sequence"] == 1 || result["items"][0]["sequence"] == "1");
        query.path = Some("/case/a'_%\\test".into());
        assert!(
            history
                .query(query.clone())
                .await
                .expect("case-sensitive path")["items"]
                .as_array()
                .expect("items")
                .is_empty()
        );
        query.path = None;
        query.limit = 100;
        assert_eq!(
            history.query(query.clone()).await.expect("host only")["items"]
                .as_array()
                .expect("items")
                .len(),
            2
        );
        query.host = None;
        query.path = Some("a'_%\\test".into());
        assert_eq!(
            history.query(query.clone()).await.expect("path only")["items"]
                .as_array()
                .expect("items")
                .len(),
            2
        );
        query.path = None;
        query.country = Some("vn".into());
        let result = history
            .query(query.clone())
            .await
            .expect("country before limit");
        assert_eq!(result["items"].as_array().expect("items").len(), 1);
        assert!(result["items"][0]["sequence"] == 1 || result["items"][0]["sequence"] == "1");
        query.host = Some("other.test".into());
        assert!(
            history
                .query(query.clone())
                .await
                .expect("host AND country")["items"]
                .as_array()
                .expect("items")
                .is_empty()
        );
        query.host = None;
        query.country = Some("us".into());
        let result = history
            .query(query)
            .await
            .expect("missing and malformed metadata excluded");
        for row in result["items"].as_array().expect("items") {
            let details: serde_json::Value =
                serde_json::from_str(row["details"].as_str().expect("details"))
                    .expect("valid metadata");
            assert_eq!(details["metadata"]["client"]["country_code"], "US");
        }
    }
    #[test]
    fn request_lookup_accepts_new_and_legacy_ids_but_rejects_sql_metacharacters() {
        for (id, valid) in [
            ("aB3_dE6_gH9_jK2_mN5_pQ8_sT1_vW4_".repeat(2), true),
            ("aB3_dE6_gH9_jK2_mN5_pQ8_sT1_vW4_".to_owned(), true),
            ("0123456789abcdef0123456789abcdef".to_owned(), true),
            (format!("{}'", "a".repeat(31)), false),
            (format!("{}\\", "a".repeat(31)), false),
            (format!("{}'", "a".repeat(63)), false),
            ("a".repeat(63), false),
            ("a".repeat(65), false),
            ("short".to_owned(), false),
        ] {
            let query = Query {
                start_ms: 1,
                end_ms: 2,
                limit: 1,
                security_only: false,
                request_id: Some(id),
                host: None,
                path: None,
                country: None,
                ..Default::default()
            };
            assert_eq!(query.validate().is_ok(), valid);
        }
    }

    #[tokio::test]
    async fn stop_before_schema_initialization_accounts_for_all_tail_logs() {
        let (hub, receiver) = openwaf_telemetry::Hub::new();
        let logs = hub.logs.subscribe();
        for _ in 0..BATCH + 5 {
            hub.start("GET").finish(200, 1, None, false, 0, 0);
        }
        let (_owner, stop) = tokio::sync::watch::channel(true);
        hub.clone().run_until(receiver, stop.clone()).await;
        let history = History::new("http://127.0.0.1:1/", None, None).expect("local origin");
        history.clone().run_until(logs, stop).await;
        let status = history.health.snapshot();
        assert_eq!(status.dropped, (BATCH + 5) as u64);
        assert_eq!(status.backlog, 0);
        assert!(status.degraded);
    }
    #[test]
    fn query_bounds_and_credential_transport() {
        assert!(
            Query {
                start_ms: 1,
                end_ms: 86_400_002,
                limit: 100,
                security_only: false,
                request_id: None,
                host: None,
                path: None,
                country: None,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Query {
                start_ms: 1,
                end_ms: 2,
                limit: 101,
                security_only: false,
                request_id: None,
                host: None,
                path: None,
                country: None,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(History::new("http://user:secret@localhost/", None, None).is_err());
        assert!(History::new("http://history.example/", None, None).is_err());
        assert!(History::new("http://127.0.0.1:8123/", None, None).is_ok());
    }
}

/// Shared exact filters for drill-down. Values are SQL data, never identifiers.
#[derive(Clone, Default, Deserialize)]
pub struct Investigation {
    #[serde(default)]
    pub route_id: Option<String>,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub config_version: Option<i64>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub layer: Option<String>,
    #[serde(default)]
    pub rule_id: Option<u32>,
    #[serde(default)]
    pub status_class: Option<u16>,
}
impl Investigation {
    fn validate(&self) -> Result<(), QueryError> {
        if self
            .client_ip
            .as_ref()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().is_err())
        {
            return Err(QueryError::Invalid);
        }
        if [&self.route_id, &self.layer].iter().any(|s| {
            s.as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        }) || self
            .action
            .as_deref()
            .is_some_and(|s| !["blocked", "forwarded", "local"].contains(&s))
            || self.config_version.is_some_and(|v| v < 0)
            || self
                .rule_id
                .is_some_and(|v| !(900000..=999999).contains(&v))
            || self.status_class.is_some_and(|v| v > 5)
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
    fn sql(&self) -> String {
        let mut s = String::new();
        for (value, field) in [
            (&self.route_id, "route_id"),
            (&self.layer, "security_layer"),
        ] {
            if let Some(value) = value {
                s.push_str(&format!(
                    " AND JSONExtractString(details,'{field}') = unhex('{}')",
                    rollup::hex(value)
                ));
            }
        }
        if let Some(ip) = &self.client_ip {
            s.push_str(&format!(
                " AND JSONExtractString(details,'metadata','client','ip') = unhex('{}')",
                rollup::hex(ip)
            ));
        }
        if let Some(v) = self.config_version {
            s.push_str(&format!(" AND config_version = {v}"));
        }
        if let Some(v) = self.rule_id {
            s.push_str(&format!(" AND has(arrayMap(x -> JSONExtractUInt(x,'rule_id'), JSONExtractArrayRaw(details,'waf','findings')), {v})"));
        }
        if let Some(v) = self.status_class {
            s.push_str(&format!(" AND intDiv(status,100) = {v}"));
        }
        if let Some(v) = &self.action {
            s.push_str(match v.as_str() {
                "blocked" => " AND blocked",
                "forwarded" => " AND forwarded",
                _ => " AND NOT blocked AND NOT forwarded",
            });
        }
        s
    }
}
impl History {
    /// Top lists describe searchable records, never gateway totals. Bounded to
    /// twenty rows per dimension, one day and the shared two-query semaphore.
    pub async fn investigation_top(&self, request: Query) -> Result<serde_json::Value, QueryError> {
        request.validate()?;
        let _permit = self
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Unavailable)?;
        let filters = request.filters_sql();
        let security = if request.security_only {
            " AND blocked"
        } else {
            ""
        };
        let mut result = serde_json::Map::new();
        for (name, expr) in [
            ("routes", "JSONExtractString(details,'route_id')"),
            (
                "clients",
                "JSONExtractString(details,'metadata','client','ip')",
            ),
            (
                "rules",
                "toString(arrayJoin(arrayMap(x -> JSONExtractUInt(x,'rule_id'), JSONExtractArrayRaw(details,'waf','findings'))))",
            ),
        ] {
            let query = format!(
                "SELECT {expr} AS label, count() AS records, countIf(blocked) AS blocked FROM openwaf_traffic_v1 WHERE observed_at_unix_ms >= {} AND observed_at_unix_ms < {} {filters} {security} GROUP BY label ORDER BY records DESC, label LIMIT 20 FORMAT JSON",
                request.start_ms, request.end_ms
            );
            let bytes = self
                .execute(&query, String::new())
                .await
                .map_err(|_| QueryError::Unavailable)?;
            let data: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| QueryError::Unavailable)?;
            if !data["data"].is_array() {
                return Err(QueryError::Unavailable);
            }
            result.insert(name.into(), data["data"].clone());
        }
        Ok(
            serde_json::json!({"source":"clickhouse_records","start_ms":request.start_ms,"end_ms":request.end_ms,"observed_at_unix_ms":openwaf_telemetry::now_ms(),"limit":20,"items":result,"health":self.health.snapshot(),"completeness":"searchable_records_only","rule_count_unit":"recorded_findings_not_requests"}),
        )
    }
}

#[cfg(test)]
mod investigation_tests {
    use super::*;

    #[test]
    fn exact_filters_validate_before_sql_and_old_queries_remain_compatible() {
        let q:Query=serde_json::from_str(r#"{"start_ms":1,"end_ms":2,"limit":1,"route_id":"a'route","config_version":12,"rule_id":941101,"action":"blocked","status_class":4}"#).expect("query");
        assert!(q.validate().is_ok());
        let sql = q.filters_sql();
        assert!(!sql.contains("a'route"));
        assert!(sql.contains("config_version = 12"));
        assert!(sql.contains("941101"));
        assert!(sql.contains("AND blocked"));
        for field in [
            r#""rule_id":1"#,
            r#""action":"bypass""#,
            r#""status_class":9"#,
            r#""config_version":-1"#,
        ] {
            let json = format!("{{\"start_ms\":1,\"end_ms\":2,\"limit\":1,{field}}}");
            let q: Query = serde_json::from_str(&json).expect("shape");
            assert!(q.validate().is_err());
        }
    }
}
