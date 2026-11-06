//! Counter-derived five-minute windows, independent of traffic records. One owned
//! writer, one bounded batch (129 rows), two identical attempts, no unbounded queue.
use super::*;
use openwaf_telemetry::{
    Hub, Totals,
    routes::{Sample, Security, delta},
};
use tokio::sync::watch;
pub const BUCKET_MS: u64 = 300_000;
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS openwaf_statistics_v1 (epoch String, route_id String, bucket_ms UInt64, start_ms UInt64, end_ms UInt64, incoming UInt64, completed UInt64, forwarded UInt64, blocked UInt64, cancelled UInt64, upstream_errors UInt64, dropped_logs UInt64, status_classes Array(UInt64), latency_buckets Array(UInt64), coverage Array(UInt64), would_block UInt64, rule_matches UInt64, truncated_reports UInt64, route_overflow UInt64, observed_at DateTime MATERIALIZED toDateTime(intDiv(end_ms,1000))) ENGINE = ReplacingMergeTree(end_ms) ORDER BY (bucket_ms,epoch,route_id,start_ms) TTL observed_at + INTERVAL 30 DAY DELETE";
const INSERT: &str = "INSERT INTO openwaf_statistics_v1 (epoch,route_id,bucket_ms,start_ms,end_ms,incoming,completed,forwarded,blocked,cancelled,upstream_errors,dropped_logs,status_classes,latency_buckets,coverage,would_block,rule_matches,truncated_reports,route_overflow) FORMAT JSONEachRow";
#[derive(Serialize)]
struct Row<'a> {
    epoch: &'a str,
    route_id: &'a str,
    bucket_ms: u64,
    start_ms: u64,
    end_ms: u64,
    incoming: u64,
    completed: u64,
    forwarded: u64,
    blocked: u64,
    cancelled: u64,
    upstream_errors: u64,
    dropped_logs: u64,
    status_classes: [u64; 6],
    latency_buckets: [u64; 16],
    coverage: [u64; 5],
    would_block: u64,
    rule_matches: u64,
    truncated_reports: u64,
    route_overflow: u64,
}
fn snapshots(hub: &Hub) -> Vec<Sample> {
    let mut samples = hub.routes.samples();
    samples.push(Sample {
        route_id: None,
        window: None,
        started_at_unix_ms: 0,
        totals: hub.totals(),
        security: Security::default(),
    });
    samples
}
fn encode(
    hub: &Hub,
    baseline: &[Sample],
    current: &[Sample],
    start: u64,
    end: u64,
    old_overflow: u64,
) -> Result<String> {
    let mut body = String::new();
    for current in current {
        let old = baseline.iter().find(|s| s.route_id == current.route_id);
        let zero = Totals::default();
        let t = delta(&current.totals, old.map_or(&zero, |s| &s.totals));
        let empty = Security::default();
        let security = old.map_or(&empty, |s| &s.security);
        let row = Row {
            epoch: &hub.epoch,
            route_id: current.route_id.as_deref().unwrap_or(""),
            bucket_ms: start / BUCKET_MS * BUCKET_MS,
            start_ms: start.max(current.started_at_unix_ms),
            end_ms: end,
            incoming: t.incoming,
            completed: t.completed,
            forwarded: t.forwarded,
            blocked: t.blocked,
            cancelled: t.cancelled,
            upstream_errors: t.upstream_errors,
            dropped_logs: t.dropped_logs,
            status_classes: t.status_classes,
            latency_buckets: t.latency_buckets,
            coverage: std::array::from_fn(|i| {
                current.security.coverage[i].saturating_sub(security.coverage[i])
            }),
            would_block: current
                .security
                .would_block
                .saturating_sub(security.would_block),
            rule_matches: current
                .security
                .rule_matches
                .saturating_sub(security.rule_matches),
            truncated_reports: current
                .security
                .truncated_reports
                .saturating_sub(security.truncated_reports),
            route_overflow: hub
                .routes
                .overflow_requests
                .load(Relaxed)
                .saturating_sub(old_overflow),
        };
        body.push_str(&serde_json::to_string(&row)?);
        body.push('\n');
    }
    ensure!(body.len() <= 512 * 1024, "statistics batch exceeds budget");
    Ok(body)
}
impl History {
    pub async fn run_rollups(self: Arc<Self>, hub: Arc<Hub>, mut stop: watch::Receiver<bool>) {
        let mut initialized = self.execute(SCHEMA, String::new()).await.is_ok();
        let mut baseline = snapshots(&hub);
        let mut start = openwaf_telemetry::now_ms();
        let mut overflow = hub.routes.overflow_requests.load(Relaxed);
        loop {
            let wait = BUCKET_MS - start % BUCKET_MS;
            let stopping = if *stop.borrow() {
                true
            } else {
                tokio::select! { _ = tokio::time::sleep(Duration::from_millis(wait)) => false, _ = stop.changed() => true }
            };
            let end = openwaf_telemetry::now_ms();
            if end <= start {
                if stopping {
                    break;
                }
                continue;
            }
            // Serialize and take the next baseline before I/O; no traffic is lost
            // between an acknowledged batch and the next measurement window.
            let current = snapshots(&hub);
            let body = encode(&hub, &baseline, &current, start, end, overflow);
            baseline = current;
            overflow = hub.routes.overflow_requests.load(Relaxed);
            start = end;
            if !initialized {
                initialized = self.execute(SCHEMA, String::new()).await.is_ok();
            }
            let mut success = false;
            if let Ok(body) = body
                && initialized
            {
                for _ in 0..2 {
                    if self
                        .execute(INSERT, body.clone())
                        .await
                        .is_ok_and(|r| r.is_empty())
                    {
                        success = true;
                        break;
                    }
                }
            }
            self.rollup_health.degraded.store(!success, Relaxed);
            if success {
                self.rollup_health
                    .written
                    .fetch_add(baseline.len() as u64, Relaxed);
                self.rollup_health.last_success.store(end, Relaxed);
            } else {
                self.rollup_health
                    .dropped
                    .fetch_add(baseline.len() as u64, Relaxed);
            }
            if stopping {
                break;
            }
        }
    }
    pub async fn statistics(
        &self,
        input: StatisticsQuery,
    ) -> Result<serde_json::Value, QueryError> {
        input.validate()?;
        let _permit = self
            .queries
            .clone()
            .try_acquire_owned()
            .map_err(|_| QueryError::Unavailable)?;
        let route = hex(input.route_id.as_deref().unwrap_or(""));
        // FINAL collapses identical retries even after an unknown commit ACK.
        // Return whole observed windows only: never prorate counts across missing data.
        let bins = |field: &str, n: usize| {
            (1..=n)
                .map(|i| format!("sum(s.{field}[{i}])"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let step = if input.end_ms - input.start_ms <= 3 * 86_400_000 {
            BUCKET_MS
        } else {
            3_600_000
        };
        let query = format!(
            "SELECT intDiv(s.bucket_ms,{step})*{step} AS bucket_ms, min(s.start_ms) AS start_ms, max(s.end_ms) AS end_ms, sum(s.end_ms-s.start_ms) AS observed_ms, sum(s.incoming) AS incoming, sum(s.completed) AS completed, sum(s.forwarded) AS forwarded, sum(s.blocked) AS blocked, sum(s.cancelled) AS cancelled, sum(s.upstream_errors) AS upstream_errors, sum(s.dropped_logs) AS dropped_logs, sum(s.would_block) AS would_block, sum(s.rule_matches) AS rule_matches, sum(s.truncated_reports) AS truncated_reports, sum(s.route_overflow) AS route_overflow, [{}] AS status_classes, [{}] AS latency_buckets, [{}] AS coverage FROM openwaf_statistics_v1 AS s FINAL WHERE route_id=unhex('{route}') AND s.start_ms >= {} AND s.end_ms <= {} GROUP BY bucket_ms ORDER BY bucket_ms LIMIT 1000 FORMAT JSON",
            bins("status_classes", 6),
            bins("latency_buckets", 16),
            bins("coverage", 5),
            input.start_ms,
            input.end_ms
        );
        let bytes = self
            .execute(&query, String::new())
            .await
            .map_err(|_| QueryError::Unavailable)?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| QueryError::Unavailable)?;
        let items = value["data"].as_array().ok_or(QueryError::Unavailable)?;
        let mut items = items.clone();
        for row in &mut items {
            let mut histogram = [0; 16];
            if let Some(bins) = row["latency_buckets"].as_array().filter(|b| b.len() == 16) {
                for (i, b) in bins.iter().enumerate() {
                    histogram[i] = number(b).ok_or(QueryError::Unavailable)?;
                }
            } else {
                return Err(QueryError::Unavailable);
            }
            row["p95_ms"] = openwaf_telemetry::quantile(&histogram, 95).into();
            row["p99_ms"] = openwaf_telemetry::quantile(&histogram, 99).into();
            if input.route_id.is_none() {
                for field in [
                    "coverage",
                    "would_block",
                    "rule_matches",
                    "truncated_reports",
                ] {
                    row[field] = serde_json::Value::Null;
                }
            }
        }
        Ok(
            serde_json::json!({"schema_version":1,"source":"counter_rollup","route_id":input.route_id,"start_ms":input.start_ms,"end_ms":input.end_ms,"bucket_ms":step,"retention_days":30,"observed_at_unix_ms":openwaf_telemetry::now_ms(),"version_scope":"mixed_config_versions","security_source":if route.is_empty(){"unavailable_use_route"}else{"route_finalization_counters"},"coverage_source":if route.is_empty(){"unavailable_use_route"}else{"route_finalization_counters"},"items":items,"health":self.rollup_health.snapshot(),"completeness":"best_effort_observed_windows_only"}),
        )
    }
}
pub fn number(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}
pub fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatisticsQuery {
    pub start_ms: u64,
    pub end_ms: u64,
    pub route_id: Option<String>,
}
impl StatisticsQuery {
    pub fn validate(&self) -> Result<(), QueryError> {
        if self.start_ms >= self.end_ms
            || self.end_ms - self.start_ms > 30 * 86_400_000
            || self.end_ms > openwaf_telemetry::now_ms() + 60_000
            || self
                .route_id
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(QueryError::Invalid);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rollup_is_counter_derived_and_retries_have_identical_keys_and_body() {
        let (hub, _rx) = Hub::new();
        let baseline = snapshots(&hub);
        let start = openwaf_telemetry::now_ms();
        let mut r = hub.start("POST");
        r.route("order");
        r.security("full", true, 3, false);
        r.blocked();
        r.finish(403, 2, Some(0), false, 0, 0);
        let body =
            encode(&hub, &baseline, &snapshots(&hub), start, start + 1000, 0).expect("encode");
        assert_eq!(
            body,
            encode(&hub, &baseline, &snapshots(&hub), start, start + 1000, 0).expect("same retry")
        );
        let row: serde_json::Value =
            serde_json::from_str(body.lines().next().expect("row")).expect("JSON");
        assert_eq!(row["incoming"], 1);
        assert_eq!(row["rule_matches"], 3);
        assert_eq!(row["blocked"], 1);
        assert!(row.get("details").is_none());
        assert!(row.get("ip").is_none());
    }
    #[test]
    fn thirty_days_use_hourly_groups_without_truncation() {
        let q = StatisticsQuery {
            start_ms: 1,
            end_ms: 30 * 86_400_000,
            route_id: None,
        };
        assert!(q.validate().is_ok());
        let q = StatisticsQuery {
            start_ms: 1,
            end_ms: 86_400_000,
            route_id: Some("r'".into()),
        };
        assert!(q.validate().is_ok());
        assert_eq!(hex("r'"), "7227");
    }
    #[tokio::test]
    #[ignore = "requires isolated ClickHouse via OPENWAF_TEST_CLICKHOUSE_URL"]
    async fn clickhouse_rollup_retry_deduplicates_and_merges_histograms() {
        let url = std::env::var("OPENWAF_TEST_CLICKHOUSE_URL").expect("isolated URL");
        let h = History::new(&url, None, None).expect("client");
        h.execute(SCHEMA, String::new()).await.expect("schema");
        h.execute("TRUNCATE TABLE openwaf_statistics_v1", String::new())
            .await
            .expect("isolated table");
        let (hub, _rx) = Hub::new();
        let start = openwaf_telemetry::now_ms() - 5000;
        let baseline = snapshots(&hub);
        let mut r = hub.start("GET");
        r.route("route'one");
        r.blocked();
        r.security("full", true, 3, false);
        r.finish(403, 1, Some(0), false, 0, 0);
        let body = encode(
            &hub,
            &baseline,
            &snapshots(&hub),
            start,
            openwaf_telemetry::now_ms() + 1,
            0,
        )
        .expect("body");
        // A lost ACK and identical retry must still yield one counter window.
        h.execute(INSERT, body.clone()).await.expect("first insert");
        h.execute(INSERT, body).await.expect("retry insert");
        let q = StatisticsQuery {
            start_ms: start,
            end_ms: openwaf_telemetry::now_ms() + 1000,
            route_id: Some("route'one".into()),
        };
        let result = h.statistics(q.clone()).await.expect("query");
        let rows = result["items"].as_array().expect("items");
        assert_eq!(rows.len(), 1);
        assert_eq!(number(&rows[0]["incoming"]), Some(1));
        assert_eq!(number(&rows[0]["rule_matches"]), Some(3));
        assert_eq!(number(&rows[0]["blocked"]), Some(1));
        assert_eq!(
            rows[0]["p95_ms"],
            openwaf_telemetry::quantile(&hub.routes.samples()[0].totals.latency_buckets, 95)
                .expect("latency")
        );
        let hourly = h
            .statistics(StatisticsQuery {
                start_ms: start - 4 * 86_400_000,
                end_ms: openwaf_telemetry::now_ms() + 1000,
                route_id: q.route_id,
            })
            .await
            .expect("hourly grouping");
        assert_eq!(hourly["bucket_ms"], 3_600_000);
        let ttl = h
            .execute(
                "SHOW CREATE TABLE openwaf_statistics_v1 FORMAT TabSeparatedRaw",
                String::new(),
            )
            .await
            .expect("DDL");
        assert!(String::from_utf8_lossy(&ttl).contains("toIntervalDay(30)"));
    }
}
