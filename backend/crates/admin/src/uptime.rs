//! Active-snapshot eligibility sampled off the hot path. Missing samples are
//! unknown time, never backfilled or interpreted as availability.
use super::*;
use axum::extract::Query;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

const INTERVAL_MS: u64 = 10_000;
const RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_SAMPLES: i64 = 60_480;

#[derive(Default)]
pub struct Service {
    degraded: AtomicBool,
    last_success: AtomicU64,
    failed_samples: AtomicU64,
    last_error: AtomicU64,
}
impl Service {
    pub async fn run(&self, app: &App, epoch: &str) {
        let mut tick = tokio::time::interval(Duration::from_millis(INTERVAL_MS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            // Managed runtime owns/cancels this future; dropping an open SQLx
            // transaction rolls it back. No detached child or retry queue.
            let result =
                tokio::time::timeout(Duration::from_secs(4), self.sample(app, epoch)).await;
            let code = match result {
                Ok(Ok(())) => 0,
                Ok(Err(_)) => 1,
                Err(_) => 2,
            };
            self.last_error.store(code, Relaxed);
            let success = code == 0;
            self.degraded.store(!success, Relaxed);
            if success {
                self.last_success
                    .store(openwaf_telemetry::now_ms(), Relaxed);
            } else {
                self.failed_samples.fetch_add(1, Relaxed);
            }
        }
    }
    async fn sample(&self, app: &App, epoch: &str) -> ApiResult<()> {
        let snapshot = app.config.as_ref().ok_or(Error::Unavailable)?.store.load();
        let observed = openwaf_telemetry::now_ms();
        let freshness: Vec<_> = snapshot
            .document
            .upstreams
            .iter()
            .map(|u| u.health.interval_ms + u.health.timeout_ms + 2000)
            .collect();
        let counts = counts(&snapshot.health.status(), &freshness, observed);
        let mut tx = app.db.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x4f575550_i64)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("INSERT INTO uptime_samples (observed_at_unix_ms, epoch, config_version, available, unavailable, unknown) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(observed as i64).bind(epoch).bind(snapshot.version)
            .bind(counts.0).bind(counts.1).bind(counts.2).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        sqlx::query("DELETE FROM uptime_samples WHERE observed_at_unix_ms < $1")
            .bind(observed.saturating_sub(RETENTION_MS) as i64)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM uptime_samples WHERE id <= (SELECT id FROM uptime_samples ORDER BY id DESC OFFSET $1 LIMIT 1)")
            .bind(MAX_SAMPLES).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}
fn counts(
    status: &[openwaf_config::health::Status],
    freshness: &[u64],
    now: u64,
) -> (i32, i32, i32) {
    let mut result = (0, 0, 0);
    for endpoint in status {
        if endpoint.checked_at_ms.is_none_or(|checked| {
            checked > now
                || now.saturating_sub(checked)
                    > freshness.get(endpoint.upstream).copied().unwrap_or(0)
        }) || (endpoint.valid_for_ms == 0 && endpoint.reason == "expired_or_passive_failure")
        {
            result.2 += 1;
        } else if endpoint.available {
            result.0 += 1;
        } else {
            result.1 += 1;
        }
    }
    result
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Range {
    from_ms: Option<u64>,
    to_ms: Option<u64>,
    before_id: Option<i64>,
    limit: Option<i64>,
}
impl Range {
    fn validate(&self, now: u64) -> ApiResult<(i64, i64, i64)> {
        let to = self.to_ms.unwrap_or(now);
        let from = self.from_ms.unwrap_or(to.saturating_sub(RETENTION_MS));
        let limit = self.limit.unwrap_or(100);
        if from > to
            || to > i64::MAX as u64
            || to - from > RETENTION_MS
            || !(1..=100).contains(&limit)
            || self.before_id.is_some_and(|v| v <= 0)
        {
            return Err(Error::Invalid);
        }
        Ok((from as i64, to as i64, limit))
    }
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/v1/history/uptime", get(history))
}
async fn history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(range): Query<Range>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    if app.config.is_none() {
        return Err(Error::Unavailable);
    }
    let now = openwaf_telemetry::now_ms();
    let (from, to, limit) = range.validate(now)?;
    let rows = sqlx::query("SELECT id, observed_at_unix_ms, epoch, config_version, available, unavailable, unknown FROM uptime_samples WHERE observed_at_unix_ms BETWEEN $1 AND $2 AND ($3::bigint IS NULL OR id < $3) ORDER BY id DESC LIMIT $4")
        .bind(from).bind(to).bind(range.before_id).bind(limit + 1).fetch_all(&app.db).await?;
    let more = rows.len() > limit as usize;
    let samples = rows.into_iter().take(limit as usize).map(|r| Ok(serde_json::json!({
        "id": r.try_get::<i64,_>("id")?, "observed_at_unix_ms": r.try_get::<i64,_>("observed_at_unix_ms")?,
        "epoch": r.try_get::<String,_>("epoch")?, "config_version": r.try_get::<i64,_>("config_version")?,
        "available": r.try_get::<i32,_>("available")?, "unavailable": r.try_get::<i32,_>("unavailable")?, "unknown": r.try_get::<i32,_>("unknown")?
    }))).collect::<std::result::Result<Vec<_>,sqlx::Error>>()?;
    let next = if more {
        samples.last().and_then(|s| s["id"].as_i64())
    } else {
        None
    };
    let last_success = app.uptime.last_success.load(Relaxed);
    Ok(Json(serde_json::json!({
        "schema_version": 1, "source": "gateway_active_snapshot", "observed_at_unix_ms": now,
        "interval_ms": INTERVAL_MS, "retention_ms": RETENTION_MS, "max_samples": MAX_SAMPLES,
        "from_ms": from, "to_ms": to, "samples": samples, "next_before_id": next,
        "sampler": {"degraded": app.uptime.degraded.load(Relaxed) || last_success == 0 || now.saturating_sub(last_success) > 2 * INTERVAL_MS,
            "last_success_unix_ms": last_success, "failed_samples": app.uptime.failed_samples.load(Relaxed),
            "last_error": match app.uptime.last_error.load(Relaxed) { 0 => None, 1 => Some("database_or_sampler_unavailable"), _ => Some("sample_deadline") }}
    })))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_and_pending_are_unknown_but_fresh_failed_checks_are_unavailable() {
        let document = openwaf_config::Document {
            upstreams: vec![openwaf_config::Upstream {
                balancing: Default::default(),
                affinity: None,
                id: "app".into(),
                endpoints: vec![openwaf_config::Endpoint {
                    weight: 1,
                    address: "127.0.0.1:8081".parse().expect("fixture"),
                    protocol: openwaf_config::Protocol::Http,
                    tls_server_name: None,
                    tls_verify: true,
                    source: None,
                }],
                health: Default::default(),
                timeouts: Default::default(),
            }],
            ..Default::default()
        };
        let health = openwaf_config::health::Health::new(
            &document,
            openwaf_config::Context {
                listeners: vec![],
                local_ips: vec![],
            },
        );
        assert_eq!(counts(&health.status(), &[7000], 10000), (0, 0, 1));
        health.publish(0, 0, vec![], Instant::now(), 10000, "http_status");
        assert_eq!(counts(&health.status(), &[7000], 10000), (0, 1, 0));
        assert_eq!(counts(&health.status(), &[7000], 18000), (0, 0, 1));
        assert_eq!(counts(&health.status(), &[7000], 9000), (0, 0, 1));
        health.publish(
            0,
            0,
            vec!["127.0.0.1:8081".parse().expect("fixture")],
            Instant::now() + Duration::from_secs(10),
            10000,
            "healthy",
        );
        assert_eq!(counts(&health.status(), &[7000], 10000), (1, 0, 0));
    }
    #[test]
    fn query_bounds() {
        let now = 2 * RETENTION_MS;
        assert!(Range::default().validate(now).is_ok());
        for range in [
            Range {
                limit: Some(101),
                ..Default::default()
            },
            Range {
                before_id: Some(0),
                ..Default::default()
            },
            Range {
                from_ms: Some(0),
                to_ms: Some(now),
                ..Default::default()
            },
            Range {
                from_ms: Some(now),
                to_ms: Some(0),
                ..Default::default()
            },
            Range {
                to_ms: Some(u64::MAX),
                ..Default::default()
            },
        ] {
            assert!(range.validate(now).is_err());
        }
    }
}
