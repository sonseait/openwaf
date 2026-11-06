//! A single bounded checkpoint writer, independent of the proxy and live aggregator.
use anyhow::{Context, Result, ensure};
use openwaf_telemetry::{Checkpoint, Hub};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};

pub async fn restore(db: &PgPool, hub: &Hub) -> Result<()> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT checkpoint FROM openwaf_statistics WHERE singleton = TRUE")
            .fetch_optional(db)
            .await
            .map_err(|_| anyhow::anyhow!("statistics checkpoint read unavailable"))?;
    if let Some(value) = value {
        let checkpoint: Checkpoint =
            serde_json::from_value(value).context("invalid statistics checkpoint")?;
        hub.restore(&checkpoint).map_err(anyhow::Error::msg)?;
    } else {
        save(db, hub).await?;
    }
    Ok(())
}

pub async fn save(db: &PgPool, hub: &Hub) -> Result<()> {
    let checkpoint = hub.checkpoint();
    // A timed-out/cancelled SQL write may finish later on the server. Its older
    // generation must never overwrite a newer final/periodic checkpoint.
    let write = async {
        let value = serde_json::to_value(&checkpoint)?;
        let result = sqlx::query("INSERT INTO openwaf_statistics (singleton, checkpoint) VALUES (TRUE, $1) ON CONFLICT (singleton) DO UPDATE SET checkpoint = EXCLUDED.checkpoint WHERE (openwaf_statistics.checkpoint->>'generation')::numeric < (EXCLUDED.checkpoint->>'generation')::numeric")
            .bind(value).execute(db).await
            .map_err(|_| anyhow::anyhow!("statistics checkpoint write unavailable"))?;
        ensure!(
            result.rows_affected() == 1,
            "statistics checkpoint was not written"
        );
        Ok::<_, anyhow::Error>(())
    };
    let result = tokio::time::timeout(Duration::from_secs(2), write)
        .await
        .context("statistics checkpoint deadline")
        .and_then(|v| v);
    hub.persistence_result(result.as_ref().ok().map(|()| checkpoint.saved_at_unix_ms));
    result
}

/// Cancellation by the control plane stops periodic writes. The owner performs
/// one final save after the request/log drain, before closing PostgreSQL.
pub async fn run(db: &PgPool, hub: Arc<Hub>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;
    loop {
        tick.tick().await;
        if save(db, &hub).await.is_err() {
            eprintln!("statistics persistence degraded; retry on next interval");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires isolated PostgreSQL via OPENWAF_STATISTICS_TEST_DATABASE_URL"]
    async fn postgres_migrates_saves_and_restores_host_statistics() {
        let url =
            std::env::var("OPENWAF_STATISTICS_TEST_DATABASE_URL").expect("isolated database URL");
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("PostgreSQL");
        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .expect("all migrations including checkpoint size");
        let (hub, _receiver) = Hub::new();
        let mut request = hub.start("GET");
        request.host("saved.test");
        request.blocked();
        request.finish(403, 1, None, false, 13, 7);
        save(&db, &hub).await.expect("save hosts");
        let (restored, _) = Hub::new();
        restore(&db, &restored).await.expect("restore hosts");
        assert_eq!(restored.totals().incoming, 1);
        let host = restored.hosts.get("saved.test").expect("persisted host");
        assert_eq!(host.metrics.borrow().totals.blocked, 1);
        assert_eq!(host.metrics.borrow().totals.received_bytes, 13);
        assert_eq!(host.metrics.borrow().totals.active_requests, 0);
        assert_eq!(host.metrics.borrow().incoming_rps, 0.0);
        assert!(restored.persistence().configured);
        let mut corrupt = hub.checkpoint();
        corrupt.hosts.push(corrupt.hosts[0].clone());
        assert_eq!(
            sqlx::query("UPDATE openwaf_statistics SET checkpoint = $1 WHERE singleton = TRUE")
                .bind(serde_json::to_value(corrupt).expect("JSON"))
                .execute(&db)
                .await
                .expect("invalid checkpoint fixture")
                .rows_affected(),
            1
        );
        let (empty, _) = Hub::new();
        assert!(restore(&db, &empty).await.is_err());
        assert_eq!(empty.totals().incoming, 0);
        db.close().await;
    }
}
