//! Persist observations outside proxy executors. Bounded local retry coalesces
//! evidence; DB errors and unknown ACK never resolve incidents or delete work.
use super::*;
use axum::extract::Path;
const CAP: i64 = 1000;
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/security/detectors", get(diagnostics))
        .route("/api/v1/security/incidents", get(list))
        .route(
            "/api/v1/security/incidents/{id}",
            axum::routing::post(action),
        )
}
async fn diagnostics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    Ok(Json(app.abuse.diagnostics(openwaf_telemetry::now_ms())))
}
async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let rows=sqlx::query("SELECT id,detector,scope,route_id,window_start_ms,window_end_ms,first_ms,last_ms,config_version,state,quality,evidence,revision FROM abuse_incidents ORDER BY last_ms DESC,id DESC LIMIT 1000").fetch_all(&app.db).await?;
    // The hard retention cap equals the bounded query limit; derive the total
    // from this exact read rather than a second, racing database snapshot.
    let count = rows.len();
    let values=rows.iter().map(|r|->std::result::Result<_,sqlx::Error>{Ok(serde_json::json!({"id":r.try_get::<i64,_>("id")?,"detector":r.try_get::<String,_>("detector")?,"scope":r.try_get::<String,_>("scope")?,"route_id":r.try_get::<String,_>("route_id")?,"window_start_ms":r.try_get::<i64,_>("window_start_ms")?,"window_end_ms":r.try_get::<i64,_>("window_end_ms")?,"first_ms":r.try_get::<i64,_>("first_ms")?,"last_ms":r.try_get::<i64,_>("last_ms")?,"config_version":r.try_get::<i64,_>("config_version")?,"state":r.try_get::<String,_>("state")?,"quality":r.try_get::<String,_>("quality")?,"evidence":r.try_get::<serde_json::Value,_>("evidence")?,"revision":r.try_get::<i64,_>("revision")?}))}).collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(
        serde_json::json!({"items":values,"total":count,"limit":1000,"retention_days":7,"max_records":CAP,"truncated":count>1000,"observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    state: String,
    expected_revision: i64,
}
async fn action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<Action>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    if !["ack", "resolved", "open"].contains(&input.state.as_str())
        || id <= 0
        || input.expected_revision < 1
    {
        return Err(Error::Invalid);
    }
    let mut tx = app.db.begin().await?;
    let changed=sqlx::query("UPDATE abuse_incidents SET state=$1,revision=revision+1,updated_at=now() WHERE id=$2 AND revision=$3").bind(&input.state).bind(id).bind(input.expected_revision).execute(&mut *tx).await?;
    if changed.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        &format!("incident.{}", input.state),
        &id.to_string(),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn persist(
    db: &PgPool,
    event: &openwaf_security::abuse::Event,
) -> std::result::Result<(), sqlx::Error> {
    let evidence = serde_json::to_value(event)
        .map_err(|_| sqlx::Error::Protocol("incident serialization".into()))?;
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331120205)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM abuse_incidents WHERE id IN (SELECT id FROM abuse_incidents WHERE state='resolved' AND updated_at<now()-interval '7 days' ORDER BY id LIMIT 1000)").execute(&mut *tx).await?;
    if event.recovered {
        if event.quality != "complete" {
            return Err(sqlx::Error::Protocol("incomplete recovery".into()));
        }
        sqlx::query("UPDATE abuse_incidents SET state='resolved',quality='recovered',revision=revision+1,updated_at=now() WHERE detector=$1 AND scope=$2 AND config_version=$3 AND window_start_ms<$4 AND state IN ('open','ack') AND quality NOT IN ('gap','restart_unknown')").bind(event.detector).bind(&event.scope).bind(event.config_version).bind(event.window_start_ms as i64).execute(&mut *tx).await?;
    } else {
        // Trim resolved history when the hard record budget is full. Open/ACK
        // records are never silently evicted; new work stays pending on overflow.
        sqlx::query("DELETE FROM abuse_incidents WHERE id IN (SELECT id FROM abuse_incidents WHERE state='resolved' ORDER BY updated_at LIMIT (SELECT GREATEST(count(*)-999,0) FROM abuse_incidents))").execute(&mut *tx).await?;
        let rows=sqlx::query("INSERT INTO abuse_incidents(group_key,detector,scope,route_id,window_start_ms,window_end_ms,first_ms,last_ms,config_version,quality,evidence) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE (SELECT count(*) FROM abuse_incidents)<1000 OR EXISTS(SELECT 1 FROM abuse_incidents WHERE group_key=$1) ON CONFLICT(group_key) DO UPDATE SET last_ms=GREATEST(abuse_incidents.last_ms,EXCLUDED.last_ms),evidence=EXCLUDED.evidence,quality=CASE WHEN abuse_incidents.quality IN ('restart_unknown','gap') THEN abuse_incidents.quality ELSE EXCLUDED.quality END,updated_at=now()")
            .bind(&event.key).bind(event.detector).bind(&event.scope).bind(&event.route).bind(event.window_start_ms as i64).bind(event.window_end_ms as i64).bind(event.first_ms as i64).bind(event.last_ms as i64).bind(event.config_version).bind(event.quality).bind(evidence).execute(&mut *tx).await?;
        if rows.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol("incident capacity".into()));
        }
    }
    tx.commit().await?;
    Ok(())
}
pub async fn run(app: &Arc<App>) {
    let mut initialized = false;
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut persisted_gap = 0;
    loop {
        interval.tick().await;
        if !initialized {
            if sqlx::query("UPDATE abuse_incidents SET quality='restart_unknown',revision=revision+1 WHERE state IN ('open','ack')").execute(&app.db).await.is_err(){app.abuse.persistence_failed();continue;}
            initialized = true;
        }
        let gap = app.abuse.dropped.load(std::sync::atomic::Ordering::Relaxed);
        if gap > persisted_gap {
            match sqlx::query("UPDATE abuse_incidents SET quality='gap',revision=revision+1 WHERE state IN ('open','ack') AND quality NOT IN ('gap','restart_unknown')").execute(&app.db).await {
                Ok(_)=>persisted_gap=gap,
                Err(_)=>{app.abuse.persistence_failed();continue;}
            }
        }
        for event in app.abuse.pending() {
            match tokio::time::timeout(Duration::from_secs(3), persist(&app.db, &event)).await {
                Ok(Ok(())) => {
                    // Use the existing coalescing/silence-aware outbox. No new sender.
                    let message = format!(
                        "OpenWAF {} route={} version={} quality={}{}",
                        event.detector,
                        event.route,
                        event.config_version,
                        event.quality,
                        if event.recovered {
                            " recovered"
                        } else {
                            " observed; review incident"
                        }
                    );
                    match tokio::time::timeout(
                        Duration::from_secs(3),
                        telegram::enqueue(
                            &app.db,
                            &format!(
                                "abuse:{}:{}:{}",
                                event.detector,
                                event.scope,
                                if event.recovered {
                                    "recovery"
                                } else {
                                    "observed"
                                }
                            ),
                            &message,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(true)) => app.abuse.ack(&event.key, event.revision),
                        _ => app.abuse.persistence_failed(),
                    }
                }
                _ => app.abuse.persistence_failed(),
            }
        }
    }
}
