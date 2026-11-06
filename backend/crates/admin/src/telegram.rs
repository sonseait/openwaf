//! Outbound-only Telegram integration. No polling, commands, or proxy-path I/O.
use super::*;
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/alerts/telegram", get(settings).put(save))
        .route("/api/v1/alerts/telegram/test", post(test))
        .route("/api/v1/alerts/telegram/outbox", get(outbox))
}
async fn settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let r=sqlx::query("SELECT revision,enabled,chat_id,topic_id,token IS NOT NULL AS token_configured,silence_until_unix_ms FROM telegram_settings WHERE singleton").fetch_one(&app.db).await?;
    Ok(Json(
        serde_json::json!({"revision":r.try_get::<i64,_>("revision")?,"enabled":r.try_get::<bool,_>("enabled")?,"chat_id":r.try_get::<String,_>("chat_id")?,"topic_id":r.try_get::<Option<i64>,_>("topic_id")?,"token_configured":r.try_get::<bool,_>("token_configured")?,"silence_until_unix_ms":r.try_get::<i64,_>("silence_until_unix_ms")?,"mode":"outbound_only"}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    expected_revision: i64,
    enabled: bool,
    chat_id: String,
    topic_id: Option<i64>,
    token: Option<String>,
    #[serde(default)]
    silence_until_unix_ms: i64,
}
impl Drop for Settings {
    fn drop(&mut self) {
        if let Some(token) = &mut self.token {
            token.zeroize();
        }
    }
}
async fn save(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Settings>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    if input.expected_revision < 0
        || input.expected_revision == i64::MAX
        || input.chat_id.len() > 64
        || (!input.chat_id.is_empty()
            && !input
                .chat_id
                .bytes()
                .enumerate()
                .all(|(i, b)| b.is_ascii_digit() || (i == 0 && b == b'-')))
        || input.topic_id.is_some_and(|n| n <= 0)
        || input.silence_until_unix_ms < 0
        || input.silence_until_unix_ms as u64 > openwaf_telemetry::now_ms() + 7 * 86400000
    {
        return Err(Error::Invalid);
    }
    let sealed = if let Some(token) = input.token.as_ref().filter(|t| !t.is_empty()) {
        if token.len() > 128
            || !token.contains(':')
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
        {
            return Err(Error::Invalid);
        }
        Some(
            app.key
                .seal("telegram-bot", token.as_bytes())
                .map_err(|_| Error::Unavailable)?,
        )
    } else {
        None
    };
    let mut tx = app.db.begin().await?;
    let result=sqlx::query("UPDATE telegram_settings SET enabled=$1,chat_id=$2,topic_id=$3,token=COALESCE($4,token),silence_until_unix_ms=$5,revision=revision+1 WHERE singleton AND revision=$6 AND (NOT $1 OR (length($2)>0 AND COALESCE($4,token) IS NOT NULL))").bind(input.enabled).bind(&input.chat_id).bind(input.topic_id).bind(sealed).bind(input.silence_until_unix_ms).bind(input.expected_revision).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "telegram.settings_changed",
        "telegram",
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(crate) async fn enqueue(
    db: &PgPool,
    key: &str,
    message: &str,
) -> std::result::Result<bool, sqlx::Error> {
    // A single owner plus this transaction-level lock bounds pending work even
    // when manual test requests and the evaluator enqueue concurrently.
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331120204)")
        .execute(&mut *tx)
        .await?;
    let grouped: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM telegram_outbox WHERE group_key=$1 AND created_at>now()-interval '5 minutes')").bind(key).fetch_one(&mut *tx).await?;
    if grouped {
        tx.commit().await?;
        return Ok(true);
    }
    let result = sqlx::query("INSERT INTO telegram_outbox(group_key,message) SELECT $1,$2 WHERE (SELECT count(*) FROM telegram_outbox WHERE state='pending')<1000").bind(key).bind(message).execute(&mut *tx).await?;
    let accepted = result.rows_affected() == 1;
    tx.commit().await?;
    Ok(accepted)
}
async fn test(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let mut tx = app.db.begin().await?;
    audit(
        &mut tx,
        Some(auth.id),
        "telegram.test_requested",
        "telegram",
        None,
    )
    .await?;
    tx.commit().await?;
    if !enqueue(&app.db, "test", "OpenWAF: test alert from your gateway.").await? {
        return Err(Error::Unavailable);
    }
    Ok(StatusCode::ACCEPTED)
}
async fn outbox(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let rows=sqlx::query("SELECT id,group_key,state,attempts,last_error FROM telegram_outbox ORDER BY id DESC LIMIT 100").fetch_all(&app.db).await?;
    let items:Vec<_>=rows.iter().map(|r|Ok(serde_json::json!({"id":r.try_get::<i64,_>("id")?,"group":r.try_get::<String,_>("group_key")?,"state":r.try_get::<String,_>("state")?,"attempts":r.try_get::<i32,_>("attempts")?,"last_error":r.try_get::<Option<String>,_>("last_error")?}))).collect::<std::result::Result<_,sqlx::Error>>()?;
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM telegram_outbox WHERE state='pending'")
            .fetch_one(&app.db)
            .await?;
    Ok(Json(
        serde_json::json!({"items":items,"limit":100,"pending":pending,"capacity":1000,"saturated":pending>=1000,"observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
pub async fn run(app: &App) {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Telegram HTTP client unavailable");
            return;
        }
    };
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut states = std::collections::BTreeMap::<&'static str, bool>::new();
    let mut blocked = 0;
    loop {
        tick.tick().await;
        if cycle(app, &client, &mut states, &mut blocked)
            .await
            .is_err()
        {
            eprintln!("Telegram control-plane cycle unavailable");
        }
    }
}
async fn cycle(
    app: &App,
    client: &reqwest::Client,
    states: &mut std::collections::BTreeMap<&'static str, bool>,
    blocked: &mut u64,
) -> ApiResult<()> {
    sqlx::query("UPDATE telegram_outbox SET state='expired',last_error='expired' WHERE state='pending' AND expires_at<=now()").execute(&app.db).await?;
    sqlx::query("DELETE FROM telegram_outbox WHERE created_at<now()-interval '7 days'")
        .execute(&app.db)
        .await?;
    let s=sqlx::query("SELECT enabled,chat_id,topic_id,token,silence_until_unix_ms FROM telegram_settings WHERE singleton").fetch_one(&app.db).await?;
    if !s.try_get::<bool, _>("enabled")?
        || s.try_get::<i64, _>("silence_until_unix_ms")? as u64 > openwaf_telemetry::now_ms()
    {
        return Ok(());
    }
    if let Some(service) = &app.telemetry {
        let metrics = service.hub.metrics.borrow().clone();
        let diagnostics = service
            .diagnostics
            .as_ref()
            .map(|d| d())
            .unwrap_or_default();
        let acme = crate::health::acme(app).await;
        let collector_health = crate::health::collector(app).await;
        let collector = matches!(
            collector_health["state"].as_str(),
            Some("degraded" | "unavailable")
        );
        let certificates = diagnostics["tls"]["certificates"]
            .as_array()
            .is_some_and(|v| {
                v.iter().any(|c| {
                    c["valid_until_unix_s"].as_u64().is_some_and(|until| {
                        until * 1000 < openwaf_telemetry::now_ms() + 7 * 86400000
                    })
                })
            });
        for (name, degraded) in [
            (
                "history",
                service
                    .history
                    .as_ref()
                    .is_some_and(|h| h.health.snapshot().degraded),
            ),
            (
                "crowdsec",
                diagnostics["crowdsec"]["degraded"]
                    .as_bool()
                    .unwrap_or(false),
            ),
            (
                "upstreams",
                diagnostics["upstreams"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|e| e["available"] == false)),
            ),
            ("monitoring", metrics.totals.dropped_logs > 0),
            ("waf_workers", diagnostics["waf"]["healthy"] == false),
            ("certificates", certificates),
            ("acme", acme["state"] == "degraded"),
            ("collector", collector),
        ] {
            if states.get(name).map_or(degraded, |old| *old != degraded)
                && !enqueue(
                    &app.db,
                    &format!("{name}-{degraded}"),
                    &format!(
                        "OpenWAF: {name} {}.",
                        if degraded { "degraded" } else { "recovered" }
                    ),
                )
                .await?
            {
                continue;
            }
            states.insert(name, degraded);
        }
        let current = metrics.totals.blocked;
        if current.saturating_sub(*blocked) >= 10 {
            if enqueue(&app.db,"blocked-surge","OpenWAF: elevated blocked request volume. Review security decisions in the dashboard.").await? {
                *blocked = current;
            }
        } else {
            *blocked = current;
        }
    }
    let row=sqlx::query("SELECT id,message,attempts FROM telegram_outbox WHERE state='pending' AND next_try<=now() ORDER BY id LIMIT 1").fetch_optional(&app.db).await?;
    let Some(row) = row else {
        return Ok(());
    };
    let envelope: Option<Vec<u8>> = s.try_get("token")?;
    let envelope = envelope.ok_or(Error::Unavailable)?;
    let token = app
        .key
        .open("telegram-bot", &envelope)
        .map_err(|_| Error::Unavailable)?;
    let token = std::str::from_utf8(&token).map_err(|_| Error::Unavailable)?;
    let body = serde_json::json!({"chat_id":s.try_get::<String,_>("chat_id")?,"message_thread_id":s.try_get::<Option<i64>,_>("topic_id")?,"text":row.try_get::<String,_>("message")?,"disable_web_page_preview":true});
    let attempt = row.try_get::<i32, _>("attempts")? + 1;
    let fallback = (10i64 * 2i64.pow(attempt.min(5) as u32)).min(300);
    let (state, error, delay) = deliver(
        client,
        &format!("https://api.telegram.org/bot{token}/sendMessage"),
        &body,
        fallback,
    )
    .await;
    let state = if attempt >= 8 && state == "pending" {
        "failed"
    } else {
        state
    };
    let result=sqlx::query("UPDATE telegram_outbox SET state=$1,last_error=$2,attempts=$3,next_try=now()+$4*interval '1 second' WHERE id=$5 AND state='pending'").bind(state).bind(error).bind(attempt).bind(delay).bind(row.try_get::<i64,_>("id")?).execute(&app.db).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    match state {
        "sent" => eprintln!("Telegram delivery outcome=sent attempt={attempt}"),
        "failed" => {
            eprintln!(
                "Telegram delivery outcome=failed reason={} attempt={attempt}",
                error.unwrap_or("unknown")
            )
        }
        _ => eprintln!(
            "Telegram delivery outcome=retry attempt={attempt} reason={}",
            error.unwrap_or("unknown")
        ),
    }
    Ok(())
}

async fn deliver(
    client: &reqwest::Client,
    url: &str,
    body: &serde_json::Value,
    fallback: i64,
) -> (&'static str, Option<&'static str>, i64) {
    let Ok(mut response) = client.post(url).json(body).send().await else {
        return ("pending", Some("delivery_unacknowledged"), fallback);
    };
    let status = response.status();
    let header_delay = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok());
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) if bytes.len() + chunk.len() <= 4096 => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            _ => return ("pending", Some("delivery_response_unavailable"), fallback),
        }
    }
    let value = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default();
    if status.as_u16() == 429 {
        let delay = header_delay
            .or_else(|| value["parameters"]["retry_after"].as_i64())
            .unwrap_or(60)
            .clamp(1, 3600);
        return ("pending", Some("telegram_rate_limited"), delay);
    }
    if status.is_success() && value["ok"] == true {
        ("sent", None, 0)
    } else if status.is_server_error() {
        ("pending", Some("telegram_unavailable"), fallback)
    } else {
        ("failed", Some("telegram_rejected"), fallback)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    async fn response(status: u16, body: &str) -> (&'static str, Option<&'static str>, i64) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let text = format!(
            "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer).await.expect("read");
            stream.write_all(text.as_bytes()).await.expect("response");
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("client");
        let value = deliver(
            &client,
            &format!("http://{address}/test"),
            &serde_json::json!({"text":"fixture"}),
            20,
        )
        .await;
        server.await.expect("owned server");
        value
    }
    #[tokio::test]
    async fn delivery_requires_ack_and_honors_bounded_telegram_retry_after() {
        assert_eq!(response(200, r#"{"ok":true}"#).await, ("sent", None, 0));
        assert_eq!(response(200, r#"{"ok":false}"#).await.0, "failed");
        assert_eq!(
            response(429, r#"{"ok":false,"parameters":{"retry_after":99999}}"#).await,
            ("pending", Some("telegram_rate_limited"), 3600)
        );
        assert_eq!(
            response(503, "unavailable").await,
            ("pending", Some("telegram_unavailable"), 20)
        );
    }
}
