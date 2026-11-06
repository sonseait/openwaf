//! Application-managed provider metadata and encrypted credentials.
use super::*;
use openwaf_cloudflare::{Client, Credentials};

const CAPACITY: i64 = 16;
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/certificate-providers", get(inventory).post(create))
        .route("/api/v1/certificate-providers/discover", post(discover))
        .route(
            "/api/v1/certificate-providers/{id}",
            axum::routing::put(update).delete(remove),
        )
        .route("/api/v1/certificate-providers/{id}/test", post(test))
        .merge(super::dns::routes())
}
pub(super) fn management(app: &App) -> ApiResult<&FsPath> {
    base_settings(app)?;
    app.certificates
        .master_key_file
        .as_deref()
        .filter(|p| p.is_absolute())
        .ok_or(Error::Unavailable)
}
pub(super) fn permit(app: &App) -> ApiResult<tokio::sync::SemaphorePermit<'_>> {
    let mut quota = app
        .certificates
        .quota
        .lock()
        .map_err(|_| Error::Unavailable)?;
    if quota.0.elapsed() >= Duration::from_secs(60) {
        *quota = (Instant::now(), 0);
    }
    if quota.1 >= 120 {
        return Err(Error::CloudflareLimited);
    }
    quota.1 += 1;
    app.certificates
        .operations
        .try_acquire()
        .map_err(|_| Error::RefreshLimited)
}
pub(super) fn secret_name(id: &str) -> String {
    format!("cloudflare-provider:{id}")
}
pub(super) fn decrypt(app: &App, id: &str, bytes: &[u8]) -> ApiResult<Credentials> {
    let plain = app
        .key
        .open(&secret_name(id), bytes)
        .map_err(|_| Error::Unavailable)?;
    let credentials: Credentials =
        serde_json::from_slice(&plain).map_err(|_| Error::Unavailable)?;
    credentials.validate().map_err(|_| Error::Unavailable)?;
    Ok(credentials)
}
pub(super) async fn extend(app: &App, settings: &mut Settings) -> ApiResult<()> {
    let rows=sqlx::query("SELECT id,name,zone_id,zone_name,environment,credential,acme_profile FROM certificate_providers ORDER BY id LIMIT 17").fetch_all(&app.db).await?;
    if rows.len() > CAPACITY as usize {
        return Err(Error::Unavailable);
    }
    if !rows.is_empty() {
        management(app)?;
    }
    for row in rows {
        let id: String = row.try_get("id")?;
        let name: String = row.try_get("name")?;
        let zone: String = row.try_get("zone_name")?;
        let env: String = row.try_get("environment")?;
        if !valid_name(&id) || settings.providers.contains_key(&id) {
            return Err(Error::Unavailable);
        }
        let master = management(app)?;
        let token = settings.root.join("providers").join(format!("{id}.enc"));
        let manifest = if env == "production" {
            PathBuf::from(std::env::var_os("OPENWAF_TLS_MANIFEST").ok_or(Error::Unavailable)?)
        } else {
            settings.root.join("staging/manifest.json")
        };
        let generated = serde_json::json!({"directory_url":if env=="production" {"https://acme-v02.api.letsencrypt.org/directory"} else {"https://acme-staging-v02.api.letsencrypt.org/directory"},"master_key_file":master,"tls_manifest":manifest,"terms_of_service_agreed":true,"deadline_seconds":180,"cloudflare":{"zone_id":row.try_get::<String,_>("zone_id")?,"zone_name":zone,"token_file":token,"propagation_seconds":60}});
        let template = row
            .try_get::<Option<serde_json::Value>, _>("acme_profile")?
            .unwrap_or(generated);
        // No secret/revision/name in identity: credential rotation keeps account,
        // immutable per-host input and renewal ownership intact.
        let fingerprint = crypto::hex(&sha256(
            &serde_json::to_vec(&template).map_err(|_| Error::Unavailable)?,
        ));
        settings.providers.insert(
            id.clone(),
            Provider {
                id,
                name,
                zone,
                environment: env,
                fingerprint,
                template,
                credential: Some(row.try_get("credential")?),
            },
        );
    }
    Ok(())
}
async fn inventory(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let rows=sqlx::query("SELECT p.id,p.name,p.zone_id,p.zone_name,p.environment,p.revision,p.updated_at::text AS updated_at,(SELECT count(*) FROM certificate_requests r WHERE r.provider_id=p.id) AS request_count FROM certificate_providers p ORDER BY p.name LIMIT 17").fetch_all(&app.db).await?;
    if rows.len() > CAPACITY as usize {
        return Err(Error::Unavailable);
    }
    let mut items = Vec::new();
    for row in rows {
        items.push(serde_json::json!({"id":row.try_get::<String,_>("id")?,"name":row.try_get::<String,_>("name")?,"zone_id":row.try_get::<String,_>("zone_id")?,"zone_name":row.try_get::<String,_>("zone_name")?,"environment":row.try_get::<String,_>("environment")?,"revision":row.try_get::<i64,_>("revision")?,"updated_at":row.try_get::<String,_>("updated_at")?,"request_count":row.try_get::<i64,_>("request_count")?,"source":"dashboard","credential_configured":true}));
    }
    Ok(Json(
        serde_json::json!({"enabled":management(&app).is_ok(),"unavailable_reason":management(&app).err().map(|_|"Provider management requires a managed TLS gateway, writable certificate state and an ACME master key mount."),"providers":items,"capacity":CAPACITY,"observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discover {
    credentials: Credentials,
    #[serde(default = "first_page")]
    page: u32,
}
fn first_page() -> u32 {
    1
}
async fn discover(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Discover>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    management(&app)?;
    let _permit = permit(&app)?;
    input.credentials.validate().map_err(|_| Error::Invalid)?;
    if !(1..=10000).contains(&input.page) {
        return Err(Error::Invalid);
    }
    let client = Client::new(&input.credentials).map_err(|_| Error::Unavailable)?;
    let v = client
        .call(
            Method::GET,
            "/zones",
            &[("per_page", "50".into()), ("page", input.page.to_string())],
            None,
        )
        .await
        .map_err(Error::from)?;
    let rows = v["result"]
        .as_array()
        .filter(|v| v.len() <= 50)
        .ok_or(Error::Unavailable)?;
    let mut zones = Vec::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|id| openwaf_cloudflare::valid_id(id))
            .ok_or(Error::Unavailable)?;
        let name = zone_name(row["name"].as_str().ok_or(Error::Unavailable)?)?;
        zones.push(serde_json::json!({"id":id,"name":name}));
    }
    let pages = v["result_info"]["total_pages"]
        .as_u64()
        .filter(|n| *n <= 10000)
        .ok_or(Error::Unavailable)?;
    Ok(Json(
        serde_json::json!({"zones":zones,"page":input.page,"has_more":u64::from(input.page)<pages,"observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
fn zone_name(name: &str) -> ApiResult<String> {
    let name = openwaf_config::hostname(name).map_err(|_| Error::Invalid)?;
    if !name.contains('.') || name.starts_with("*.") || name.parse::<std::net::IpAddr>().is_ok() {
        return Err(Error::Invalid);
    }
    Ok(name)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    name: String,
    zone_id: String,
    zone_name: String,
    environment: String,
    credentials: Credentials,
}
fn valid_name_label(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 100 && !name.chars().any(char::is_control)
}
async fn verify_zone(client: &Client, id: &str, name: &str) -> ApiResult<()> {
    let value = client
        .call(Method::GET, &format!("/zones/{id}"), &[], None)
        .await
        .map_err(Error::from)?;
    if value["result"]["id"] != id
        || value["result"]["name"]
            .as_str()
            .and_then(|v| zone_name(v).ok())
            .as_deref()
            != Some(name)
    {
        return Err(Error::CloudflareUnavailable);
    }
    Ok(())
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Create>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    management(&app)?;
    let _permit = permit(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    if !valid_name_label(&input.name)
        || !openwaf_cloudflare::valid_id(&input.zone_id)
        || !matches!(input.environment.as_str(), "production" | "staging")
    {
        return Err(Error::Invalid);
    }
    let zone = zone_name(&input.zone_name)?;
    input.credentials.validate().map_err(|_| Error::Invalid)?;
    let client = Client::new(&input.credentials).map_err(|_| Error::Unavailable)?;
    verify_zone(&client, &input.zone_id, &zone).await?;
    let id = format!(
        "cf_{}",
        &random_token().map_err(|_| Error::Unavailable)?[..32]
    );
    let plain =
        Zeroizing::new(serde_json::to_vec(&input.credentials).map_err(|_| Error::Unavailable)?);
    let encrypted = app
        .key
        .seal(&secret_name(&id), &plain)
        .map_err(|_| Error::Unavailable)?;
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM certificate_providers")
        .fetch_one(&mut *tx)
        .await?;
    if count >= CAPACITY {
        return Err(Error::Conflict);
    }
    let r=sqlx::query("INSERT INTO certificate_providers(id,name,zone_id,zone_name,environment,credential) VALUES($1,$2,$3,$4,$5,$6)").bind(&id).bind(input.name.trim()).bind(&input.zone_id).bind(&zone).bind(&input.environment).bind(encrypted).execute(&mut *tx).await?;
    if r.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "certificate_provider.create",
        &id,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    app.certificates.wake.notify_one();
    Ok(Json(serde_json::json!({"id":id,"revision":1})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    name: String,
    expected_revision: i64,
    credentials: Option<Credentials>,
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    Json(input): Json<Update>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    management(&app)?;
    let _permit = permit(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    if !valid_name(&id)
        || !valid_name_label(&input.name)
        || input.expected_revision < 1
        || input.expected_revision == i64::MAX
    {
        return Err(Error::Invalid);
    }
    let row = sqlx::query("SELECT zone_id,zone_name FROM certificate_providers WHERE id=$1")
        .bind(&id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error::NotFound)?;
    let encrypted = if let Some(credentials) = &input.credentials {
        credentials.validate().map_err(|_| Error::Invalid)?;
        let client = Client::new(credentials).map_err(|_| Error::Unavailable)?;
        verify_zone(
            &client,
            &row.try_get::<String, _>("zone_id")?,
            &row.try_get::<String, _>("zone_name")?,
        )
        .await?;
        let plain =
            Zeroizing::new(serde_json::to_vec(credentials).map_err(|_| Error::Unavailable)?);
        Some(
            app.key
                .seal(&secret_name(&id), &plain)
                .map_err(|_| Error::Unavailable)?,
        )
    } else {
        None
    };
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    let r=sqlx::query("UPDATE certificate_providers SET name=$1,credential=COALESCE($2,credential),revision=revision+1,updated_at=now() WHERE id=$3 AND revision=$4").bind(input.name.trim()).bind(encrypted).bind(&id).bind(input.expected_revision).execute(&mut *tx).await?;
    if r.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "certificate_provider.update",
        &id,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    app.certificates.wake.notify_one();
    Ok(StatusCode::NO_CONTENT)
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    Json(input): Json<Revision>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    management(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    if !valid_name(&id) || input.expected_revision < 1 {
        return Err(Error::Invalid);
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(1331123011)")
        .execute(&mut *tx)
        .await?;
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM certificate_requests WHERE provider_id=$1)",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?
    {
        return Err(Error::Conflict);
    }
    let r = sqlx::query("DELETE FROM certificate_providers WHERE id=$1 AND revision=$2")
        .bind(&id)
        .bind(input.expected_revision)
        .execute(&mut *tx)
        .await?;
    if r.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "certificate_provider.delete",
        &id,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) struct Saved {
    pub client: Client,
    pub zone_id: String,
    pub zone: String,
    pub revision: i64,
}
pub(super) async fn saved(app: &App, id: &str) -> ApiResult<Saved> {
    management(app)?;
    if !valid_name(id) {
        return Err(Error::Invalid);
    }
    let r = sqlx::query(
        "SELECT zone_id,zone_name,credential,revision FROM certificate_providers WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&app.db)
    .await?
    .ok_or(Error::NotFound)?;
    let c = decrypt(app, id, &r.try_get::<Vec<u8>, _>("credential")?)?;
    Ok(Saved {
        client: Client::new(&c).map_err(|_| Error::Unavailable)?,
        zone_id: r.try_get("zone_id")?,
        zone: r.try_get("zone_name")?,
        revision: r.try_get("revision")?,
    })
}
async fn test(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    let _permit = permit(&app)?;
    let p = saved(&app, &id).await?;
    verify_zone(&p.client, &p.zone_id, &p.zone).await?;
    // A read confirms token/zone/DNS-read access, never mutates records to test.
    p.client
        .call(
            Method::GET,
            &format!("/zones/{}/dns_records", p.zone_id),
            &[("per_page", "1".into())],
            None,
        )
        .await
        .map_err(Error::from)?;
    Ok(Json(
        serde_json::json!({"zone_access":true,"dns_read":true,"dns_write":"not_tested","observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    #[serde(default = "first_page")]
    pub page: u32,
    #[serde(default)]
    pub name: String,
}
pub(super) fn page_query(q: &Page) -> ApiResult<Vec<(&'static str, String)>> {
    if !(1..=10000).contains(&q.page) || q.name.len() > 253 || q.name.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    let mut query = vec![("per_page", "50".into()), ("page", q.page.to_string())];
    if !q.name.is_empty() {
        query.push(("name", q.name.clone()));
    }
    Ok(query)
}
