//! Application mutations share the configuration writer and durable publication protocol.
pub mod certificates;
use super::*;
use axum::extract::Multipart;
use openwaf_applications::{Limits, Store, now_ms};
use openwaf_config::{
    Document, Route, Snapshot,
    application::{Mode, Target, valid_id},
};
use tokio::io::AsyncWriteExt;

pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/applications", get(list).post(create))
        .route(
            "/api/v1/applications/settings",
            axum::routing::put(settings),
        )
        .route(
            "/api/v1/applications/certificates/retry",
            post(retry_certificates),
        )
        .route("/api/v1/applications/{id}", axum::routing::put(update))
        .route(
            "/api/v1/applications/{id}/releases",
            post(upload).layer(DefaultBodyLimit::max(1024 * 1024 * 1024 + 1024 * 1024)),
        )
        .route(
            "/api/v1/applications/{id}/releases/{release}",
            axum::routing::delete(delete_release),
        )
        .route("/api/v1/applications/{id}/review", post(review))
        .route("/api/v1/applications/{id}/actions", post(action))
}
fn storage(app: &App) -> ApiResult<&Arc<Store>> {
    app.applications.as_ref().ok_or(Error::Unavailable)
}
fn plane(app: &App) -> ApiResult<&config::Plane> {
    app.config.as_ref().ok_or(Error::Unavailable)
}
fn app_id(id: &str) -> ApiResult<()> {
    if valid_id(id) {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}
fn domain(value: &str, app: &App) -> ApiResult<String> {
    let value = openwaf_config::hostname(value).map_err(|_| Error::Invalid)?;
    let admin = app
        .origin
        .parse::<axum::http::Uri>()
        .map_err(|_| Error::Unavailable)?
        .host()
        .ok_or(Error::Unavailable)?
        .to_owned();
    if value.parse::<std::net::IpAddr>().is_ok()
        || value == admin
        || value.ends_with(&format!(".{admin}"))
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}
fn tls(app: &App, hostname: &str) -> serde_json::Value {
    match app
        .application_tls
        .as_ref()
        .and_then(|s| s.certificate_for(hostname))
    {
        Some(c) => {
            serde_json::json!({"state":"ready","hostname":c.hostname,"expires_at_unix_s":c.valid_until_unix_s})
        }
        None => {
            serde_json::json!({"state":"unavailable","reason":"No valid certificate loaded for this hostname"})
        }
    }
}
async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let Some(store) = &app.applications else {
        return Ok(Json(
            serde_json::json!({"enabled":false,"applications":[],"limits":Limits::default(),"preview_base_domain":null}),
        ));
    };
    let snapshot = plane(&app)?.store.load();
    let rows=sqlx::query("SELECT id,name,domain,mode,created_at::text AS created_at FROM applications ORDER BY created_at DESC LIMIT 65").fetch_all(&app.db).await?;
    if rows.len() > 64 {
        return Err(Error::Unavailable);
    }
    let mut applications = Vec::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let hostname: String = row.try_get("domain")?;
        let active = snapshot.document.routes.iter().find(|r| {
            r.application
                .as_ref()
                .is_some_and(|t| t.application_id == id && t.preview_expires_at_unix_ms.is_none())
        });
        let releases=sqlx::query("SELECT id,checksum,bytes,file_count,preview_label,created_at::text AS created_at FROM application_releases WHERE application_id=$1 ORDER BY created_at DESC LIMIT 65").bind(&id).fetch_all(&app.db).await?;
        let mut items = Vec::new();
        for r in releases {
            let release: String = r.try_get("id")?;
            let preview = snapshot.document.routes.iter().find(|r| {
                r.application.as_ref().is_some_and(|t| {
                    t.release_id == release
                        && t.preview_expires_at_unix_ms
                            .is_some_and(|expiry| expiry > now_ms())
                })
            });
            let label: String = r.try_get("preview_label")?;
            let preview_hostname = preview.map(|route| {
                match route.hostname.split_once('.') {
                    Some((first, base)) if first.eq_ignore_ascii_case(&label) => {
                        format!("{label}.{base}")
                    }
                    _ => route.hostname.clone(), // Preserve existing long preview URLs.
                }
            });
            items.push(serde_json::json!({"id":release,"checksum":r.try_get::<String,_>("checksum")?,"bytes":r.try_get::<i64,_>("bytes")?,"file_count":r.try_get::<i32,_>("file_count")?,"created_at":r.try_get::<String,_>("created_at")?,"preview":preview.map(|r|serde_json::json!({"url":format!("https://{}",preview_hostname.as_deref().unwrap_or(&r.hostname)),"expires_at_unix_ms":r.application.as_ref().and_then(|t|t.preview_expires_at_unix_ms),"tls":tls(&app,&r.hostname)}))}));
        }
        applications.push(serde_json::json!({"id":id,"name":row.try_get::<String,_>("name")?,"domain":hostname,"mode":row.try_get::<String,_>("mode")?,"created_at":row.try_get::<String,_>("created_at")?,"active_release":active.and_then(|r|r.application.as_ref()).map(|t|&t.release_id),"active_domain":active.map(|r|&r.hostname),"tls":tls(&app,&hostname),"releases":items}));
    }
    let base: Option<String> = sqlx::query_scalar(
        "SELECT preview_base_domain FROM application_settings WHERE singleton=true",
    )
    .fetch_one(&app.db)
    .await?;
    Ok(Json(
        serde_json::json!({"enabled":true,"applications":applications,"preview_base_domain":base,"limits":store.limits,"active_version":snapshot.version,"auto_tls_configured":certificates::configured(),"auto_tls_health":app.application_certificate_health.lock().map_err(|_|Error::Unavailable)?.clone(),"certificate_jobs":certificate_jobs(&app).await?,"dns":"Point production domains and wildcard preview DNS to the public gateway; DNS reachability is not checked here"}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppInput {
    name: String,
    domain: String,
    mode: Mode,
}
async fn write_metadata(
    app: &App,
    headers: &HeaderMap,
    peer: SocketAddr,
    input: AppInput,
    existing: Option<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(app, headers, true).await?;
    storage(app)?;
    let plane = plane(app)?;
    if input.name.trim().is_empty()
        || input.name.len() > 100
        || input.name.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    let hostname = domain(&input.domain, app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let active = plane.store.load();
    let id = existing
        .clone()
        .map(Ok)
        .unwrap_or_else(|| openwaf_applications::id().map_err(|_| Error::Unavailable))?;
    if existing.is_some()
        && active.document.routes.iter().any(|r| {
            r.application
                .as_ref()
                .is_some_and(|t| t.application_id == id)
        })
    {
        return Err(Error::Conflict);
    }
    let mut tx = app.db.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM applications")
        .fetch_one(&mut *tx)
        .await?;
    if count >= 64 && existing.is_none() {
        return Err(Error::Conflict);
    }
    let duplicate: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE domain=$1 AND id<>$2)")
            .bind(&hostname)
            .bind(&id)
            .fetch_one(&mut *tx)
            .await?;
    let preview: Option<String> = sqlx::query_scalar(
        "SELECT preview_base_domain FROM application_settings WHERE singleton=true",
    )
    .fetch_one(&mut *tx)
    .await?;
    if duplicate
        || preview
            .as_ref()
            .is_some_and(|base| hostname == *base || hostname.ends_with(&format!(".{base}")))
    {
        return Err(Error::Conflict);
    }
    let mode = match input.mode {
        Mode::Static => "static",
        Mode::Spa => "spa",
    };
    let result = if existing.is_some() {
        sqlx::query("UPDATE applications SET name=$1,domain=$2,mode=$3 WHERE id=$4")
            .bind(input.name.trim())
            .bind(&hostname)
            .bind(mode)
            .bind(&id)
            .execute(&mut *tx)
            .await?
    } else {
        sqlx::query("INSERT INTO applications(id,name,domain,mode) VALUES($1,$2,$3,$4)")
            .bind(&id)
            .bind(input.name.trim())
            .bind(&hostname)
            .bind(mode)
            .execute(&mut *tx)
            .await?
    };
    if result.rows_affected() != 1 {
        return Err(Error::NotFound);
    }
    audit(
        &mut tx,
        Some(auth.id),
        if existing.is_some() {
            "application.updated"
        } else {
            "application.created"
        },
        &format!("applications/{id}"),
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({"id":id,"domain":hostname,"tls":tls(app,&hostname)}),
    ))
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<AppInput>,
) -> ApiResult<Json<serde_json::Value>> {
    write_metadata(&app, &headers, peer, input, None).await
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    Json(input): Json<AppInput>,
) -> ApiResult<Json<serde_json::Value>> {
    app_id(&id)?;
    write_metadata(&app, &headers, peer, input, Some(id)).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    preview_base_domain: Option<String>,
}
async fn settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Settings>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    storage(&app)?;
    let base = input
        .preview_base_domain
        .map(|s| domain(&s, &app))
        .transpose()?;
    let admin = app
        .origin
        .parse::<axum::http::Uri>()
        .map_err(|_| Error::Unavailable)?
        .host()
        .ok_or(Error::Unavailable)?
        .to_owned();
    if base
        .as_ref()
        .is_some_and(|base| admin.ends_with(&format!(".{base}")))
    {
        return Err(Error::Invalid);
    }
    let plane = plane(&app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    if plane.store.load().document.routes.iter().any(|r| {
        r.application
            .as_ref()
            .is_some_and(|t| t.preview_expires_at_unix_ms.is_some())
    }) {
        return Err(Error::Conflict);
    }
    let mut tx = app.db.begin().await?;
    if let Some(base) = &base {
        let domains: Vec<String> = sqlx::query_scalar("SELECT domain FROM applications")
            .fetch_all(&mut *tx)
            .await?;
        if domains
            .iter()
            .any(|v| v == base || v.ends_with(&format!(".{base}")))
        {
            return Err(Error::Conflict);
        }
    }
    if sqlx::query("UPDATE application_settings SET preview_base_domain=$1 WHERE singleton=true")
        .bind(&base)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "application.preview_settings",
        "applications/settings",
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"preview_base_domain":base})))
}
async fn upload(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    app_id(&id)?;
    let store = storage(&app)?.clone();
    let lock = store
        .writer
        .clone()
        .try_lock_owned()
        .map_err(|_| Error::Unavailable)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM applications WHERE id=$1)")
        .bind(&id)
        .fetch_one(&app.db)
        .await?;
    if !exists {
        return Err(Error::NotFound);
    }
    retain(&app, &id).await?;
    let capacity = store.clone();
    tokio::task::spawn_blocking(move || capacity.reserve_upload())
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unavailable)?;
    let release = openwaf_applications::id().map_err(|_| Error::Unavailable)?;
    let path = store.staging(&release).map_err(|_| Error::Unavailable)?;
    let mut field = multipart
        .next_field()
        .await
        .map_err(|_| Error::Invalid)?
        .ok_or(Error::Invalid)?;
    if field.name() != Some("file") {
        return Err(Error::Invalid);
    }
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
        .map_err(|_| Error::Unavailable)?;
    let mut bytes = 0u64;
    while let Some(chunk) = field.chunk().await.map_err(|_| Error::Invalid)? {
        bytes = bytes
            .checked_add(chunk.len() as u64)
            .ok_or(Error::Invalid)?;
        if bytes > store.limits.zip_bytes {
            return Err(Error::PayloadTooLarge);
        }
        output
            .write_all(&chunk)
            .await
            .map_err(|_| Error::Unavailable)?;
    }
    output.sync_all().await.map_err(|_| Error::Unavailable)?;
    drop(output);
    drop(field);
    if bytes == 0
        || multipart
            .next_field()
            .await
            .map_err(|_| Error::Invalid)?
            .is_some()
    {
        return Err(Error::Invalid);
    }
    let worker = store.clone();
    let app_id = id.clone();
    let release_id = release.clone();
    let (manifest, _lock) = tokio::task::spawn_blocking(move || {
        let result = worker.ingest(&app_id, &release_id, &path);
        std::fs::remove_file(path).context("cannot remove upload staging file")?;
        result.map(|manifest| (manifest, lock))
    })
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(artifact_error)?;
    let mut tx = app.db.begin().await?;
    if sqlx::query("INSERT INTO application_releases(id,application_id,checksum,bytes,file_count,created_by) VALUES($1,$2,$3,$4,$5,$6)").bind(&release).bind(&id).bind(&manifest.checksum).bind(manifest.bytes as i64).bind(manifest.files.len() as i32).bind(auth.id).execute(&mut *tx).await?.rows_affected()!=1 {return Err(Error::Conflict);}
    audit(
        &mut tx,
        Some(auth.id),
        "application.release_uploaded",
        &format!("applications/{id}/releases/{release}"),
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::json!({"id":release,"checksum":manifest.checksum,"bytes":manifest.bytes,"file_count":manifest.files.len(),"state":"ready"}),
    ))
}
fn artifact_error(error: anyhow::Error) -> Error {
    if error.is::<openwaf_applications::Capacity>()
        || error.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                !matches!(
                    io.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::InvalidInput
                )
            })
        })
    {
        Error::Unavailable
    } else {
        Error::Invalid
    }
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Deploy,
    Rollback,
    Preview,
    DisablePreview,
    Disable,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    kind: Kind,
    release_id: Option<String>,
    expected_active_version: i64,
    expected_draft_revision: i64,
}
async fn prepare_action(
    app: &App,
    id: &str,
    input: &Action,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> ApiResult<Snapshot> {
    app_id(id)?;
    let row = sqlx::query("SELECT domain,mode FROM applications WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    let hostname: String = row.try_get("domain")?;
    domain(&hostname, app)?;
    let mode = match row.try_get::<String, _>("mode")?.as_str() {
        "static" => Mode::Static,
        "spa" => Mode::Spa,
        _ => return Err(Error::Unavailable),
    };
    let plane = plane(app)?;
    let active = plane.store.load();
    let state=sqlx::query("SELECT draft_revision,draft,committed_version FROM config_state WHERE singleton=true FOR UPDATE").fetch_one(&mut **tx).await?;
    let revision: i64 = state.try_get("draft_revision")?;
    let version: i64 = state.try_get("committed_version")?;
    let draft: Document = openwaf_config::resources::persisted_document(state.try_get("draft")?)
        .map_err(|_| Error::Unavailable)?;
    if revision != input.expected_draft_revision
        || version != input.expected_active_version
        || version != active.version
        || draft != active.document
        || version == i64::MAX
        || revision == i64::MAX
    {
        return Err(Error::Conflict);
    }
    let mut document = active.document.clone();
    let route_id = match input.kind {
        Kind::Preview | Kind::DisablePreview => {
            let release = input.release_id.as_ref().ok_or(Error::Invalid)?;
            app_id(release)?;
            format!("preview-{release}")
        }
        _ => format!("app-{id}"),
    };
    if document.routes.iter().any(|r| {
        r.id == route_id
            && r.application
                .as_ref()
                .is_none_or(|target| target.application_id != id)
    }) {
        return Err(Error::Conflict);
    }
    if matches!(input.kind, Kind::Disable | Kind::DisablePreview) {
        let before = document.routes.len();
        document.routes.retain(|r| r.id != route_id);
        if document.routes.len() == before {
            return Err(Error::NotFound);
        }
    } else {
        let release = input.release_id.as_ref().ok_or(Error::Invalid)?;
        app_id(release)?;
        let label: String = sqlx::query_scalar(
            "SELECT preview_label FROM application_releases WHERE id=$1 AND application_id=$2",
        )
        .bind(release)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
        let (hostname, expiry) = if matches!(input.kind, Kind::Preview) {
            let base: Option<String> = sqlx::query_scalar(
                "SELECT preview_base_domain FROM application_settings WHERE singleton=true",
            )
            .fetch_one(&mut **tx)
            .await?;
            let base = base.ok_or(Error::Invalid)?;
            domain(&base, app)?;
            (
                document
                    .routes
                    .iter()
                    .find(|r| r.id == route_id)
                    .map(|r| r.hostname.clone())
                    .unwrap_or_else(|| format!("{label}.{base}")),
                Some(now_ms() + 7 * 24 * 3600 * 1000),
            )
        } else {
            (hostname, None)
        };
        // A pre-existing root route is never silently shadowed, including method-specific routes.
        if document
            .routes
            .iter()
            .any(|r| r.id != route_id && r.host_matches(&hostname) && r.path == "/")
        {
            return Err(Error::Conflict);
        }
        let target = Target {
            application_id: id.to_owned(),
            release_id: release.to_owned(),
            mode,
            preview_expires_at_unix_ms: expiry,
        };
        if let Some(route) = document.routes.iter_mut().find(|r| r.id == route_id) {
            route.application = Some(target);
            route.hostname = hostname;
        } else {
            let route:Route=serde_json::from_value(serde_json::json!({"id":route_id,"hostname":hostname,"path":"/","path_match":"prefix","application":target,"waf":openwaf_config::waf::Policy::default()})).map_err(|_|Error::Invalid)?;
            document.routes.push(route);
        }
    }
    plane.prepare(version + 1, document).await
}
async fn review(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Action>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    storage(&app)?;
    let plane = plane(&app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let mut tx = app.db.begin().await?;
    let snapshot = prepare_action(&app, &id, &input, &mut tx).await?;
    let diff = openwaf_config::diff(&plane.store.load().document, &snapshot.document);
    let routes:Vec<_>=snapshot.document.routes.iter().filter(|r|r.application.as_ref().is_some_and(|t|t.application_id==id)).map(|r|serde_json::json!({"domain":r.hostname,"target":r.application,"tls":tls(&app,&r.hostname)})).collect();
    let child_routes: Vec<_> = snapshot
        .document
        .routes
        .iter()
        .filter(|r| {
            r.application.is_none()
                && routes.iter().any(|a| {
                    a["domain"]
                        .as_str()
                        .is_some_and(|host| r.host_matches(host))
                })
        })
        .map(|r| serde_json::json!({"id":r.id,"hostname":r.hostname,"path":r.path}))
        .collect();
    tx.rollback().await?;
    Ok(Json(
        serde_json::json!({"diff":diff,"routes":routes,"more_specific_routes":child_routes,"expected_active_version":input.expected_active_version,"expected_draft_revision":input.expected_draft_revision}),
    ))
}
async fn action(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    Json(input): Json<Action>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    storage(&app)?;
    let plane = plane(&app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let mut tx = app.db.begin().await?;
    let snapshot = prepare_action(&app, &id, &input, &mut tx).await?;
    let diff = openwaf_config::diff(&plane.store.load().document, &snapshot.document);
    let value = serde_json::to_value(&snapshot.document).map_err(|_| Error::Invalid)?;
    if sqlx::query(
        "INSERT INTO config_versions(version,document,diff,created_by) VALUES($1,$2,$3,$4)",
    )
    .bind(snapshot.version)
    .bind(&value)
    .bind(serde_json::to_value(&diff).map_err(|_| Error::Invalid)?)
    .bind(auth.id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    if sqlx::query("UPDATE config_state SET committed_version=$1,draft=$2,draft_revision=draft_revision+1 WHERE singleton=true AND committed_version=$3 AND draft_revision=$4").bind(snapshot.version).bind(&value).bind(input.expected_active_version).bind(input.expected_draft_revision).execute(&mut *tx).await?.rows_affected()!=1 {return Err(Error::Conflict);}
    let name = match input.kind {
        Kind::Deploy => "application.deployed",
        Kind::Rollback => "application.rolled_back",
        Kind::Preview => "application.preview_enabled",
        Kind::DisablePreview => "application.preview_disabled",
        Kind::Disable => "application.disabled",
    };
    audit(
        &mut tx,
        Some(auth.id),
        name,
        &format!(
            "applications/{id}/{}",
            input.release_id.as_deref().unwrap_or("routing")
        ),
        Some(peer),
    )
    .await?;
    let version = snapshot.version;
    tx.commit().await?;
    plane.store.publish(snapshot);
    Ok(Json(
        serde_json::json!({"active_version":version,"diff":diff}),
    ))
}
async fn delete_release(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path((id, release)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    app_id(&id)?;
    app_id(&release)?;
    let store = storage(&app)?.clone();
    let _lock = store.writer.try_lock().map_err(|_| Error::Conflict)?;
    remove_release(&app, &id, &release, Some((auth.id, peer))).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove_release(
    app: &App,
    id: &str,
    release: &str,
    actor: Option<(i64, SocketAddr)>,
) -> ApiResult<()> {
    let plane = plane(app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    if plane.store.load().document.routes.iter().any(|r| {
        r.application
            .as_ref()
            .is_some_and(|t| t.release_id == release)
    }) {
        return Err(Error::Conflict);
    }
    let mut tx = app.db.begin().await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM application_releases WHERE id=$1 AND application_id=$2)",
    )
    .bind(release)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if !exists {
        return Err(Error::NotFound);
    }
    // DB deletion commits first. A crash leaves an orphan that the janitor can safely retry.
    // Artifact deletion is deferred until every snapshot/request lease has retired.
    if sqlx::query("DELETE FROM application_releases WHERE id=$1 AND application_id=$2")
        .bind(release)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        actor.map(|a| a.0),
        "application.release_deleted",
        &format!("applications/{id}/releases/{release}"),
        actor.map(|a| a.1),
    )
    .await?;
    tx.commit().await?;
    let store = storage(app)?.clone();
    let release = release.to_owned();
    match tokio::task::spawn_blocking(move || store.remove(&release)).await {
        Ok(Ok(_)) => {}
        _ => eprintln!("Application release metadata deleted; artifact cleanup deferred for retry"),
    }
    Ok(())
}
async fn retain(app: &App, id: &str) -> ApiResult<()> {
    let keep = storage(app)?.limits.retained_releases;
    let releases: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM application_releases WHERE application_id=$1 ORDER BY created_at DESC",
    )
    .bind(id)
    .fetch_all(&app.db)
    .await?;
    let mut remaining = releases.len();
    // Reserve one slot for this upload, preserving the newest releases even
    // when older protected releases also remain in the inventory.
    for release in releases.iter().skip(keep.saturating_sub(1)).rev() {
        match remove_release(app, id, release, None).await {
            Ok(()) => remaining -= 1,
            Err(Error::Conflict) => {}
            Err(e) => return Err(e),
        }
    }
    if remaining >= 64 {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Owned by the admin supervisor; cancellation drops this loop. No detached tasks.
pub async fn run(app: &App) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if app.applications.is_none() {
            continue;
        }
        if !matches!(
            tokio::time::timeout(Duration::from_secs(30), cleanup(app)).await,
            Ok(Ok(()))
        ) {
            eprintln!("Applications cleanup unavailable; artifacts retained for retry");
        }
    }
}
async fn cleanup(app: &App) -> ApiResult<()> {
    let store = storage(app)?.clone();
    let lock = store
        .writer
        .clone()
        .try_lock_owned()
        .map_err(|_| Error::Conflict)?;
    // Expired preview routes are removed through the normal durable publication path.
    let plane = plane(app)?;
    let expired: Vec<_> = plane
        .store
        .load()
        .document
        .routes
        .iter()
        .filter_map(|r| {
            r.application
                .as_ref()
                .filter(|t| {
                    t.preview_expires_at_unix_ms
                        .is_some_and(|expiry| expiry <= now_ms())
                })
                .cloned()
        })
        .collect();
    for target in expired {
        expire_preview(app, &target).await?;
    }
    let apps: Vec<String> = sqlx::query_scalar("SELECT id FROM applications LIMIT 65")
        .fetch_all(&app.db)
        .await?;
    for id in apps {
        retain_after_upload(app, &id).await?;
    }
    let known: std::collections::BTreeSet<String> =
        sqlx::query_scalar::<_, String>("SELECT id FROM application_releases LIMIT 4097")
            .fetch_all(&app.db)
            .await?
            .into_iter()
            .collect();
    if known.len() > 4096 {
        return Err(Error::Unavailable);
    }
    tokio::task::spawn_blocking(move || {
        let _lock = lock;
        store.sweep(&known)
    })
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)
}
async fn retain_after_upload(app: &App, id: &str) -> ApiResult<()> {
    let releases:Vec<String>=sqlx::query_scalar("SELECT id FROM application_releases WHERE application_id=$1 ORDER BY created_at DESC OFFSET $2").bind(id).bind(storage(app)?.limits.retained_releases as i64).fetch_all(&app.db).await?;
    for release in releases {
        match remove_release(app, id, &release, None).await {
            Ok(()) | Err(Error::Conflict) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
async fn expire_preview(app: &App, target: &Target) -> ApiResult<()> {
    let plane = plane(app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Conflict)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let active = plane.store.load();
    let mut tx = app.db.begin().await?;
    let state=sqlx::query("SELECT draft_revision,draft,committed_version FROM config_state WHERE singleton=true FOR UPDATE").fetch_one(&mut *tx).await?;
    let draft: Document = openwaf_config::resources::persisted_document(state.try_get("draft")?)
        .map_err(|_| Error::Unavailable)?;
    let version: i64 = state.try_get("committed_version")?;
    let revision: i64 = state.try_get("draft_revision")?;
    if version != active.version
        || draft != active.document
        || version == i64::MAX
        || revision == i64::MAX
    {
        return Err(Error::Conflict);
    }
    let mut document = active.document.clone();
    document
        .routes
        .retain(|r| r.application.as_ref() != Some(target));
    let snapshot = plane.prepare(version + 1, document).await?;
    let value = serde_json::to_value(&snapshot.document).map_err(|_| Error::Invalid)?;
    let diff = serde_json::to_value(openwaf_config::diff(&active.document, &snapshot.document))
        .map_err(|_| Error::Invalid)?;
    if sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES($1,$2,$3)")
        .bind(snapshot.version)
        .bind(&value)
        .bind(diff)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(Error::Conflict);
    }
    if sqlx::query("UPDATE config_state SET committed_version=$1,draft=$2,draft_revision=draft_revision+1 WHERE singleton=true AND committed_version=$3 AND draft_revision=$4").bind(snapshot.version).bind(value).bind(version).bind(revision).execute(&mut *tx).await?.rows_affected()!=1 {return Err(Error::Conflict);}
    audit(
        &mut tx,
        None,
        "application.preview_expired",
        &format!(
            "applications/{}/releases/{}",
            target.application_id, target.release_id
        ),
        None,
    )
    .await?;
    tx.commit().await?;
    plane.store.publish(snapshot);
    Ok(())
}

async fn certificate_jobs(app: &App) -> ApiResult<Vec<serde_json::Value>> {
    let rows=sqlx::query("SELECT hostname,state,covered_by_hostname,attempts,updated_at::text AS updated_at FROM application_certificates ORDER BY hostname LIMIT 129").fetch_all(&app.db).await?;
    Ok(rows.into_iter().map(|r|Ok(serde_json::json!({"hostname":r.try_get::<String,_>("hostname")?,"state":r.try_get::<String,_>("state")?,"covered_by_hostname":r.try_get::<Option<String>,_>("covered_by_hostname")?,"attempts":r.try_get::<i32,_>("attempts")?,"updated_at":r.try_get::<String,_>("updated_at")?}))).collect::<std::result::Result<_,sqlx::Error>>()?)
}
async fn retry_certificates(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    storage(&app)?;
    if !certificates::configured() {
        return Err(Error::Unavailable);
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("UPDATE application_certificates SET attempts=0,state='pending',next_attempt=now(),updated_at=now() WHERE state='degraded'").execute(&mut *tx).await?;
    audit(
        &mut tx,
        Some(auth.id),
        "application.certificates_retry",
        "applications/certificates",
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
