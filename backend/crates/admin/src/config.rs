//! Serialize prepare/commit/publication outside the proxy runtime. No await
//! between successful database commit and infallible ArcSwap publication.
use super::*;
use openwaf_config::{Context as ConfigContext, Document, Snapshot, Store, diff};
use sqlx::{Postgres, pool::PoolConnection};

#[derive(Debug)]
pub enum PreparationUnavailable {
    InvalidPolicy,
    Unavailable,
}

#[async_trait::async_trait]
pub trait Preparer: Send + Sync {
    async fn prepare(
        &self,
        snapshot: Snapshot,
    ) -> std::result::Result<Snapshot, PreparationUnavailable>;
}

const OWNER_LOCK: i64 = 0x4f574346;
pub struct Plane {
    pub store: Arc<Store>,
    db: PgPool,
    pub(super) applications: Option<Arc<openwaf_applications::Store>>,
    key: MasterKey,
    preparer: Option<Arc<dyn Preparer>>,
    pub(super) context: ConfigContext,
    // Session lock/liveness connection is separate from pooled transactions.
    // Cancelled transactions return to the pool for rollback immediately;
    // retaining them here could retain row locks until another API call.
    // A broken ownership connection cannot silently reacquire after an outage.
    pub(super) writer: tokio::sync::Mutex<PoolConnection<Postgres>>,
}
impl Plane {
    pub async fn load(
        db: &PgPool,
        context: ConfigContext,
        key: &MasterKey,
        preparer: Option<Arc<dyn Preparer>>,
        applications: Option<Arc<openwaf_applications::Store>>,
    ) -> Result<Self> {
        let mut owner = db.acquire().await?;
        owner.close_on_drop();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(OWNER_LOCK)
            .fetch_one(&mut *owner)
            .await?;
        ensure!(
            acquired,
            "another managed gateway owns this configuration database"
        );
        let row = sqlx::query("SELECT s.committed_version, s.draft_revision, s.draft, s.admission_defaults_upgraded, v.document FROM config_state s JOIN config_versions v ON v.version = s.committed_version WHERE singleton = true").fetch_one(&mut *owner).await?;
        let mut version: i64 = row.try_get("committed_version")?;
        let value: serde_json::Value = row.try_get("document")?;
        let mut document = openwaf_config::resources::persisted_document(value)
            .context("invalid committed config schema")?;
        let original = document.clone();
        let old_version = version;
        let draft_revision: i64 = row.try_get("draft_revision")?;
        let mut draft = openwaf_config::resources::persisted_document(row.try_get("draft")?)?;
        let origin = std::env::var("OPENWAF_ADMIN_ORIGIN").unwrap_or_default();
        let (edge_upgraded, admission_upgraded) = if origin.is_empty() {
            (false, false)
        } else {
            let edge = crate::bootstrap::upgrade_edge(&mut document, &origin)?;
            let admission = crate::bootstrap::upgrade_admission(&mut document, &origin)?;
            (edge, admission)
        };
        let needs_defaults_upgrade = !row.try_get::<bool, _>("admission_defaults_upgraded")?;
        let defaults_upgraded =
            needs_defaults_upgrade && openwaf_config::resources::upgrade_defaults(&mut document);
        let draft_defaults_upgraded =
            needs_defaults_upgrade && openwaf_config::resources::upgrade_defaults(&mut draft);
        let upgraded =
            edge_upgraded || admission_upgraded || defaults_upgraded || draft_defaults_upgraded;
        if upgraded {
            version = version.checked_add(1).context("config version exhausted")?;
            if !origin.is_empty() {
                crate::bootstrap::upgrade_edge(&mut draft, &origin)?;
                crate::bootstrap::upgrade_admission(&mut draft, &origin)?;
            }
            crate::bootstrap::validate(&draft)?;
            Snapshot::prepare(version, draft.clone(), &context)
                .context("invalid draft during admin route upgrade")?;
        }
        let seed = if let Some(host) = crate::bootstrap::public_host()? {
            if version == 0 && document == Document::default() {
                let draft: Document = serde_json::from_value(row.try_get("draft")?)?;
                ensure!(
                    row.try_get::<i64, _>("draft_revision")? == 0 && draft == Document::default(),
                    "cannot replace an existing draft during admin bootstrap"
                );
                document = crate::bootstrap::document(&host)?;
                version = 1;
                true
            } else {
                false
            }
        } else {
            false
        };
        crate::bootstrap::validate(&document)?;
        let snapshot = Snapshot::prepare(version, document, &context)
            .context("invalid committed proxy configuration")?;
        let snapshot = password_snapshot(snapshot, key)
            .map_err(|_| anyhow::anyhow!("invalid protected-route verifier"))?;
        let snapshot = match &preparer {
            Some(preparer) => preparer
                .prepare(snapshot)
                .await
                .map_err(|_| anyhow::anyhow!("cannot prepare committed configuration resources"))?,
            None => {
                ensure!(
                    !snapshot.document.routes.iter().any(|r| r.waf.is_some()),
                    "WAF policies require a configuration resource preparer"
                );
                snapshot
            }
        };
        validate_application_references(db, &snapshot.document).await?;
        let snapshot = prepare_applications(applications.as_ref(), snapshot).await?;
        if seed || upgraded {
            let mut tx = db.begin().await?;
            let value = serde_json::to_value(&snapshot.document)?;
            let difference = serde_json::to_value(diff(&original, &snapshot.document))?;
            ensure!(
                sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES($1,$2,$3)")
                    .bind(version)
                    .bind(&value)
                    .bind(difference)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                    == 1,
                "admin config version not saved"
            );
            let next_draft = if seed {
                value.clone()
            } else {
                serde_json::to_value(&draft)?
            };
            let next_revision = draft_revision
                .checked_add(1)
                .context("draft revision exhausted")?;
            ensure!(sqlx::query("UPDATE config_state SET committed_version=$1,draft_revision=$2,draft=$3,admission_defaults_upgraded=true WHERE singleton=true AND committed_version=$4 AND draft_revision=$5")
                .bind(version).bind(next_revision).bind(next_draft).bind(old_version).bind(draft_revision)
                .execute(&mut *tx).await?.rows_affected() == 1, "admin config startup conflict");
            audit(
                &mut tx,
                None,
                if seed {
                    "config.admin_bootstrap"
                } else if edge_upgraded {
                    "config.admin_axum_upgrade"
                } else if admission_upgraded {
                    "config.admin_admission_upgrade"
                } else {
                    "config.admission_defaults_upgrade"
                },
                &format!("proxy/version/{version}"),
                None,
            )
            .await?;
            tx.commit().await?;
        } else if needs_defaults_upgrade {
            // No route semantics changed (e.g. only custom quotas). Finish the
            // one-time migration without inventing a configuration version.
            ensure!(sqlx::query("UPDATE config_state SET admission_defaults_upgraded=true WHERE singleton=true AND committed_version=$1 AND draft_revision=$2 AND admission_defaults_upgraded=false")
                .bind(old_version).bind(draft_revision).execute(&mut *owner).await?.rows_affected() == 1,
                "admission defaults migration conflict");
        }
        let store = Arc::new(Store::new(snapshot));
        crate::operations::load(db, &store).await?;
        Ok(Self {
            db: db.clone(),
            applications,
            key: key.clone(),
            preparer,
            store,
            context,
            writer: tokio::sync::Mutex::new(owner),
        })
    }
    pub(super) async fn prepare(&self, version: i64, document: Document) -> ApiResult<Snapshot> {
        crate::bootstrap::validate(&document).map_err(|_| Error::Invalid)?;
        let snapshot =
            Snapshot::prepare(version, document, &self.context).map_err(|_| Error::Invalid)?;
        let snapshot = password_snapshot(snapshot, &self.key)?;
        let snapshot = match &self.preparer {
            Some(preparer) => preparer.prepare(snapshot).await.map_err(|e| match e {
                PreparationUnavailable::InvalidPolicy => Error::Invalid,
                PreparationUnavailable::Unavailable => Error::Unavailable,
            }),
            None if snapshot.document.routes.iter().any(|r| r.waf.is_some()) => {
                Err(Error::Unavailable)
            }
            None => Ok(snapshot),
        }?;
        validate_application_references(&self.db, &snapshot.document)
            .await
            .map_err(|_| Error::Invalid)?;
        prepare_applications(self.applications.as_ref(), snapshot)
            .await
            .map_err(|_| Error::Unavailable)
    }
}
async fn validate_application_references(db: &PgPool, document: &Document) -> Result<()> {
    for route in &document.routes {
        if let Some(target) = &route.application {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM application_releases WHERE id=$1 AND application_id=$2)").bind(&target.release_id).bind(&target.application_id).fetch_one(db).await?;
            ensure!(exists, "application release no longer exists");
        }
    }
    Ok(())
}
async fn prepare_applications(
    store: Option<&Arc<openwaf_applications::Store>>,
    snapshot: Snapshot,
) -> Result<Snapshot> {
    match store {
        Some(store) => store.prepare(snapshot).await,
        None if snapshot
            .document
            .routes
            .iter()
            .any(|r| r.application.is_some()) =>
        {
            anyhow::bail!("applications storage is unavailable")
        }
        None => Ok(snapshot),
    }
}
fn plane(app: &App) -> ApiResult<&Plane> {
    app.config.as_ref().ok_or(Error::Unavailable)
}

fn password_snapshot(mut snapshot: Snapshot, key: &MasterKey) -> ApiResult<Snapshot> {
    for (i, route) in snapshot.document.routes.iter().enumerate() {
        if let Some(policy) = &route.password_protect {
            let bytes = policy
                .sealed_verifier
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    std::str::from_utf8(pair)
                        .ok()
                        .and_then(|p| u8::from_str_radix(p, 16).ok())
                        .ok_or(Error::Invalid)
                })
                .collect::<ApiResult<Vec<_>>>()?;
            let plain = key
                .open(&format!("route-password:{}", route.id), &bytes)
                .map_err(|_| Error::Invalid)?;
            let hash = std::str::from_utf8(&plain).map_err(|_| Error::Invalid)?;
            // Fixed server-generated cost prevents config-supplied resource exhaustion.
            let parsed = PasswordHash::new(hash).map_err(|_| Error::Invalid)?;
            if parsed.algorithm.as_str() != "argon2id"
                || parsed.version != Some(19)
                || parsed.params.get_decimal("m") != Some(19456)
                || parsed.params.get_decimal("t") != Some(2)
                || parsed.params.get_decimal("p") != Some(1)
            {
                return Err(Error::Invalid);
            }
            snapshot.password_verifiers[i] = Some(Arc::new(Zeroizing::new(hash.to_owned())));
        }
    }
    Ok(snapshot)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    route_id: String,
    password: String,
}
impl Drop for PasswordInput {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
async fn password_verifier(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(mut input): Json<PasswordInput>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    plane(&app)?;
    if !openwaf_config::valid_id(&input.route_id) || !(12..=128).contains(&input.password.len()) {
        return Err(Error::Invalid);
    }
    let permit = app
        .hashing
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Busy)?;
    let password = Zeroizing::new(std::mem::take(&mut input.password));
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(password.as_bytes()).map(Zeroizing::new)
    })
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)?;
    let sealed = app
        .key
        .seal(
            &format!("route-password:{}", input.route_id),
            hash.as_bytes(),
        )
        .map_err(|_| Error::Unavailable)?;
    Ok(Json(
        serde_json::json!({"sealed_verifier":crypto::hex(&sealed)}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Simulation {
    source: String,
    document: Option<Document>,
    request: openwaf_config::playground::Input,
}
async fn playground(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Simulation>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    let plane = plane(&app)?;
    let value = match input.source.as_str() {
        "active" if input.document.is_none() => plane.store.load().playground(input.request),
        "draft" => {
            let document = input.document.ok_or(Error::Invalid)?;
            Snapshot::prepare(0, document, &plane.context)
                .map_err(|_| Error::Invalid)?
                .playground(input.request)
        }
        _ => return Err(Error::Invalid),
    }
    .map_err(|_| Error::Invalid)?;
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaImport {
    document: serde_json::Value,
    path: String,
    method: String,
}
async fn import_schema(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<SchemaImport>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    let policy = openwaf_config::api_schema::import(&input.document, &input.path, &input.method)
        .map_err(|_| Error::Invalid)?;
    Ok(Json(
        serde_json::json!({"policy":policy,"coverage":"selected_required_application_json_request_body_only","not_supported":["parameters","responses","security","references","composition","formats","multipart"],"applied":false}),
    ))
}
pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/config", get(status))
        .route("/api/v1/config/import-schema", post(import_schema))
        .route("/api/v1/config/password-verifier", post(password_verifier))
        .route("/api/v1/config/playground", post(playground))
        .route("/api/v1/config/profiles", get(profiles))
        .route("/api/v1/config/coverage", get(inspection_coverage))
        .route("/api/v1/config/diagnostics", post(diagnostics))
        .route("/api/v1/config/draft", axum::routing::put(save))
        .route("/api/v1/config/validate", post(validate))
        .route("/api/v1/config/apply", post(apply))
        .route("/api/v1/config/rollback", post(rollback))
        .route("/api/v1/config/versions", get(versions))
        .layer(DefaultBodyLimit::max(
            openwaf_config::MAX_CONFIG_BYTES + 1024,
        ))
}
async fn status(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    let plane = plane(&app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Unavailable)?;
    let row = sqlx::query(
        "SELECT draft_revision, draft, committed_version FROM config_state WHERE singleton = true",
    )
    .fetch_one(&mut **owner)
    .await?;
    let draft: serde_json::Value = row.try_get("draft")?;
    let draft =
        openwaf_config::resources::persisted_document(draft).map_err(|_| Error::Unavailable)?;
    let active = plane.store.load();
    let committed: i64 = row.try_get("committed_version")?;
    Ok(Json(
        serde_json::json!({"draft_revision": row.try_get::<i64,_>("draft_revision")?, "draft": draft,
        "committed_version": committed, "active_version": active.version, "active": active.document, "upstream_health": active.health.status(),
        "inspection_coverage": coverage(&active), "diagnostics": openwaf_config::traffic::diagnostics(&draft, &plane.store.1), "degraded": committed != active.version, "diff": diff(&active.document, &draft)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposed {
    document: Document,
}
async fn validate(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Proposed>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    let plane = plane(&app)?;
    let snapshot = match Snapshot::prepare(0, input.document, &plane.context) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("config operation=validate outcome=invalid reason=schema");
            return Ok(Json(serde_json::json!({"valid": false, "error": error})));
        }
    };
    // Compilation/capacity failures are unavailable, never a successful validation.
    plane.prepare(0, snapshot.document).await?;
    eprintln!("config operation=validate outcome=valid");
    Ok(Json(serde_json::json!({"valid": true, "error": null})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    expected_revision: i64,
    document: Document,
}
async fn save(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Draft>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    if input.expected_revision < 0 || input.expected_revision == i64::MAX {
        return Err(Error::Invalid);
    }
    let plane = plane(&app)?;
    let active = plane.store.load();
    if input
        .document
        .routes
        .iter()
        .filter(|r| r.application.is_some())
        .any(|r| {
            active
                .document
                .routes
                .iter()
                .find(|a| a.id == r.id)
                .is_none_or(|a| a.application != r.application || a.hostname != r.hostname)
        })
        || active
            .document
            .routes
            .iter()
            .filter(|r| r.application.is_some())
            .any(|r| {
                !input.document.routes.iter().any(|a| {
                    a.id == r.id && a.application == r.application && a.hostname == r.hostname
                })
            })
    {
        return Err(Error::Conflict);
    }
    let snapshot = plane.prepare(0, input.document).await?;
    let value = serde_json::to_value(&snapshot.document).map_err(|_| Error::Invalid)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Unavailable)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let mut tx = app.db.begin().await?;
    let result = sqlx::query("UPDATE config_state SET draft_revision = draft_revision + 1, draft = $1 WHERE singleton = true AND draft_revision = $2")
        .bind(value).bind(input.expected_revision).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "config.draft_saved",
        &format!("proxy/draft/{}", input.expected_revision + 1),
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    eprintln!(
        "config operation=draft_save outcome=committed revision={}",
        input.expected_revision + 1
    );
    Ok(Json(
        serde_json::json!({"draft_revision": input.expected_revision + 1}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    expected_draft_revision: i64,
    expected_active_version: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollback {
    version: i64,
    expected_active_version: i64,
    expected_draft_revision: i64,
}
async fn apply(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Apply>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    commit(
        &app,
        auth.id,
        peer,
        input.expected_draft_revision,
        input.expected_active_version,
        None,
    )
    .await
}
async fn rollback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(input): Json<Rollback>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    if input.version < 0 {
        return Err(Error::Invalid);
    }
    commit(
        &app,
        auth.id,
        peer,
        input.expected_draft_revision,
        input.expected_active_version,
        Some(input.version),
    )
    .await
}
async fn commit(
    app: &App,
    actor: i64,
    peer: SocketAddr,
    expected_draft: i64,
    expected_active: i64,
    rollback: Option<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    if expected_draft < 0
        || expected_active < 0
        || expected_active == i64::MAX
        || expected_draft == i64::MAX
    {
        return Err(Error::Invalid);
    }
    let plane = plane(app)?;
    let mut owner = plane.writer.try_lock().map_err(|_| Error::Unavailable)?;
    sqlx::query("SELECT 1").execute(&mut **owner).await?;
    let mut tx = app.db.begin().await?;
    let row = sqlx::query("SELECT draft_revision, draft, committed_version FROM config_state WHERE singleton = true FOR UPDATE").fetch_one(&mut *tx).await?;
    let committed: i64 = row.try_get("committed_version")?;
    let draft_revision: i64 = row.try_get("draft_revision")?;
    let active = plane.store.load();
    if committed != active.version {
        return Err(Error::Unavailable);
    }
    if draft_revision != expected_draft || committed != expected_active {
        return Err(Error::Conflict);
    }
    let value: serde_json::Value = if let Some(version) = rollback {
        sqlx::query_scalar("SELECT document FROM config_versions WHERE version = $1")
            .bind(version)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::NotFound)?
    } else {
        row.try_get("draft")?
    };
    let document =
        openwaf_config::resources::persisted_document(value).map_err(|_| Error::Invalid)?;
    // Rollback revalidates against current listeners and limits, exactly as apply.
    let snapshot = plane.prepare(committed + 1, document).await?;
    let value = serde_json::to_value(&snapshot.document).map_err(|_| Error::Invalid)?;
    let difference = serde_json::to_value(diff(&active.document, &snapshot.document))
        .map_err(|_| Error::Invalid)?;
    let result = sqlx::query("INSERT INTO config_versions (version, document, diff, rollback_from, created_by) VALUES ($1, $2, $3, $4, $5)")
        .bind(snapshot.version).bind(&value).bind(&difference).bind(rollback).bind(actor).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    // Rollback updates the draft too; a later apply cannot silently undo rollback.
    let new_draft_revision = draft_revision + i64::from(rollback.is_some());
    let result = sqlx::query("UPDATE config_state SET committed_version = $1, draft = $2, draft_revision = $3 WHERE singleton = true AND committed_version = $4 AND draft_revision = $5")
        .bind(snapshot.version).bind(&value).bind(new_draft_revision).bind(committed).bind(draft_revision).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(actor),
        if rollback.is_some() {
            "config.rollback_committed"
        } else {
            "config.committed"
        },
        &format!("proxy/version/{}", snapshot.version),
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    // Infallible, with no cancellation/await point after durable acknowledgement.
    plane.store.publish(snapshot);
    eprintln!(
        "config operation={} outcome=published version={} rollback_from={}",
        if rollback.is_some() {
            "rollback"
        } else {
            "apply"
        },
        committed + 1,
        rollback.map_or(0, |version| version)
    );
    Ok(Json(
        serde_json::json!({"active_version": committed + 1, "committed_version": committed + 1, "draft_revision": new_draft_revision, "rollback_from": rollback, "diff": difference}),
    ))
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionFilter {
    version: Option<i64>,
}
async fn versions(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    axum::extract::Query(filter): axum::extract::Query<VersionFilter>,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    authenticate(&app, &headers, false).await?;
    plane(&app)?;
    if filter.version.is_some_and(|v| v < 0) {
        return Err(Error::Invalid);
    }
    let rows = sqlx::query("SELECT version, diff, rollback_from, created_by, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at FROM config_versions WHERE ($1::bigint IS NULL OR version=$1) ORDER BY version DESC LIMIT 100").bind(filter.version).fetch_all(&app.db).await?;
    let values = rows.into_iter().map(|row| Ok(serde_json::json!({"version": row.try_get::<i64,_>("version")?, "diff": row.try_get::<serde_json::Value,_>("diff")?, "rollback_from": row.try_get::<Option<i64>,_>("rollback_from")?, "created_by": row.try_get::<Option<i64>,_>("created_by")?, "created_at": row.try_get::<String,_>("created_at")?}))).collect::<std::result::Result<_,sqlx::Error>>()?;
    Ok(Json(values))
}

async fn profiles(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    Ok(Json(
        serde_json::json!({"schema_version":1,"templates":openwaf_config::traffic::templates()}),
    ))
}
async fn diagnostics(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(input): Json<Proposed>,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, true).await?;
    // Bound work and reject malformed invariants using the same validator as apply.
    let plane = plane(&app)?;
    let snapshot =
        Snapshot::prepare(0, input.document, &plane.context).map_err(|_| Error::Invalid)?;
    Ok(Json(
        serde_json::json!({"diagnostics":openwaf_config::traffic::diagnostics(&snapshot.document,&plane.store.1)}),
    ))
}
fn coverage(snapshot: &Snapshot) -> serde_json::Value {
    let routes: Vec<_> = snapshot.document.routes.iter().zip(&snapshot.coverage).map(|(route,c)| {
        let counts = c.counts();
        serde_json::json!({"route_id":route.id,"profile":route.profile,"counts":counts,"total":counts.iter().sum::<u64>()})
    }).collect();
    serde_json::json!({"schema_version":1,"source":"gateway_snapshot_completed_or_cancelled","observed_at_unix_ms":openwaf_telemetry::now_ms(),"config_version":snapshot.version,"scopes":openwaf_config::traffic::SCOPES,"routes":routes,"reset":"process_restart_or_config_apply","includes_retired_snapshots":false})
}

async fn inspection_coverage(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    authenticate(&app, &headers, false).await?;
    Ok(Json(coverage(&plane(&app)?.store.load())))
}
