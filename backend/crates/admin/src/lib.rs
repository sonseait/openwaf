//! Authenticated control-plane foundation; no dependency on the proxy hot path.
#![forbid(unsafe_code)]
pub mod abuse;
pub mod applications;
mod bootstrap;
pub mod certificate_bootstrap;
pub mod certificates;
pub mod config;
pub mod crypto;
mod dashboard;
pub mod discovery;
mod health;
mod investigation;
mod limiter;
pub mod operations;
pub mod shadow;
pub mod simulator;
pub mod statistics;
pub mod telegram;
pub mod telemetry;
pub mod transport;
pub mod uptime;

use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use crypto::{MasterKey, random_token, valid_name};
use limiter::Limiter;
use openssl::{memcmp, sha::sha256};
use serde::{Deserialize, Serialize};
use sqlx::{
    ConnectOptions, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use transport::Peer;
use zeroize::{Zeroize, Zeroizing};

const COOKIE: &str = "__Host-openwaf_session";
const LOCK: i64 = 0x4f574144;
const KEY_CHECK: &str = "__master_key_check";

pub struct App {
    dashboard: dashboard::Service,
    certificates: certificates::Service,
    pub applications: Option<Arc<openwaf_applications::Store>>,
    pub application_tls: Option<Arc<openwaf_tls::Store>>,
    application_certificate_health: Mutex<serde_json::Value>,
    pub simulator: Option<Arc<dyn simulator::Backend>>,
    pub abuse: Arc<openwaf_security::abuse::Service>,
    pub shadow: Option<Arc<dyn shadow::Backend>>,
    pub uptime: uptime::Service,
    pub telemetry: Option<telemetry::Service>,
    pub config: Option<config::Plane>,
    pub discovery: Option<Arc<dyn discovery::Backend>>,
    db: PgPool,
    key: MasterKey,
    origin: String,
    dummy_hash: String,
    hashing: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    limiter: Mutex<Limiter>,
}

#[derive(Clone, Copy)]
enum Error {
    Invalid,
    PayloadTooLarge,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Busy,
    SetupLimited,
    RefreshLimited,
    Unavailable,
    CloudflareDenied,
    CloudflareLimited,
    CloudflareUnavailable,
    CloudflareOutcomeUnknown,
}
type ApiResult<T> = std::result::Result<T, Error>;
impl From<openwaf_cloudflare::ApiError> for Error {
    fn from(error: openwaf_cloudflare::ApiError) -> Self {
        use openwaf_cloudflare::ApiError as E;
        match error {
            E::Denied => Self::CloudflareDenied,
            E::Limited => Self::CloudflareLimited,
            E::NotFound => Self::NotFound,
            E::Rejected => Self::Invalid,
            E::Unavailable => Self::CloudflareUnavailable,
            E::OutcomeUnknown => Self::CloudflareOutcomeUnknown,
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "validation"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::RefreshLimited => (StatusCode::TOO_MANY_REQUESTS, "refresh_rate_limited"),
            Self::Busy => (StatusCode::TOO_MANY_REQUESTS, "login_rate_limited"),
            Self::SetupLimited => (StatusCode::TOO_MANY_REQUESTS, "setup_rate_limited"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::CloudflareDenied => (StatusCode::BAD_GATEWAY, "cloudflare_permission_denied"),
            Self::CloudflareLimited => (StatusCode::TOO_MANY_REQUESTS, "cloudflare_rate_limited"),
            Self::CloudflareUnavailable => (StatusCode::BAD_GATEWAY, "cloudflare_unavailable"),
            Self::CloudflareOutcomeUnknown => {
                (StatusCode::BAD_GATEWAY, "cloudflare_outcome_unknown")
            }
        };
        let mut response = (status, Json(serde_json::json!({"error": code}))).into_response();
        if matches!(
            self,
            Self::Busy | Self::SetupLimited | Self::RefreshLimited | Self::CloudflareLimited
        ) {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_static(if matches!(self, Self::RefreshLimited) {
                    "2"
                } else {
                    "60"
                }),
            );
        }
        response
    }
}

pub async fn connect(url: &str) -> Result<PgPool> {
    // Disable statement logs: bind parameters may contain hashes/encrypted data.
    let options = PgConnectOptions::from_str(url)
        .map_err(|_| anyhow::anyhow!("invalid admin database configuration"))?
        .disable_statement_logging()
        .options([("statement_timeout", "3000"), ("lock_timeout", "2000")]);
    let db = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(options)
        .await
        .map_err(|_| anyhow::anyhow!("admin database unavailable"))?;
    sqlx::migrate!()
        .run(&db)
        .await
        .context("admin schema migration failed")?;
    Ok(db)
}

pub async fn validate_key(db: &PgPool, key: &MasterKey) -> Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK)
        .execute(&mut *tx)
        .await?;
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT envelope FROM secret_key_check WHERE singleton = true")
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(envelope) = existing {
        ensure!(
            key.open(KEY_CHECK, &envelope)?.as_slice() == b"openwaf-admin-master-v1",
            "invalid admin key verifier"
        );
    } else {
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            count == 0,
            "missing master key verifier for existing credentials"
        );
        let envelope = key.seal(KEY_CHECK, b"openwaf-admin-master-v1")?;
        ensure!(
            sqlx::query("INSERT INTO secret_key_check (envelope) VALUES ($1)")
                .bind(envelope)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1,
            "master key verifier was not saved"
        );
    }
    let credentials = sqlx::query("SELECT name, envelope FROM credentials LIMIT 129")
        .fetch_all(&mut *tx)
        .await?;
    ensure!(credentials.len() <= 128, "too many credentials");
    for row in credentials {
        let name: String = row.try_get("name")?;
        let envelope: Vec<u8> = row.try_get("envelope")?;
        key.open(&name, &envelope)?;
    }
    let providers = sqlx::query("SELECT id,credential FROM certificate_providers LIMIT 17")
        .fetch_all(&mut *tx)
        .await?;
    ensure!(providers.len() <= 16, "too many certificate providers");
    for row in providers {
        let id: String = row.try_get("id")?;
        let bytes: Vec<u8> = row.try_get("credential")?;
        let plain = key.open(&format!("cloudflare-provider:{id}"), &bytes)?;
        serde_json::from_slice::<openwaf_cloudflare::Credentials>(&plain)?.validate()?;
    }
    tx.commit().await?;
    Ok(())
}

fn hash_password(password: &[u8]) -> Result<String> {
    let mut salt = [0; 16];
    openssl::rand::rand_bytes(&mut salt)?;
    let salt =
        SaltString::encode_b64(&salt).map_err(|_| anyhow::anyhow!("password salt failed"))?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| anyhow::anyhow!("password hash failed"))
}

impl App {
    pub async fn new(db: PgPool, key: MasterKey, origin: String) -> Result<Arc<Self>> {
        let uri: axum::http::Uri = origin.parse().context("invalid admin origin")?;
        ensure!(
            uri.scheme_str() == Some("https")
                && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
                && uri.path() == "/"
                && uri.query().is_none()
                && !origin.ends_with('/'),
            "admin origin must be an exact HTTPS origin without path or trailing slash"
        );
        validate_key(&db, &key).await?;
        bootstrap::validate_origin(&origin)?;
        let dummy_hash =
            tokio::task::spawn_blocking(|| hash_password(b"unused dummy password")).await??;
        Ok(Arc::new(Self {
            dashboard: dashboard::Service::from_env().await?,
            certificates: certificates::Service::from_env(&db, &key).await,
            applications: std::env::var_os("OPENWAF_APPLICATIONS_ROOT")
                .map(|root| {
                    openwaf_applications::Store::open(
                        root.into(),
                        openwaf_applications::Limits::from_env()?,
                    )
                })
                .transpose()?,
            application_tls: None,
            application_certificate_health: Mutex::new(
                serde_json::json!({"state":"starting","observed_at_unix_ms":openwaf_applications::now_ms()}),
            ),
            simulator: None,
            abuse: Arc::new(openwaf_security::abuse::Service::default()),
            shadow: None,
            uptime: uptime::Service::default(),
            telemetry: None,
            config: None,
            discovery: None,
            db,
            key,
            origin,
            dummy_hash,
            hashing: Arc::new(Semaphore::new(2)),
            requests: Arc::new(Semaphore::new(64)),
            limiter: Mutex::new(Limiter::new()),
        }))
    }

    pub async fn managed(
        db: PgPool,
        key: MasterKey,
        origin: String,
        context: openwaf_config::Context,
    ) -> Result<Arc<Self>> {
        Self::managed_prepared(db, key, origin, context, None).await
    }

    pub async fn managed_prepared(
        db: PgPool,
        key: MasterKey,
        origin: String,
        context: openwaf_config::Context,
        preparer: Option<Arc<dyn config::Preparer>>,
    ) -> Result<Arc<Self>> {
        let mut app = Self::new(db.clone(), key.clone(), origin).await?;
        let plane =
            config::Plane::load(&db, context, &key, preparer, app.applications.clone()).await?;
        Arc::get_mut(&mut app)
            .context("admin app unexpectedly shared during startup")?
            .config = Some(plane);
        Ok(app)
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/v1/auth/setup", get(setup_status).post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/session", get(session_info))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/credentials", get(credentials))
        .route(
            "/api/v1/credentials/{name}",
            axum::routing::put(put_credential).delete(delete_credential),
        )
        .route("/api/v1/audit", get(audit_history))
        .merge(config::routes())
        .merge(applications::routes())
        .merge(certificates::routes())
        .merge(discovery::routes())
        .merge(telemetry::routes())
        .merge(uptime::routes())
        .merge(operations::routes())
        .merge(telegram::routes())
        .merge(shadow::routes())
        .merge(abuse::routes())
        .merge(simulator::routes())
        .merge(investigation::routes())
        .merge(health::routes())
        .fallback(dashboard::serve)
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}

async fn guard(
    State(app): State<Arc<App>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let version = request.version();
    let connection = request
        .extensions()
        .get::<ConnectInfo<transport::ConnectionInfo>>()
        .map(|v| v.0.clone());
    if let Some(info) = &connection {
        request.extensions_mut().insert(ConnectInfo(info.peer));
    }
    let mut response = match app.requests.clone().try_acquire_owned() {
        Err(_) => Error::Unavailable.into_response(),
        Ok(_permit) => {
            if request.method() != Method::GET
                && request.method() != Method::HEAD
                && request
                    .headers()
                    .get(header::ORIGIN)
                    .and_then(|v| v.to_str().ok())
                    != Some(&app.origin)
            {
                Error::Forbidden.into_response()
            } else {
                async {
                    let upload = request.method() == Method::POST
                        && request.uri().path().starts_with("/api/v1/applications/")
                        && request.uri().path().ends_with("/releases");
                    if upload {
                        if let Err(error) = authenticate(&app, request.headers(), true).await {
                            return error.into_response();
                        }
                        if let Some(connection) = &connection {
                            connection.extend_upload();
                        }
                    }
                    match tokio::time::timeout(
                        Duration::from_secs(if upload { 180 } else { 10 }),
                        next.run(request),
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(_) => Error::Unavailable.into_response(),
                    }
                }
                .await
            }
        }
    };
    // Axum's JSON/path rejections can quote invalid input; keep errors redacted.
    if response.status().is_client_error() && response.status() != StatusCode::TOO_MANY_REQUESTS {
        let status = response.status();
        let code = match status {
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
            _ => "validation",
        };
        response = (status, Json(serde_json::json!({"error": code}))).into_response();
    }
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/html"));
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            if is_html {
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; frame-src 'self' about:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            } else {
                "default-src 'none'; frame-ancestors 'none'"
            },
        ),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    if let Some(info) = connection {
        response = info.finish_event_stream(response, version);
    }
    response
}

struct Auth {
    id: i64,
    username: String,
    token: Zeroizing<String>,
}
async fn authenticate(app: &App, headers: &HeaderMap, mutate: bool) -> ApiResult<Auth> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for cookie in value.to_str().map_err(|_| Error::Unauthorized)?.split(';') {
            if let Some((name, value)) = cookie.trim().split_once('=')
                && name == COOKIE
            {
                if found.is_some() {
                    return Err(Error::Unauthorized);
                }
                found = Some(value);
            }
        }
    }
    let token = found
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .ok_or(Error::Unauthorized)?;
    if mutate {
        let expected = app.key.csrf(token).map_err(|_| Error::Unavailable)?;
        let provided = headers
            .get("x-csrf-token")
            .map(|v| v.as_bytes())
            .ok_or(Error::Forbidden)?;
        if provided.len() != expected.len() || !memcmp::eq(provided, expected.as_bytes()) {
            return Err(Error::Forbidden);
        }
    }
    let row = sqlx::query("SELECT u.id, u.username FROM admin_sessions s JOIN admin_users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()")
        .bind(sha256(token.as_bytes()).as_slice()).fetch_optional(&app.db).await?.ok_or(Error::Unauthorized)?;
    Ok(Auth {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        token: Zeroizing::new(token.to_owned()),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}
impl Drop for Login {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
#[derive(Serialize)]
struct SessionInfo {
    username: String,
    csrf_token: String,
    expires_at: String,
}

#[derive(Serialize)]
struct SetupStatus {
    setup_required: bool,
}

async fn has_admin(db: &PgPool) -> ApiResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admin_users)")
            .fetch_one(db)
            .await?,
    )
}

async fn setup_status(State(app): State<Arc<App>>) -> ApiResult<Json<SetupStatus>> {
    Ok(Json(SetupStatus {
        setup_required: !has_admin(&app.db).await?,
    }))
}

/// First deployment only. Serialize setup across all admin server instances.
async fn setup(
    State(app): State<Arc<App>>,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(mut input): Json<Login>,
) -> ApiResult<StatusCode> {
    if has_admin(&app.db).await? {
        return Err(Error::Conflict);
    }
    let admitted = app.limiter.lock().map_err(|_| Error::Unavailable)?.admit(
        peer.ip().to_string(),
        "first-admin-setup".into(),
        Instant::now(),
    );
    if !admitted {
        return Err(Error::SetupLimited);
    }
    if !valid_name(&input.username) || !(12..=128).contains(&input.password.len()) {
        return Err(Error::Invalid);
    }
    let permit = app
        .hashing
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable)?;
    let password = Zeroizing::new(std::mem::take(&mut input.password));
    // Cancellation cannot release the worker permit or password while hashing.
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(password.as_bytes())
    })
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|_| Error::Unavailable)?;
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK)
        .execute(&mut *tx)
        .await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admin_users)")
        .fetch_one(&mut *tx)
        .await?;
    if exists {
        return Err(Error::Conflict);
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(&input.username)
    .bind(hash)
    .fetch_one(&mut *tx)
    .await?;
    audit(
        &mut tx,
        Some(id),
        "admin.bootstrap",
        &input.username,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

async fn login(
    State(app): State<Arc<App>>,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Json(mut input): Json<Login>,
) -> ApiResult<Response> {
    if !valid_name(&input.username) || input.password.is_empty() || input.password.len() > 128 {
        return Err(Error::Invalid);
    }
    let admitted = app.limiter.lock().map_err(|_| Error::Unavailable)?.admit(
        peer.ip().to_string(),
        crypto::hex(&sha256(input.username.as_bytes())),
        Instant::now(),
    );
    if !admitted {
        return Err(Error::Busy);
    }
    let permit = app
        .hashing
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Unavailable)?;
    let row = sqlx::query("SELECT id, password_hash FROM admin_users WHERE username = $1")
        .bind(&input.username)
        .fetch_optional(&app.db)
        .await?;
    let (id, hash) = match row {
        Some(row) => (
            Some(row.try_get::<i64, _>("id")?),
            row.try_get::<String, _>("password_hash")?,
        ),
        None => (None, app.dummy_hash.clone()),
    };
    let password = Zeroizing::new(std::mem::take(&mut input.password));
    // The blocking closure owns its permit and password after caller cancellation.
    let matches = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .map_err(|_| Error::Unavailable)?;
    let mut tx = app.db.begin().await?;
    if !matches || id.is_none() {
        // No untrusted username/password is recorded for failed authentication.
        audit(&mut tx, None, "auth.login_failed", "login", Some(peer)).await?;
        tx.commit().await?;
        return Err(Error::Unauthorized);
    }
    let id = id.ok_or(Error::Unauthorized)?;
    // Serialize per-user session cap. Expired sessions cannot accumulate on login.
    sqlx::query("SELECT id FROM admin_users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM admin_sessions WHERE token_hash IN (SELECT token_hash FROM admin_sessions WHERE user_id = $1 ORDER BY created_at DESC, token_hash OFFSET 9)").bind(id).execute(&mut *tx).await?;
    let token = Zeroizing::new(random_token().map_err(|_| Error::Unavailable)?);
    let expiry: String = sqlx::query_scalar("INSERT INTO admin_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '12 hours') RETURNING to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
        .bind(sha256(token.as_bytes()).as_slice()).bind(id).fetch_one(&mut *tx).await?;
    audit(&mut tx, Some(id), "auth.login", "session", Some(peer)).await?;
    tx.commit().await?;
    let csrf_token = app.key.csrf(&token).map_err(|_| Error::Unavailable)?;
    let mut response = Json(SessionInfo {
        username: input.username.clone(),
        csrf_token,
        expires_at: expiry,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={}; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict",
            token.as_str()
        ))
        .map_err(|_| Error::Unavailable)?,
    );
    Ok(response)
}

async fn session_info(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<SessionInfo>> {
    let auth = authenticate(&app, &headers, false).await?;
    let expires_at = sqlx::query_scalar("SELECT to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') FROM admin_sessions WHERE token_hash = $1 AND expires_at > now()")
        .bind(sha256(auth.token.as_bytes()).as_slice()).fetch_optional(&app.db).await?.ok_or(Error::Unauthorized)?;
    Ok(Json(SessionInfo {
        username: auth.username,
        csrf_token: app.key.csrf(&auth.token).map_err(|_| Error::Unavailable)?,
        expires_at,
    }))
}

async fn logout(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
) -> ApiResult<Response> {
    let auth = authenticate(&app, &headers, true).await?;
    let mut tx = app.db.begin().await?;
    let result = sqlx::query("DELETE FROM admin_sessions WHERE token_hash = $1")
        .bind(sha256(auth.token.as_bytes()).as_slice())
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    audit(&mut tx, Some(auth.id), "auth.logout", "session", Some(peer)).await?;
    tx.commit().await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-openwaf_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        ),
    );
    Ok(response)
}

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: Option<i64>,
    action: &str,
    target: &str,
    peer: Option<SocketAddr>,
) -> std::result::Result<(), sqlx::Error> {
    let result = sqlx::query("INSERT INTO admin_audit (actor_id, action, target, source_ip) VALUES ($1, $2, $3, $4::inet)")
        .bind(actor).bind(action).bind(target).bind(peer.map(|p| p.ip().to_string())).execute(&mut **tx).await?;
    if result.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

#[derive(Serialize)]
struct Credential {
    name: String,
    revision: i64,
    updated_at: String,
}
async fn credentials(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<Credential>>> {
    authenticate(&app, &headers, false).await?;
    let rows = sqlx::query("SELECT name, revision, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS updated_at FROM credentials ORDER BY name LIMIT 128").fetch_all(&app.db).await?;
    let entries = rows
        .into_iter()
        .map(|row| {
            Ok(Credential {
                name: row.try_get("name")?,
                revision: row.try_get("revision")?,
                updated_at: row.try_get("updated_at")?,
            })
        })
        .collect::<std::result::Result<_, sqlx::Error>>()?;
    Ok(Json(entries))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretInput {
    value: String,
    expected_revision: Option<i64>,
}
impl Drop for SecretInput {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

async fn put_credential(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(name): Path<String>,
    Json(input): Json<SecretInput>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    if !valid_name(&name)
        || input.value.is_empty()
        || input.value.len() > 2048
        || input
            .expected_revision
            .is_some_and(|r| r < 1 || r == i64::MAX)
    {
        return Err(Error::Invalid);
    }
    let envelope = app
        .key
        .seal(&name, input.value.as_bytes())
        .map_err(|_| Error::Unavailable)?;
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK)
        .execute(&mut *tx)
        .await?;
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM credentials WHERE name = $1")
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await?;
    let next = match (revision, input.expected_revision) {
        (None, None) => {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
                .fetch_one(&mut *tx)
                .await?;
            if count >= 128 {
                return Err(Error::Conflict);
            }
            let result = sqlx::query("INSERT INTO credentials (name, envelope) VALUES ($1, $2)")
                .bind(&name)
                .bind(envelope)
                .execute(&mut *tx)
                .await?;
            if result.rows_affected() != 1 {
                return Err(Error::Conflict);
            }
            1
        }
        (None, Some(_)) => return Err(Error::NotFound),
        (Some(current), Some(expected)) if current == expected => {
            let result = sqlx::query("UPDATE credentials SET envelope = $1, revision = revision + 1, updated_at = now() WHERE name = $2 AND revision = $3").bind(envelope).bind(&name).bind(expected).execute(&mut *tx).await?;
            if result.rows_affected() != 1 {
                return Err(Error::Conflict);
            }
            expected + 1
        }
        _ => return Err(Error::Conflict),
    };
    audit(
        &mut tx,
        Some(auth.id),
        "credential.write",
        &name,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"name": name, "revision": next})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    expected_revision: i64,
}
async fn delete_credential(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(name): Path<String>,
    Json(input): Json<Revision>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    if !valid_name(&name) || input.expected_revision < 1 {
        return Err(Error::Invalid);
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(LOCK)
        .execute(&mut *tx)
        .await?;
    let revision: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM credentials WHERE name = $1")
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await?;
    if revision.is_none() {
        return Err(Error::NotFound);
    }
    if revision != Some(input.expected_revision) {
        return Err(Error::Conflict);
    }
    let result = sqlx::query("DELETE FROM credentials WHERE name = $1 AND revision = $2")
        .bind(&name)
        .bind(input.expected_revision)
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(Error::Conflict);
    }
    audit(
        &mut tx,
        Some(auth.id),
        "credential.delete",
        &name,
        Some(peer),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn audit_history(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<serde_json::Value>>> {
    authenticate(&app, &headers, false).await?;
    let rows = sqlx::query("SELECT id, actor_id, action, target, host(source_ip) AS source_ip, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS occurred_at FROM admin_audit ORDER BY id DESC LIMIT 100").fetch_all(&app.db).await?;
    let entries = rows.into_iter().map(|row| Ok(serde_json::json!({
        "id": row.try_get::<i64, _>("id")?, "actor_id": row.try_get::<Option<i64>, _>("actor_id")?,
        "action": row.try_get::<String, _>("action")?, "target": row.try_get::<String, _>("target")?,
        "source_ip": row.try_get::<Option<String>, _>("source_ip")?, "occurred_at": row.try_get::<String, _>("occurred_at")?
    }))).collect::<std::result::Result<_, sqlx::Error>>()?;
    Ok(Json(entries))
}
