//! Public admin origin and managed route bootstrap. No account provisioning.
use crate::*;
use openwaf_config::{Document, Route, Upstream};

pub(crate) fn public_host() -> Result<Option<String>> {
    match std::env::var("OPENWAF_ADMIN_PUBLIC").as_deref() {
        Ok("true") => {
            let host = openwaf_config::hostname(&std::env::var("OPENWAF_ADMIN_HOST")?)?;
            ensure!(
                !host.starts_with("*.") && host.parse::<std::net::IpAddr>().is_err(),
                "invalid public admin hostname"
            );
            Ok(Some(host))
        }
        Ok("false") | Err(std::env::VarError::NotPresent) => Ok(None),
        _ => anyhow::bail!("OPENWAF_ADMIN_PUBLIC must be true or false"),
    }
}

pub(crate) fn validate_origin(origin: &str) -> Result<()> {
    if let Some(host) = public_host()? {
        ensure!(
            valid_origin(origin, &host),
            "public admin origin must be HTTPS on OPENWAF_ADMIN_HOST"
        );
    }
    Ok(())
}

pub(crate) fn document(host: &str) -> Result<Document> {
    let route: Route = serde_json::from_value(serde_json::json!({
        "id":"openwaf-admin", "hostname":host, "path":"/", "path_match":"prefix",
        "upstream":"openwaf-admin-edge", "waf":{"mode":"DetectionOnly"},
        // SSE holds request slots while the browser fetches API data and lazy chunks.
        "admission":{"requests":64,"streams":8,"uploads":4,"per_client":32},
        "body":{"inspection":"headers-query-only","max_body_bytes":1074790400,"idle_timeout_ms":120000}
    }))?;
    let upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id":"openwaf-admin-edge",
        "endpoints":[{"address":"127.0.0.1:9090","protocol":"http","tls_server_name":null}],
        "timeouts":{"total_ms":200000,"read_ms":120000,"write_ms":120000},
        "health":{"method":"GET","path":"/"}
    }))?;
    Ok(Document {
        routes: vec![route],
        upstreams: vec![upstream],
        ..Default::default()
    })
}

fn valid_origin(origin: &str, host: &str) -> bool {
    origin.parse::<axum::http::Uri>().is_ok_and(|uri| {
        uri.scheme_str() == Some("https")
            && uri.host() == Some(host)
            && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
            && uri.path() == "/"
            && uri.query().is_none()
            && uri.port_u16() != Some(0)
    })
}

/// Upgrade only the known, exclusively used admin-edge endpoint. Custom
/// upstreams and unrelated routes are never rewritten during startup.
pub(crate) fn upgrade_edge(document: &mut Document, origin: &str) -> Result<bool> {
    let uri: axum::http::Uri = origin.parse()?;
    let host = uri.host().context("admin origin needs a hostname")?;
    let mut changed = false;
    for upstream in &mut document.upstreams {
        if !matches!(upstream.id.as_str(), "openwaf-admin" | "openwaf-admin-edge")
            || upstream.endpoints.len() != 1
        {
            continue;
        }
        let references: Vec<_> = document
            .routes
            .iter()
            .filter(|r| r.upstream == upstream.id)
            .collect();
        if references.len() != 1
            || references[0].id != "openwaf-admin"
            || openwaf_config::hostname(&references[0].hostname)? != host
            || references[0].path != "/"
        {
            continue;
        }
        let endpoint = &upstream.endpoints[0];
        let value = serde_json::to_value(endpoint)?;
        let nginx = value["address"] == "127.0.0.1:9080"
            && value["protocol"] == "http"
            && value["tls_server_name"].is_null();
        let caddy = value["address"] == "127.0.0.1:9443"
            && value["protocol"] == "https"
            && value["tls_server_name"] == host;
        if nginx || caddy {
            upstream.endpoints[0].address = "127.0.0.1:9090".parse()?;
            upstream.endpoints[0].protocol = openwaf_config::Protocol::Http;
            upstream.endpoints[0].tls_server_name = None;
            changed = true;
        }
    }
    Ok(changed)
}

/// Upgrade only the exact formerly packaged public route. Custom policies are
/// rejected by the reserved-route validator, never silently rewritten.
pub(crate) fn upgrade_admission(document: &mut Document, origin: &str) -> Result<bool> {
    let uri: axum::http::Uri = origin.parse()?;
    let host = uri.host().context("admin origin needs a hostname")?;
    let expected = self::document(host)?;
    let mut legacy = expected.routes[0].clone();
    legacy.admission = openwaf_config::resources::Admission::legacy_default();
    let mut changed = false;
    for route in &mut document.routes {
        if *route == legacy {
            route.admission = expected.routes[0].admission.clone();
            changed = true;
        }
    }
    Ok(changed)
}

pub(crate) fn validate(document: &Document) -> Result<()> {
    let Some(host) = public_host()? else {
        return Ok(());
    };
    validate_for(document, &host)
}
fn validate_for(document: &Document, host: &str) -> Result<()> {
    let expected = self::document(host)?;
    // The bootstrap route is part of versioned configuration. Editing, deleting,
    // shadowing or redirecting it cannot silently remove the management path.
    ensure!(
        document
            .routes
            .iter()
            .filter(|route| openwaf_config::hostname(&route.hostname)
                .is_ok_and(|name| name == host)
                || route.id == "openwaf-admin")
            .eq(expected.routes.iter()),
        "public admin route is reserved while OPENWAF_ADMIN_PUBLIC=true"
    );
    ensure!(
        document
            .upstreams
            .iter()
            .find(|upstream| upstream.id == "openwaf-admin-edge")
            == expected.upstreams.first(),
        "public admin upstream is reserved"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admin_admission_upgrade_is_scoped_bounded_and_idempotent() -> Result<()> {
        let origin = "https://admin.example.com";
        let mut old = document("admin.example.com")?;
        let expected = old.clone();
        old.routes[0].admission = openwaf_config::resources::Admission::legacy_default();
        let mut unrelated = old.routes[0].clone();
        unrelated.id = "website".into();
        unrelated.hostname = "app.example.com".into();
        old.routes.push(unrelated.clone());
        assert!(upgrade_admission(&mut old, origin)?);
        assert_eq!(old.routes[0], expected.routes[0]);
        assert_eq!(old.routes[1], unrelated);
        old.routes[0].admission.validate()?;
        assert_eq!(old.routes[0].admission.per_client, 32);
        assert!(!upgrade_admission(&mut old, origin)?);
        for change in ["quota", "host", "body"] {
            let mut custom = expected.clone();
            custom.routes[0].admission = openwaf_config::resources::Admission::legacy_default();
            match change {
                "quota" => custom.routes[0].admission.per_client = 4,
                "host" => custom.routes[0].hostname = "other.example.com".into(),
                _ => {
                    custom.routes[0]
                        .body
                        .as_mut()
                        .context("fixture body")?
                        .idle_timeout_ms = 60000
                }
            }
            let before = custom.clone();
            assert!(!upgrade_admission(&mut custom, origin)?);
            assert_eq!(custom, before);
        }
        Ok(())
    }
    #[test]
    fn edge_upgrade_is_scoped_and_idempotent() -> Result<()> {
        for (id, address, protocol, sni) in [
            ("openwaf-admin-edge", "127.0.0.1:9080", "http", None),
            (
                "openwaf-admin",
                "127.0.0.1:9443",
                "https",
                Some("admin.example.com"),
            ),
        ] {
            let mut old = document("admin.example.com")?;
            old.routes[0].upstream = id.into();
            old.upstreams[0].id = id.into();
            old.upstreams[0].endpoints[0] = serde_json::from_value(serde_json::json!({
                "address":address,"protocol":protocol,"tls_server_name":sni,"weight":3
            }))?;
            let original = old.clone();
            assert!(upgrade_edge(&mut old, "https://admin.example.com:8443")?);
            assert_eq!(old.routes, original.routes);
            assert_eq!(old.upstreams[0].endpoints[0].weight, 3);
            assert_eq!(
                old.upstreams[0].endpoints[0].address.socket(),
                Some("127.0.0.1:9090".parse()?)
            );
            assert!(!upgrade_edge(&mut old, "https://admin.example.com:8443")?);
            let mut custom = original.clone();
            assert!(!upgrade_edge(&mut custom, "https://other.example.com")?);
            assert_eq!(custom, original);
            custom.routes.push(custom.routes[0].clone());
            assert!(!upgrade_edge(&mut custom, "https://admin.example.com")?);
        }
        assert!(valid_origin(
            "https://admin.example.com:8443",
            "admin.example.com"
        ));
        assert!(!valid_origin(
            "http://admin.example.com",
            "admin.example.com"
        ));
        assert!(!valid_origin(
            "https://admin.example.com@evil.example",
            "admin.example.com"
        ));
        Ok(())
    }
    #[test]
    fn public_route_is_normalized_and_cannot_be_shadowed_or_removed() -> Result<()> {
        let host = "admin.example.com";
        let document = document(host)?;
        let context = openwaf_config::Context {
            listeners: vec!["0.0.0.0:8443".parse()?],
            local_ips: vec!["127.0.0.1".parse()?],
        };
        let snapshot = openwaf_config::Snapshot::prepare(1, document.clone(), &context)?;
        validate_for(&snapshot.document, host)?;
        assert!(validate_for(&Document::default(), host).is_err());
        let mut shadow = document.clone();
        let mut route = shadow.routes[0].clone();
        route.id = "shadow-admin".into();
        route.hostname = "ADMIN.EXAMPLE.COM.".into();
        route.path = "/api/".into();
        shadow.routes.push(route);
        assert!(validate_for(&shadow, host).is_err());
        let mut redirected = document;
        redirected.upstreams[0].endpoints[0].address =
            serde_json::from_value(serde_json::json!("127.0.0.1:9081"))?;
        assert!(validate_for(&redirected, host).is_err());
        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires a fresh isolated PostgreSQL database and public bootstrap environment"]
    async fn postgres_startup_leaves_first_admin_to_setup() -> Result<()> {
        let url = std::env::var("OPENWAF_BOOTSTRAP_TEST_DATABASE_URL")?;
        let db = connect(&url).await?;
        ensure!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_users")
                .fetch_one(&db)
                .await?
                == 0,
            "test needs a fresh database"
        );
        let host = public_host()?.context("test requires public admin environment")?;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let key_dir = tempfile::tempdir()?;
        let key_path = key_dir.path().join("master.key");
        let mut key_bytes = [0; 32];
        openssl::rand::rand_bytes(&mut key_bytes)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)?
            .write_all(&key_bytes)?;
        let key = MasterKey::load(&key_path)?;
        validate_key(&db, &key).await?;
        let origin = format!("https://{host}");
        assert!(
            App::new(db.clone(), key.clone(), "https://wrong.example.com".into())
                .await
                .is_err()
        );
        use tower::ServiceExt;
        async fn setup_required(app: Arc<App>) -> Result<bool> {
            let response = router(app)
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/api/v1/auth/setup")
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024).await?;
            let value: serde_json::Value = serde_json::from_slice(&body)?;
            value["setup_required"]
                .as_bool()
                .context("missing setup status")
        }
        let app = App::new(db.clone(), key.clone(), origin.clone()).await?;
        assert!(setup_required(app.clone()).await?);
        // Starting again before setup must still leave the database without a user.
        let second = App::new(db.clone(), key.clone(), origin.clone()).await?;
        assert!(setup_required(second.clone()).await?);
        let mut random = [0; 24];
        openssl::rand::rand_bytes(&mut random)?;
        let password = crypto::hex(&random);
        let request = |username: &str| -> Result<axum::http::Request<axum::body::Body>> {
            Ok(axum::http::Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/setup")
                .header(header::ORIGIN, &origin)
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(Peer("127.0.0.1:12345".parse()?)))
                .body(axum::body::Body::from(serde_json::to_vec(
                    &serde_json::json!({
                        "username": username, "password": password,
                    }),
                )?))?)
        };
        let (a, b) = tokio::join!(
            router(app.clone()).oneshot(request("chosen-owner")?),
            router(second.clone()).oneshot(request("another-owner")?),
        );
        let statuses = [a?.status(), b?.status()];
        assert!(statuses.contains(&StatusCode::CREATED));
        assert!(statuses.contains(&StatusCode::CONFLICT));
        assert!(!setup_required(app.clone()).await?);
        assert_eq!(
            router(app.clone())
                .oneshot(request("extra-owner")?)
                .await?
                .status(),
            StatusCode::CONFLICT
        );
        let hash: String = sqlx::query_scalar("SELECT password_hash FROM admin_users")
            .fetch_one(&db)
            .await?;
        Argon2::default()
            .verify_password(
                password.as_bytes(),
                &PasswordHash::new(&hash).map_err(|_| anyhow::anyhow!("invalid hash"))?,
            )
            .map_err(|_| anyhow::anyhow!("password verification failed"))?;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM admin_audit WHERE action='admin.bootstrap'"
            )
            .fetch_one(&db)
            .await?,
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM admin_audit WHERE action='admin.startup_bootstrap'"
            )
            .fetch_one(&db)
            .await?,
            0
        );
        drop(app);
        drop(second);
        let restarted = App::new(db.clone(), key.clone(), origin.clone()).await?;
        assert!(!setup_required(restarted.clone()).await?);
        drop(restarted);
        struct Prepared;
        #[async_trait::async_trait]
        impl crate::config::Preparer for Prepared {
            async fn prepare(
                &self,
                snapshot: openwaf_config::Snapshot,
            ) -> std::result::Result<openwaf_config::Snapshot, crate::config::PreparationUnavailable>
            {
                Ok(snapshot)
            }
        }
        let context = openwaf_config::Context {
            listeners: vec!["0.0.0.0:8443".parse()?],
            local_ips: vec!["127.0.0.1".parse()?],
        };
        let plane =
            crate::config::Plane::load(&db, context.clone(), &key, Some(Arc::new(Prepared)), None)
                .await?;
        assert_eq!(plane.store.load().version, 1);
        assert_eq!(plane.store.load().document, document(&host)?);
        assert!(plane.prepare(2, Document::default()).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM admin_audit WHERE action='config.admin_bootstrap'"
            )
            .fetch_one(&db)
            .await?,
            1
        );
        drop(plane);
        db.close().await;
        let db = connect(&url).await?;
        let plane =
            crate::config::Plane::load(&db, context.clone(), &key, Some(Arc::new(Prepared)), None)
                .await?;
        assert_eq!(plane.store.load().version, 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM config_versions")
                .fetch_one(&db)
                .await?,
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_users")
                .fetch_one(&db)
                .await?,
            1
        );
        assert_eq!(
            hash,
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM admin_users")
                .fetch_one(&db)
                .await?
        );
        drop(plane);
        // Simulate the persisted edge layout and an unrelated saved draft edit.
        // A startup upgrade must version/audit once and preserve that edit.
        ensure!(
            std::env::var("OPENWAF_ADMIN_ORIGIN")? == origin,
            "test needs matching origin environment"
        );
        let mut legacy = document(&host)?;
        legacy.upstreams[0].endpoints[0].address = "127.0.0.1:9080".parse()?;
        legacy.routes[0].admission = openwaf_config::resources::Admission::legacy_default();
        let mut draft = legacy.clone();
        let mut extra = draft.upstreams[0].clone();
        extra.id = "unrelated-draft-upstream".into();
        extra.endpoints[0].address = "192.0.2.12:8080".parse()?;
        draft.upstreams.push(extra);
        let mut tx = db.begin().await?;
        sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES(2,$1,$2)")
            .bind(serde_json::to_value(&legacy)?)
            .bind(serde_json::to_value(openwaf_config::diff(
                &document(&host)?,
                &legacy,
            ))?)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE config_state SET committed_version=2,draft_revision=3,draft=$1 WHERE singleton=true")
            .bind(serde_json::to_value(&draft)?).execute(&mut *tx).await?;
        tx.commit().await?;
        for _ in 0..2 {
            let plane = crate::config::Plane::load(
                &db,
                context.clone(),
                &key,
                Some(Arc::new(Prepared)),
                None,
            )
            .await?;
            assert_eq!(plane.store.load().version, 3);
            assert_eq!(plane.store.load().document, document(&host)?);
            let (revision, value): (i64, serde_json::Value) = sqlx::query_as(
                "SELECT draft_revision,draft FROM config_state WHERE singleton=true",
            )
            .fetch_one(&db)
            .await?;
            upgrade_edge(&mut draft, &origin)?;
            upgrade_admission(&mut draft, &origin)?;
            assert_eq!(revision, 4);
            assert_eq!(serde_json::from_value::<Document>(value)?, draft);
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM admin_audit WHERE action='config.admin_axum_upgrade'"
                )
                .fetch_one(&db)
                .await?,
                1
            );
            drop(plane);
        }
        // Also cover the common case: current Axum upstream but legacy quota.
        // Do not lose unrelated draft changes or mutate immutable old versions.
        let mut legacy = document(&host)?;
        legacy.routes[0].admission = openwaf_config::resources::Admission::legacy_default();
        draft.routes[0].admission = openwaf_config::resources::Admission::legacy_default();
        let mut tx = db.begin().await?;
        ensure!(
            sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES(4,$1,'{}')")
                .bind(serde_json::to_value(&legacy)?)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1
        );
        ensure!(sqlx::query("UPDATE config_state SET committed_version=4,draft_revision=5,draft=$1 WHERE singleton=true")
            .bind(serde_json::to_value(&draft)?).execute(&mut *tx).await?.rows_affected() == 1);
        tx.commit().await?;
        upgrade_admission(&mut draft, &origin)?;
        for _ in 0..2 {
            let plane = crate::config::Plane::load(
                &db,
                context.clone(),
                &key,
                Some(Arc::new(Prepared)),
                None,
            )
            .await?;
            assert_eq!(plane.store.load().version, 5);
            assert_eq!(plane.store.load().document, document(&host)?);
            let (revision, value): (i64, serde_json::Value) = sqlx::query_as(
                "SELECT draft_revision,draft FROM config_state WHERE singleton=true",
            )
            .fetch_one(&db)
            .await?;
            assert_eq!(revision, 6);
            assert_eq!(serde_json::from_value::<Document>(value)?, draft);
            let prior: serde_json::Value =
                sqlx::query_scalar("SELECT document FROM config_versions WHERE version=4")
                    .fetch_one(&db)
                    .await?;
            assert_eq!(serde_json::from_value::<Document>(prior)?, legacy);
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM admin_audit WHERE action='config.admin_admission_upgrade'"
                )
                .fetch_one(&db)
                .await?,
                1
            );
            drop(plane);
        }
        // General websites: omitted/explicit former defaults migrate together;
        // a deliberately smaller quota and unrelated draft edits stay intact.
        let mut legacy = document(&host)?;
        let mut backend = legacy.upstreams[0].clone();
        backend.id = "website-backend".into();
        backend.endpoints[0].address = "192.0.2.20:8080".parse()?;
        legacy.upstreams.push(backend);
        for id in ["implicit", "explicit", "custom"] {
            let mut route = legacy.routes[0].clone();
            route.id = id.into();
            route.hostname = format!("{id}.example.com");
            route.upstream = "website-backend".into();
            route.admission = openwaf_config::resources::Admission::legacy_default();
            if id == "custom" {
                route.admission.per_client = 4;
            }
            legacy.routes.push(route);
        }
        let mut old_value = serde_json::to_value(&legacy)?;
        old_value["routes"][1]
            .as_object_mut()
            .context("route object")?
            .remove("admission");
        draft = legacy.clone();
        let mut extra = draft.upstreams[1].clone();
        extra.id = "saved-draft-edit".into();
        draft.upstreams.push(extra);
        let mut draft_value = serde_json::to_value(&draft)?;
        draft_value["routes"][1]
            .as_object_mut()
            .context("draft route")?
            .remove("admission");
        let mut tx = db.begin().await?;
        ensure!(
            sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES(6,$1,'{}')")
                .bind(&old_value)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1
        );
        ensure!(sqlx::query("UPDATE config_state SET committed_version=6,draft_revision=7,draft=$1,admission_defaults_upgraded=false WHERE singleton=true")
            .bind(draft_value).execute(&mut *tx).await?.rows_affected() == 1);
        tx.commit().await?;
        let mut expected = legacy.clone();
        openwaf_config::resources::upgrade_defaults(&mut expected);
        openwaf_config::resources::upgrade_defaults(&mut draft);
        for _ in 0..2 {
            let plane = crate::config::Plane::load(
                &db,
                context.clone(),
                &key,
                Some(Arc::new(Prepared)),
                None,
            )
            .await?;
            assert_eq!(plane.store.load().version, 7);
            assert_eq!(plane.store.load().document, expected);
            let (revision, value): (i64, serde_json::Value) = sqlx::query_as(
                "SELECT draft_revision,draft FROM config_state WHERE singleton=true",
            )
            .fetch_one(&db)
            .await?;
            assert_eq!(revision, 8);
            assert_eq!(openwaf_config::resources::persisted_document(value)?, draft);
            let prior: serde_json::Value =
                sqlx::query_scalar("SELECT document FROM config_versions WHERE version=6")
                    .fetch_one(&db)
                    .await?;
            assert_eq!(prior, old_value);
            assert_eq!(
                openwaf_config::resources::persisted_document(prior)?,
                legacy
            );
            let current: serde_json::Value =
                sqlx::query_scalar("SELECT document FROM config_versions WHERE version=7")
                    .fetch_one(&db)
                    .await?;
            assert_eq!(current["routes"][1]["admission"]["per_client"], 32);
            assert_eq!(current["routes"][3]["admission"]["per_client"], 4);
            let difference: serde_json::Value =
                sqlx::query_scalar("SELECT diff FROM config_versions WHERE version=7")
                    .fetch_one(&db)
                    .await?;
            assert_eq!(
                difference["routes"]["changed"],
                serde_json::json!(["explicit", "implicit"])
            );
            assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM admin_audit WHERE action='config.admission_defaults_upgrade'").fetch_one(&db).await?, 1);
            drop(plane);
        }
        // After migration, choosing the former quota explicitly (or rolling
        // back to it) is valid and must survive subsequent startups.
        let pinned_legacy = serde_json::to_value(&legacy)?;
        let mut tx = db.begin().await?;
        ensure!(
            sqlx::query("INSERT INTO config_versions(version,document,diff) VALUES(8,$1,'{}')")
                .bind(&pinned_legacy)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1
        );
        ensure!(sqlx::query("UPDATE config_state SET committed_version=8,draft_revision=9,draft=$1 WHERE singleton=true")
            .bind(&pinned_legacy).execute(&mut *tx).await?.rows_affected() == 1);
        tx.commit().await?;
        let plane =
            crate::config::Plane::load(&db, context.clone(), &key, Some(Arc::new(Prepared)), None)
                .await?;
        assert_eq!(plane.store.load().version, 8);
        assert_eq!(plane.store.load().document, legacy);
        drop(plane);
        let unavailable = App::new(db.clone(), key.clone(), origin).await?;
        db.close().await;
        let response = router(unavailable)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/auth/setup")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }
}
