//! Static dashboard files from an immutable image directory, outside the proxy hot path.
use crate::*;
use axum::{body::Body, extract::Request};
use percent_encoding::percent_decode_str;
use std::path::{Path as FilePath, PathBuf};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

pub(super) struct Service {
    root: Option<PathBuf>,
}
impl Service {
    pub(super) async fn from_env() -> Result<Self> {
        let root = match std::env::var_os("OPENWAF_ADMIN_UI_ROOT") {
            Some(path) => {
                let root = tokio::fs::canonicalize(path)
                    .await
                    .context("dashboard directory unavailable")?;
                ensure!(
                    tokio::fs::metadata(root.join("index.html"))
                        .await
                        .context("dashboard index unavailable")?
                        .is_file(),
                    "dashboard index must be a file"
                );
                Some(root)
            }
            None => None, // Local API-only development remains supported.
        };
        Ok(Self { root })
    }

    async fn response(&self, request: Request) -> Response {
        let Some(root) = &self.root else {
            return Error::NotFound.into_response();
        };
        let Ok(path) = percent_decode_str(request.uri().path()).decode_utf8() else {
            return Error::NotFound.into_response();
        };
        // API typos, internal paths, hidden files and traversal must never become HTML.
        if path == "/api"
            || path.starts_with("/api/")
            || path == "/metrics"
            || path.starts_with("/metrics/")
            || path.contains('\\')
            || path.contains('\0')
            || path.split('/').any(|part| part.starts_with('.'))
        {
            return Error::NotFound.into_response();
        }
        if !matches!(*request.method(), Method::GET | Method::HEAD) {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let navigation = path == "/"
            || (FilePath::new(path.as_ref()).extension().is_none()
                && !path.starts_with("/assets/")
                && request
                    .headers()
                    .get(header::ACCEPT)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| {
                        v.split(',')
                            .any(|v| v.trim().split(';').next() == Some("text/html"))
                    }));
        let (parts, body) = request.into_parts();
        let result = ServeDir::new(root)
            .oneshot(Request::from_parts(parts.clone(), body))
            .await;
        let response = match result {
            Ok(response) if response.status() == StatusCode::NOT_FOUND && navigation => {
                ServeFile::new(root.join("index.html"))
                    .oneshot(Request::from_parts(parts, Body::empty()))
                    .await
            }
            result => result,
        };
        match response {
            Ok(response) => response.map(Body::new),
            Err(error) => match error {}, // Infallible; IO errors are safe HTTP statuses.
        }
    }
}

pub(super) async fn serve(State(app): State<Arc<App>>, request: Request) -> Response {
    app.dashboard.response(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn static_files_navigation_and_api_boundaries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        tokio::fs::write(temp.path().join("index.html"), "<html>dashboard</html>").await?;
        tokio::fs::create_dir(temp.path().join("assets")).await?;
        tokio::fs::write(temp.path().join("assets/app.js"), "export {};").await?;
        tokio::fs::write(temp.path().join(".env"), "never public").await?;
        let service = Service {
            root: Some(temp.path().to_owned()),
        };
        for path in ["/", "/configuration", "/applications/detail"] {
            let response = service
                .response(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, "text/html")
                        .body(Body::empty())?,
                )
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                to_bytes(response.into_body(), 1024).await?.as_ref(),
                b"<html>dashboard</html>"
            );
        }
        let response = service
            .response(
                Request::builder()
                    .uri("/assets/app.js")
                    .body(Body::empty())?,
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_TYPE]
                .to_str()?
                .contains("javascript")
        );
        let head = service
            .response(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/")
                    .body(Body::empty())?,
            )
            .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert!(to_bytes(head.into_body(), 1024).await?.is_empty());
        for path in [
            "/api",
            "/api/missing",
            "/%61pi/missing",
            "/metrics",
            "/metrics/unknown",
            "/.env",
            "/%2eenv",
            "/../secret",
            "/%2e%2e/secret",
            "/assets/missing.js",
            "/assets/missing",
            "/missing.css",
        ] {
            let response = service
                .response(
                    Request::builder()
                        .uri(path)
                        .header(header::ACCEPT, "text/html")
                        .body(Body::empty())?,
                )
                .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        let response = service
            .response(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .body(Body::empty())?,
            )
            .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }
}
