//! Pingora adapter for local authentication; no login body is sent upstream or
//! captured in telemetry. Its own strict form contract replaces application MIME
//! policies on the reserved local endpoint; ACL/admission/CrowdSec still apply.
use crate::{Gateway, RequestContext};
use openwaf_gateway::password_protect::{self as auth, Reply};
use pingora::prelude::*;
use std::time::Duration;

impl Gateway {
    pub(crate) async fn password_check(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        ctx.decision_trace.begin("password_protect");
        let Some((snapshot, index)) = ctx.snapshot.clone().zip(ctx.route) else {
            ctx.checked("password_protect", "disabled");
            return Ok(false);
        };
        let route = &snapshot.document.routes[index];
        let scope = format!("{}@{}", ctx.host, snapshot.version);
        if route.password_protect.is_none() {
            ctx.checked("password_protect", "disabled");
            return Ok(false);
        }
        // HTTP-only redirects cannot forward application traffic and lead to TLS.
        if !self.tls && route.redirect.as_ref().is_some_and(|r| r.http_only) {
            ctx.checked("password_protect", "redirected_to_https");
            return self.redirect(session, ctx).await;
        }
        ctx.security_layer = "password_protect";
        if !self.tls {
            ctx.failure = Some("password_requires_https");
            return self.reject(session, ctx, 503).await;
        }
        if self.password_gate.authenticated(
            &scope,
            route,
            &session.req_header().headers,
            openwaf_telemetry::now_ms(),
        ) {
            ctx.checked("password_protect", "authenticated");
            return Ok(false);
        }
        ctx.failure = Some("password_required");
        if let Some(request) = &mut ctx.telemetry {
            request.blocked();
        }
        let html = session
            .req_header()
            .headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));
        if !html {
            return self.reject(session, ctx, 401).await;
        }
        let path = openwaf_config::canonical_path(session.req_header().uri.path())
            .map_err(|_| pingora::Error::new(pingora::ErrorType::HTTPStatus(400)))?;
        let reply = self
            .password_gate
            .page(&scope, route, &path, openwaf_telemetry::now_ms(), false)
            .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
        ctx.decision_trace.stop("denied");
        self.password_reply(session, ctx, reply).await
    }
    pub(crate) async fn password_login(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        ctx.decision_trace.begin("password_protect");
        ctx.security_layer = "password_protect";
        let Some((snapshot, index)) = ctx.snapshot.clone().zip(ctx.route) else {
            return self.reject(session, ctx, 404).await;
        };
        let route = &snapshot.document.routes[index];
        let scope = format!("{}@{}", ctx.host, snapshot.version);
        if !self.tls {
            ctx.failure = Some("password_requires_https");
            return self.reject(session, ctx, 503).await;
        }
        if session.req_header().method != "POST" {
            return self.reject(session, ctx, 405).await;
        }
        let Some(client) = ctx.client else {
            return self.reject(session, ctx, 503).await;
        };
        if let Err(status) = self.password_gate.limit(client.ip()) {
            ctx.failure = Some("password_login_rate_limit");
            return self
                .reply(session, ctx, status, (status == 429).then_some(60))
                .await;
        }
        let headers = &session.req_header().headers;
        if headers.get_all("content-type").iter().count() != 1
            || !headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v == "application/x-www-form-urlencoded")
            || headers.contains_key("content-encoding")
        {
            return self.reject(session, ctx, 415).await;
        }
        if headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|v| v > 8192)
        {
            return self.reject(session, ctx, 413).await;
        }
        let read = async {
            let mut body = zeroize::Zeroizing::new(Vec::new());
            while let Some(chunk) = session.read_request_body().await? {
                if body.len() + chunk.len() > 8192 {
                    return Err(pingora::Error::new(pingora::ErrorType::HTTPStatus(413)));
                }
                body.extend_from_slice(&chunk);
            }
            Ok::<_, Box<pingora::Error>>(body)
        };
        let body = match tokio::time::timeout(Duration::from_secs(3), read).await {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => {
                return self
                    .reject(
                        session,
                        ctx,
                        if error.etype() == &pingora::ErrorType::HTTPStatus(413) {
                            413
                        } else {
                            400
                        },
                    )
                    .await;
            }
            Err(_) => return self.reject(session, ctx, 408).await,
        };
        let Ok(input) = serde_urlencoded::from_bytes::<auth::Login>(&body) else {
            return self.reject(session, ctx, 422).await;
        };
        let path = input.return_path.clone();
        if openwaf_config::canonical_path(&path).is_err()
            || path.starts_with(auth::PREFIX)
            || !route.path_matches(&path)
        {
            return self.reject(session, ctx, 422).await;
        }
        let authority = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(&ctx.host);
        if !self.password_gate.csrf_valid(
            &scope,
            authority,
            route,
            &session.req_header().headers,
            &input,
            openwaf_telemetry::now_ms(),
        ) {
            ctx.failure = Some("password_csrf_denied");
            if let Some(request) = &mut ctx.telemetry {
                request.blocked();
            }
            return self.reject(session, ctx, 403).await;
        }
        let Some(verifier) = snapshot
            .password_verifiers
            .get(index)
            .and_then(Clone::clone)
        else {
            return self.reject(session, ctx, 503).await;
        };
        let verified = match self.password_gate.verify(input, verifier).await {
            Ok(value) => value,
            Err(status) => return self.reject(session, ctx, status).await,
        };
        let now = openwaf_telemetry::now_ms();
        let reply = if verified {
            ctx.checked("password_protect", "login_succeeded");
            ctx.failure = Some("password_login_succeeded");
            self.password_gate.success(&scope, route, &path, now)
        } else {
            ctx.failure = Some("password_login_denied");
            if let Some(r) = &mut ctx.telemetry {
                r.blocked();
            }
            self.password_gate.page(&scope, route, &path, now, true)
        }
        .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
        ctx.decision_trace.stop("denied");
        self.password_reply(session, ctx, reply).await
    }
    async fn password_reply(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        reply: Reply,
    ) -> pingora::Result<bool> {
        session.as_mut().set_keepalive(None);
        let mut header = pingora::http::ResponseHeader::build(reply.status, Some(12))?;
        self.response_headers(&mut header, ctx)?;
        header.insert_header("content-type", "text/html; charset=utf-8")?;
        header.insert_header("cache-control", "private, no-store")?;
        header.insert_header("content-security-policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")?;
        header.insert_header("x-frame-options", "DENY")?;
        header.insert_header("x-content-type-options", "nosniff")?;
        // no-referrer makes browsers send Origin: null on form POSTs, which
        // correctly fail our strict CSRF check. Preserve same-origin submissions
        // without disclosing the protected path to another origin.
        header.insert_header("referrer-policy", "same-origin")?;
        header.insert_header("content-length", reply.body.len().to_string())?;
        for cookie in reply.cookies {
            header.append_header("set-cookie", cookie)?;
        }
        if let Some(location) = reply.location {
            header.insert_header("location", location)?;
        }
        let end = reply.body.is_empty() || session.req_header().method == "HEAD";
        ctx.record_response_header(&header, end);
        session.write_response_header(Box::new(header), end).await?;
        if !end {
            ctx.record_response_chunk(reply.body.as_bytes(), true);
            session
                .write_response_body(Some(bytes::Bytes::from(reply.body)), true)
                .await?;
        }
        Ok(true)
    }
}
