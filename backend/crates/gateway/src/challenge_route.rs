//! Local browser challenge before WAF/application work. No request body replay,
//! no upstream on challenge responses, no network/database calls for verification.
use crate::{Gateway, RequestContext};
use openwaf_gateway::challenge::{self, Binding, Proof};
use openwaf_security::traffic::Verdict;
use pingora::prelude::*;

impl Gateway {
    pub(crate) async fn browser_challenge(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        ctx.decision_trace.begin("challenge");
        let Some((snapshot, index)) = ctx.snapshot.clone().zip(ctx.route) else {
            ctx.checked("challenge", "disabled");
            return Ok(false);
        };
        let route = &snapshot.document.routes[index];
        let global = snapshot.document.global_rules.challenge;
        let local = route.access.challenge;
        if global.is_none() && local.is_none() {
            ctx.checked("challenge", "disabled");
            return Ok(false);
        }
        ctx.security_layer = "challenge";
        // The gateway must terminate HTTPS itself. Forwarded headers do not
        // authorize Secure cookies. Existing HTTP-only redirects may lead to TLS.
        if !self.tls {
            if route.redirect.as_ref().is_some_and(|r| r.http_only) {
                ctx.checked("challenge", "redirected_to_https");
                return self.redirect(session, ctx).await;
            }
            ctx.failure = Some("challenge_requires_https");
            return self.reject(session, ctx, 503).await;
        }
        let Some(client) = ctx.client else {
            return self.reject(session, ctx, 503).await;
        };
        let target = session
            .req_header()
            .uri
            .path_and_query()
            .map_or("/", |v| v.as_str())
            .to_owned();
        let authority = session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(&ctx.host)
            .to_ascii_lowercase();
        let binding = Binding {
            authority: &authority,
            version: snapshot.version,
            ip: client.ip(),
            route: &route.id,
            target: &target,
            global,
            local,
        };
        let now = openwaf_telemetry::now_ms();
        let verifying = session.req_header().headers.contains_key(challenge::HEADER);
        if !verifying
            && self
                .challenge_gate
                .cleared(&binding, &session.req_header().headers, now)
        {
            ctx.signal("challenge", "clearance_valid", "observed");
            ctx.checked("challenge", "cleared");
            return Ok(false);
        }
        if !verifying && let Some(request) = &mut ctx.telemetry {
            request.blocked();
        }
        match self.challenge_gate.limit(client.ip()) {
            Verdict::Allow => {}
            Verdict::Limited(retry) => {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                ctx.failure = Some("challenge_rate_limit");
                return self.reply(session, ctx, 429, Some(retry)).await;
            }
            _ => {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                ctx.failure = Some("challenge_capacity");
                return self.reject(session, ctx, 503).await;
            }
        }
        // Never solve/replay POST, upload, WS or SSE requests. A browser must
        // first navigate to a GET URL covered by this route to obtain clearance.
        let headers = &session.req_header().headers;
        let bodyless = !headers.contains_key("transfer-encoding")
            && !headers.contains_key("expect")
            && headers.get("content-length").is_none_or(|v| v == "0");
        if session.req_header().method != "GET" || !bodyless {
            if let Some(request) = &mut ctx.telemetry {
                request.blocked();
            }
            ctx.failure = Some("challenge_required");
            return self.reject(session, ctx, 403).await;
        }
        if verifying {
            let input = (headers.get_all(challenge::HEADER).iter().count() == 1)
                .then(|| headers.get(challenge::HEADER).filter(|v| v.len() <= 1024))
                .flatten()
                .and_then(|v| serde_json::from_slice::<Proof>(v.as_bytes()).ok());
            let issued = input
                .as_ref()
                .and_then(|p| self.challenge_gate.verify(&binding, headers, p, now));
            let Some(issued) = issued else {
                if let Some(request) = &mut ctx.telemetry {
                    request.blocked();
                }
                ctx.failure = Some("challenge_invalid");
                return self.reject(session, ctx, 403).await;
            };
            let cookies = self
                .challenge_gate
                .success(&binding, issued, now)
                .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
            ctx.failure = Some("challenge_solved");
            ctx.signal("challenge", "proof_verified", "observed");
            ctx.checked("challenge", "solved");
            return self
                .challenge_reply(session, ctx, 204, String::new(), cookies, None)
                .await;
        }
        if !challenge::wants_page(headers) {
            ctx.failure = Some("challenge_required");
            return self.reject(session, ctx, 403).await;
        }
        let page = self
            .challenge_gate
            .page(&binding, now)
            .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
        ctx.failure = Some("challenge_required");
        ctx.signal("challenge", "proof_required", "enforced_block");
        ctx.checked("challenge", "required");
        self.challenge_reply(
            session,
            ctx,
            403,
            page.body,
            vec![page.cookie],
            Some(page.nonce),
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn challenge_reply(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        status: u16,
        body: String,
        cookies: Vec<String>,
        nonce: Option<String>,
    ) -> pingora::Result<bool> {
        session.as_mut().set_keepalive(None);
        let mut header = pingora::http::ResponseHeader::build(status, Some(14))?;
        self.response_headers(&mut header, ctx)?;
        header.insert_header("cache-control", "private, no-store")?;
        header.insert_header(
            "vary",
            "Cookie, Accept, Sec-Fetch-Dest, X-OpenWAF-Challenge",
        )?;
        header.insert_header(
            "x-openwaf-challenge",
            if status == 204 { "solved" } else { "required" },
        )?;
        header.insert_header("content-type", "text/html; charset=utf-8")?;
        header.insert_header("referrer-policy", "same-origin")?;
        header.insert_header("x-frame-options", "DENY")?;
        header.insert_header("x-content-type-options", "nosniff")?;
        if let Some(nonce) = nonce {
            header.insert_header("content-security-policy", format!("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"))?;
        } else {
            header.insert_header(
                "content-security-policy",
                "default-src 'none'; frame-ancestors 'none'",
            )?;
        }
        for cookie in cookies {
            header.append_header("set-cookie", cookie)?;
        }
        if status != 204 {
            header.insert_header("content-length", body.len().to_string())?;
        }
        ctx.record_response_header(&header, body.is_empty());
        session
            .write_response_header(Box::new(header), body.is_empty())
            .await?;
        if !body.is_empty() {
            ctx.record_response_chunk(body.as_bytes(), true);
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
        }
        Ok(true)
    }
}
