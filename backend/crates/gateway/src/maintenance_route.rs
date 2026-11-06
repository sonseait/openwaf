//! Return local route maintenance without consulting the application or auth service.
use crate::{Gateway, RequestContext};
use pingora::prelude::*;
impl Gateway {
    pub(crate) async fn route_maintenance(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        ctx.decision_trace.begin("route_maintenance");
        let Some((snapshot, index)) = ctx.snapshot.clone().zip(ctx.route) else {
            ctx.checked("route_maintenance", "disabled");
            return Ok(false);
        };
        let Some(policy) = &snapshot.document.routes[index].maintenance else {
            ctx.checked("route_maintenance", "disabled");
            return Ok(false);
        };
        ctx.security_layer = "route_maintenance";
        ctx.failure = Some("route_maintenance");
        ctx.checked("route_maintenance", "enabled");
        let headers = &session.req_header().headers;
        let json = headers.contains_key("upgrade")
            || headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("application/json") && !v.contains("text/html"));
        let body = if json {
            serde_json::json!({"status":503,"reason":"route_maintenance","message":policy.message,"retry_after_seconds":policy.retry_after_seconds,"request_id":ctx.request_id}).to_string()
        } else {
            openwaf_gateway::maintenance::html(
                &policy.message,
                policy.retry_after_seconds,
                &ctx.request_id,
                ctx.client.map(|client| client.ip()),
                &ctx.location,
            )
        };
        let mut header = pingora::http::ResponseHeader::build(503, Some(12))?;
        self.response_headers(&mut header, ctx)?;
        header.insert_header(
            "content-type",
            if json {
                "application/json"
            } else {
                "text/html; charset=utf-8"
            },
        )?;
        header.insert_header("cache-control", "private, no-store")?;
        header.insert_header("retry-after", policy.retry_after_seconds.to_string())?;
        header.insert_header("x-openwaf-maintenance", "route")?;
        header.insert_header("x-content-type-options", "nosniff")?;
        header.insert_header("x-frame-options", "DENY")?;
        header.insert_header("referrer-policy", "no-referrer")?;
        header.insert_header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")?;
        header.insert_header("content-length", body.len().to_string())?;
        session.as_mut().set_keepalive(None);
        let head = session.req_header().method == "HEAD";
        ctx.record_response_header(&header, head);
        session
            .write_response_header(Box::new(header), head)
            .await?;
        if !head {
            ctx.record_response_chunk(body.as_bytes(), true);
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
        }
        Ok(true)
    }
}
