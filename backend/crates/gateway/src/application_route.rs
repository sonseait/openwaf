//! Static responses use the same admission/security/WAF path as proxied requests.
use super::*;

impl Gateway {
    pub(crate) async fn application_response(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
    ) -> pingora::Result<bool> {
        let Some((snapshot, index)) = ctx.snapshot.as_ref().zip(ctx.route) else {
            return Ok(false);
        };
        let Some(target) = snapshot.document.routes[index].application.clone() else {
            return Ok(false);
        };
        ctx.decision_trace.begin("application");
        ctx.security_layer = "application";
        if target
            .preview_expires_at_unix_ms
            .is_some_and(|v| v <= openwaf_applications::now_ms())
        {
            return self.reject(session, ctx, 404).await;
        }
        let prepared = snapshot
            .applications
            .as_ref()
            .and_then(|v| v.downcast_ref::<openwaf_applications::Prepared>());
        let Some((store, release)) = prepared.and_then(|p| {
            p.routes
                .get(index)
                .and_then(|r| r.clone())
                .map(|r| (p.store.clone(), r))
        }) else {
            return self.reject(session, ctx, 503).await;
        };
        if session.req_header().method != "GET" && session.req_header().method != "HEAD" {
            ctx.checked("application", "method_not_allowed");
            let mut header = pingora::http::ResponseHeader::build(405, Some(8))?;
            header.insert_header("allow", "GET, HEAD")?;
            header.insert_header("content-length", "0")?;
            self.response_headers(&mut header, ctx)?;
            session.as_mut().set_keepalive(None);
            ctx.record_response_header(&header, true);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
        let path = ctx
            .rewritten_uri
            .as_ref()
            .unwrap_or(&session.req_header().uri)
            .path()
            .to_owned();
        if openwaf_applications::request_path(&path).is_err() {
            return self.reject(session, ctx, 400).await;
        }
        let result = store
            .response(
                release,
                target.mode,
                &path,
                session.req_header().method.as_str(),
                &session.req_header().headers,
            )
            .await;
        let mut reply = match result {
            Ok(reply) => reply,
            Err(_) => {
                ctx.failure = Some("application_unavailable");
                return self.reject(session, ctx, 503).await;
            }
        };
        if reply.status == 404 {
            return self.reject(session, ctx, 404).await;
        }
        let mut header = pingora::http::ResponseHeader::build(reply.status, Some(12))?;
        for (name, value) in &reply.headers {
            if *name == "location" {
                let query = ctx
                    .rewritten_uri
                    .as_ref()
                    .unwrap_or(&session.req_header().uri)
                    .query();
                let location = match query {
                    Some(query) => format!("{value}?{query}"),
                    None => value.clone(),
                };
                header.insert_header(*name, location)?;
            } else {
                header.insert_header(*name, value)?;
            }
        }
        if reply.status != 304 {
            header.insert_header("content-length", reply.length.to_string())?;
        }
        self.response_headers(&mut header, ctx)?;
        if target.preview_expires_at_unix_ms.is_some() {
            header.insert_header("x-robots-tag", "noindex, nofollow, noarchive")?;
            header.insert_header("cache-control", "no-store")?;
        }
        ctx.checked("application", "served");
        let no_body =
            session.req_header().method == "HEAD" || reply.file.is_none() || reply.length == 0;
        if !session.as_mut().is_body_done() {
            session.as_mut().set_keepalive(None);
        }
        ctx.record_response_header(&header, no_body);
        session
            .write_response_header(Box::new(header), no_body)
            .await?;
        if no_body {
            return Ok(true);
        }
        let Some(file) = reply.file.as_mut() else {
            return Ok(true);
        };
        let mut remaining = reply.length;
        let mut offset = reply.offset;
        while remaining > 0 {
            let wanted = remaining.min(65536) as usize;
            let buffer = file
                .read_at(offset, wanted)
                .await
                .map_err(|_| pingora::Error::new(pingora::ErrorType::InternalError))?;
            let n = buffer.len();
            if n == 0 {
                return Err(pingora::Error::new(pingora::ErrorType::InternalError));
            }
            remaining -= n as u64;
            offset += n as u64;
            ctx.record_response_chunk(&buffer, remaining == 0);
            session
                .write_response_body(Some(bytes::Bytes::from(buffer)), remaining == 0)
                .await?;
        }
        Ok(true)
    }
}
