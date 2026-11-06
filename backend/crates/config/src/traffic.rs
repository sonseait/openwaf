//! Opt-in traffic contracts. Templates are copied by the editor, never expanded on load.
use crate::{Document, Route, Timeouts, Validation, retry, waf};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ApiCrud,
    Upload,
    Sse,
    Websocket,
    Media,
    PaymentWebhook,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub kind: Kind,
    pub version: u16,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Api,
    Upload,
    Stream,
    Critical,
}
impl Class {
    pub fn index(self) -> usize {
        match self {
            Self::Api => 0,
            Self::Upload => 1,
            Self::Stream => 2,
            Self::Critical => 3,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Content {
    /// Exact lower-case media types. Parameters are parsed, not used for matching.
    pub media_types: Vec<String>,
    /// A nonempty or chunked body must carry Content-Type. Empty requests may omit it.
    pub require_type_for_body: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Template {
    pub profile: Profile,
    pub methods: Vec<String>,
    pub content: Content,
    pub body: retry::Body,
    pub timeouts: Timeouts,
    pub retry: retry::Policy,
    pub admission_class: Class,
    pub waf: waf::Policy,
}
pub fn templates() -> Vec<Template> {
    [
        Kind::ApiCrud,
        Kind::Upload,
        Kind::Sse,
        Kind::Websocket,
        Kind::Media,
        Kind::PaymentWebhook,
    ]
    .into_iter()
    .map(|kind| {
        let streaming = matches!(
            kind,
            Kind::Upload | Kind::Sse | Kind::Websocket | Kind::Media
        );
        Template {
            profile: Profile { kind, version: 1 },
            methods: match kind {
                Kind::ApiCrud => vec!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                Kind::Upload => vec!["POST", "PUT"],
                Kind::PaymentWebhook => vec!["POST"],
                Kind::Sse | Kind::Websocket => vec!["GET"],
                Kind::Media => vec!["GET", "HEAD"],
            }
            .into_iter()
            .map(str::to_owned)
            .collect(),
            content: Content {
                media_types: match kind {
                    Kind::Upload => vec!["application/octet-stream", "multipart/form-data"],
                    Kind::ApiCrud | Kind::PaymentWebhook => vec!["application/json"],
                    _ => vec![],
                }
                .into_iter()
                .map(str::to_owned)
                .collect(),
                require_type_for_body: true,
            },
            body: retry::Body {
                max_body_bytes: if kind == Kind::Upload {
                    536870912
                } else {
                    65536
                },
                inspection: if streaming {
                    retry::Inspection::HeadersQueryOnly
                } else {
                    retry::Inspection::Full
                },
                idle_timeout_ms: 30000,
            },
            timeouts: Timeouts {
                total_ms: if streaming { 1800000 } else { 30000 },
                header_ms: Some(if kind == Kind::Upload { 1800000 } else { 10000 }),
                response_idle_ms: Some(30000),
                tls_ms: Some(3000),
                ..Default::default()
            },
            retry: retry::Policy::default(),
            admission_class: match kind {
                Kind::Upload => Class::Upload,
                Kind::Sse | Kind::Websocket | Kind::Media => Class::Stream,
                Kind::PaymentWebhook => Class::Critical,
                _ => Class::Api,
            },
            waf: waf::Policy::default(),
        }
    })
    .collect()
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
fn media(value: &str) -> bool {
    value.split_once('/').is_some_and(|(a, b)| {
        !a.is_empty()
            && !b.is_empty()
            && a.bytes().all(token)
            && b.bytes().all(token)
            && !value.contains('*')
    })
}
pub fn validate(route: &Route) -> Result<(), Validation> {
    if route.profile.as_ref().is_some_and(|p| p.version == 0)
        || route.profile.is_some()
            && (route.content.is_none()
                || route.body.is_none()
                || route.timeouts.is_none()
                || route.admission_class.is_none()
                || route.waf.is_none()
                || route.methods.is_empty())
    {
        return Err(Validation::Content);
    }
    if let Some(c) = &route.content {
        let unique: BTreeSet<_> = c.media_types.iter().collect();
        if c.media_types.len() > 16
            || unique.len() != c.media_types.len()
            || c.media_types
                .iter()
                .any(|t| t.len() > 127 || !media(t) || *t != t.to_ascii_lowercase())
        {
            return Err(Validation::Content);
        }
        // JSON/form syntax validation is bounded and must precede upstream forwarding.
        if c.media_types
            .iter()
            .any(|t| json(t) || t == "application/x-www-form-urlencoded")
            && route
                .body
                .as_ref()
                .is_some_and(|b| b.inspection != retry::Inspection::Full)
        {
            return Err(Validation::Content);
        }
    }
    if route.timeouts.as_ref().is_some_and(|t| !t.valid()) {
        return Err(Validation::Timeout);
    }
    Ok(())
}
fn json(t: &str) -> bool {
    t == "application/json" || t.starts_with("application/") && t.ends_with("+json")
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Parsed {
    pub multipart: bool,
    pub json: bool,
    pub form: bool,
}
/// Strict bounded MIME parser, including quoted parameters and duplicate detection.
fn parse(value: &str) -> Result<(String, bool), u16> {
    if value.len() > 1024 {
        return Err(400);
    }
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b';' {
        i += 1;
    }
    let typ = value[..i].trim().to_ascii_lowercase();
    if !media(&typ) {
        return Err(400);
    }
    let mut names = BTreeSet::new();
    let mut boundary = false;
    let mut unsupported_charset = false;
    while i < bytes.len() {
        i += 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && token(bytes[i]) {
            i += 1;
        }
        if i == start {
            return Err(400);
        }
        let name = value[start..i].to_ascii_lowercase();
        if !names.insert(name.clone()) || names.len() > 16 {
            return Err(400);
        }
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        if bytes.get(i) != Some(&b'=') {
            return Err(400);
        }
        i += 1;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        let mut size = 0;
        let mut parameter = Vec::new();
        if bytes.get(i) == Some(&b'"') {
            i += 1;
            loop {
                let Some(&b) = bytes.get(i) else {
                    return Err(400);
                };
                i += 1;
                if b == b'"' {
                    break;
                }
                let b = if b == b'\\' {
                    let Some(&next) = bytes.get(i) else {
                        return Err(400);
                    };
                    i += 1;
                    next
                } else {
                    b
                };
                if !(32..=126).contains(&b) {
                    return Err(400);
                }
                parameter.push(b);
                size += 1;
            }
        } else {
            while i < bytes.len() && token(bytes[i]) {
                parameter.push(bytes[i]);
                size += 1;
                i += 1;
            }
        }
        if size == 0 {
            return Err(400);
        }
        if name == "charset"
            && json(&typ)
            && !parameter.eq_ignore_ascii_case(b"utf-8")
            && !parameter.eq_ignore_ascii_case(b"utf8")
        {
            unsupported_charset = true;
        }
        if name == "boundary" {
            if size > 70
                || parameter.last() == Some(&b' ')
                || !parameter
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(b))
            {
                return Err(400);
            }
            boundary = true;
        }
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] != b';' {
            return Err(400);
        }
    }
    if unsupported_charset {
        return Err(415);
    }
    Ok((typ, boundary))
}
/// Pingora reconciles TE/CL before the application hook. Inspect original H1
/// field names as well; borrow bytes only, never retain or emit raw headers.
pub fn raw_framing(raw: &[u8]) -> Result<(), u16> {
    let mut lengths = 0;
    let mut transfers = 0;
    for line in raw.split(|b| *b == b'\n').skip(1) {
        if line == b"\r" || line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            return Err(400);
        };
        let name = &line[..colon];
        lengths += usize::from(name.eq_ignore_ascii_case(b"content-length"));
        transfers += usize::from(name.eq_ignore_ascii_case(b"transfer-encoding"));
    }
    if lengths > 1 || transfers > 1 || lengths != 0 && transfers != 0 {
        Err(400)
    } else {
        Ok(())
    }
}
/// Reject ambiguous framing before selecting a body reader or contacting upstream.
pub fn framing(headers: &http::HeaderMap) -> Result<(), u16> {
    let lengths: Vec<_> = headers.get_all("content-length").iter().collect();
    let transfers: Vec<_> = headers.get_all("transfer-encoding").iter().collect();
    if lengths.len() > 1 || transfers.len() > 1 || !lengths.is_empty() && !transfers.is_empty() {
        return Err(400);
    }
    if let Some(length) = lengths.first() {
        let value = length.to_str().map_err(|_| 400u16)?;
        if value.is_empty()
            || !value.bytes().all(|b| b.is_ascii_digit())
            || value.parse::<u64>().is_err()
        {
            return Err(400);
        }
    }
    if let Some(transfer) = transfers.first()
        && !transfer.as_bytes().eq_ignore_ascii_case(b"chunked")
    {
        return Err(400);
    }
    Ok(())
}
/// Status-only failures never retain attacker-controlled header values.
pub fn headers(
    contract: &Content,
    headers: &http::HeaderMap,
    has_body: bool,
) -> Result<Parsed, u16> {
    let mut encodings = headers.get_all("content-encoding").iter();
    if let Some(value) = encodings.next() {
        if encodings.next().is_some() {
            return Err(400);
        }
        let value = value.to_str().map_err(|_| 400u16)?.trim();
        if value
            .split(',')
            .any(|coding| coding.trim().is_empty() || !coding.trim().bytes().all(token))
        {
            return Err(400);
        }
        if !value.eq_ignore_ascii_case("identity") {
            return Err(415);
        }
    }
    let mut types = headers.get_all("content-type").iter();
    let Some(value) = types.next() else {
        return if has_body && contract.require_type_for_body {
            Err(415)
        } else {
            Ok(Parsed::default())
        };
    };
    if types.next().is_some() {
        return Err(400);
    }
    let (typ, boundary) = parse(value.to_str().map_err(|_| 400u16)?)?;
    let multipart = typ.starts_with("multipart/");
    if multipart && !boundary {
        return Err(400);
    }
    if !contract.media_types.contains(&typ) {
        return Err(415);
    }
    Ok(Parsed {
        multipart,
        json: json(&typ),
        form: typ == "application/x-www-form-urlencoded",
    })
}
pub fn body(parsed: Parsed, body: &[u8]) -> Result<(), u16> {
    if parsed.json && serde_json::from_slice::<serde_json::Value>(body).is_err() {
        return Err(400);
    }
    if parsed.form
        && !body.is_empty()
        && !body.split(|b| *b == b'&').all(|pair| {
            pair.contains(&b'=')
                && pair.iter().enumerate().all(|(i, b)| {
                    *b != b'%'
                        || pair.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                            && pair.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
                })
        })
    {
        return Err(400);
    }
    Ok(())
}
#[derive(Serialize)]
pub struct Diagnostic {
    pub path: String,
    pub route_id: String,
    pub code: &'static str,
    pub message: &'static str,
}
pub fn diagnostics(
    document: &Document,
    operations: &crate::operations::Operations,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for (i, r) in document.routes.iter().enumerate() {
        let mut warn = |field: &str, code, message| {
            out.push(Diagnostic {
                path: format!("routes.{i}.{field}"),
                route_id: r.id.clone(),
                code,
                message,
            })
        };
        if r.password_protect.is_none()
            && document.routes.iter().any(|parent| {
                parent.password_protect.is_some()
                    && parent.path_match == crate::PathMatch::Prefix
                    && parent.id != r.id
                    && parent.host_matches(&r.hostname)
                    && parent.path_matches(&r.path)
            })
        {
            warn(
                "password_protect",
                "password_prefix_override",
                "This route can override a password-protected prefix. Configure password protection here too if the whole application must be protected.",
            );
        }
        if r.content
            .as_ref()
            .is_none_or(|c| c.media_types.iter().any(|t| t.starts_with("multipart/")))
        {
            warn(
                "content",
                "multipart_body_skipped",
                "Multipart bodies bypass body parsing; restrict media types or use a separate upload route.",
            );
        }
        if r.body
            .as_ref()
            .is_some_and(|b| b.inspection == retry::Inspection::Full && b.max_body_bytes > 65536)
        {
            warn(
                "body.max_body_bytes",
                "full_body_cap",
                "Full inspection is capped at 64 KiB; lower the cap or explicitly choose headers-query-only.",
            );
        }
        if r.retry.mode != retry::Mode::Disabled {
            warn(
                "retry.mode",
                "backend_dedup",
                "Retries can repeat backend work; verify backend deduplication and scope before enabling retries.",
            );
        }
        let stream = r
            .body
            .as_ref()
            .is_some_and(|b| b.inspection == retry::Inspection::HeadersQueryOnly);
        let total = r
            .timeouts
            .as_ref()
            .map(|t| t.total_ms)
            .or_else(|| {
                document
                    .upstreams
                    .iter()
                    .find(|u| u.id == r.upstream)
                    .map(|u| u.timeouts.total_ms)
            })
            .unwrap_or(30000);
        let total = total.min(r.retry.total_timeout_ms.unwrap_or(total));
        if stream && total < 300000 {
            warn(
                "timeouts.total_ms",
                "short_stream_deadline",
                "Stream has a total deadline below five minutes; set an explicit lifetime suitable for this application.",
            );
        }
        if r.access.rate_limit.is_none() && document.global_rules.rate_limit.is_none() {
            warn(
                "access.rate_limit",
                "missing_quota",
                "No global or route rate quota is configured; set a bounded rate policy in Global rules or on this route, separately from concurrent admission limits.",
            );
        }
        if document
            .upstreams
            .iter()
            .find(|u| u.id == r.upstream)
            .is_some_and(|u| {
                u.endpoints
                    .iter()
                    .all(|e| !operations.eligible(&crate::operations::Operations::key(&u.id, e)))
            })
        {
            warn(
                "upstream",
                "all_endpoints_drained",
                "Every endpoint is drained or in maintenance; resume an endpoint before sending traffic.",
            );
        }
    }
    out
}

pub const SCOPES: [&str; 5] = [
    "full",
    "headers_query_only",
    "skipped_multipart",
    "off",
    "not_inspected",
];
#[derive(Default)]
pub struct Coverage([std::sync::atomic::AtomicU64; 5]);
impl Coverage {
    pub fn record(&self, scope: &str) {
        let index = SCOPES.iter().position(|s| *s == scope).unwrap_or(4);
        self.0[index].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn counts(&self) -> [u64; 5] {
        std::array::from_fn(|i| self.0[i].load(std::sync::atomic::Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn contract() -> Content {
        Content {
            media_types: vec![
                "application/json".into(),
                "multipart/form-data".into(),
                "application/x-www-form-urlencoded".into(),
            ],
            require_type_for_body: true,
        }
    }
    fn header(value: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("content-type", value.parse().expect("fixture"));
        h
    }
    #[test]
    fn strict_media_contract_cannot_be_downgraded() {
        let c = Content {
            media_types: vec!["application/json".into()],
            require_type_for_body: true,
        };
        assert!(
            headers(&c, &header("Application/JSON; charset=\"utf-8\""), true)
                .expect("parameters")
                .json
        );
        assert_eq!(
            headers(&c, &header("multipart/form-data; boundary=abc"), true).unwrap_err(),
            415
        );
        assert_eq!(headers(&c, &http::HeaderMap::new(), true).unwrap_err(), 415);
        assert!(headers(&c, &http::HeaderMap::new(), false).is_ok());
        for value in [
            "application/json, text/plain",
            "application/json;",
            "application/json; charset=",
            "application/json; charset=utf8; CHARSET=utf8",
            "application/json; charset=a; charset=b",
            "application/json; charset=\"unterminated",
            "multipart/form-data",
            "multipart/form-data; boundary=\"\"",
        ] {
            assert_eq!(
                headers(&contract(), &header(value), true).unwrap_err(),
                400,
                "{value}"
            );
        }
        let mut h = header("application/json");
        h.append("content-type", "application/json".parse().expect("fixture"));
        assert_eq!(headers(&c, &h, true).unwrap_err(), 400);
        h = header("application/json");
        h.insert("content-encoding", "gzip".parse().expect("fixture"));
        assert_eq!(headers(&c, &h, true).unwrap_err(), 415);
        h.insert("content-encoding", "gzip, br".parse().expect("fixture"));
        assert_eq!(headers(&c, &h, true).unwrap_err(), 415);
        h.insert("content-encoding", "identity".parse().expect("fixture"));
        assert!(headers(&c, &h, true).is_ok());
        assert!(
            headers(
                &contract(),
                &header("multipart/form-data; boundary=\"a:b\""),
                true
            )
            .expect("quoted")
            .multipart
        );
    }
    #[test]
    fn framing_is_checked_before_pingora_reconciliation() {
        for raw in [
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
        ] {
            assert_eq!(raw_framing(raw), Err(400));
        }
        assert!(raw_framing(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n").is_ok());
        let mut h = http::HeaderMap::new();
        h.insert("content-length", "+5".parse().expect("fixture"));
        assert_eq!(framing(&h), Err(400));
        h.insert("content-length", "5".parse().expect("fixture"));
        assert!(framing(&h).is_ok());
        h.insert("transfer-encoding", "chunked".parse().expect("fixture"));
        assert_eq!(framing(&h), Err(400));
        assert_eq!(
            headers(
                &contract(),
                &header("application/json; charset=utf-16"),
                true
            )
            .unwrap_err(),
            415
        );
        assert_eq!(
            headers(
                &contract(),
                &header("multipart/form-data; boundary=\"a;b\""),
                true
            )
            .unwrap_err(),
            400
        );
    }
    #[test]
    fn syntax_is_checked_without_collecting_streams() {
        let parsed = headers(&contract(), &header("application/json"), true).expect("json");
        assert!(body(parsed, br#"{"value":1}"#).is_ok());
        assert_eq!(body(parsed, b"value=1"), Err(400));
        assert_eq!(body(parsed, br#"{"value":1} trailing"#), Err(400));
        let parsed = headers(
            &contract(),
            &header("application/x-www-form-urlencoded"),
            true,
        )
        .expect("form");
        assert!(body(parsed, b"value=hello%20world&next=1").is_ok());
        assert_eq!(body(parsed, b"value=%xx"), Err(400));
        assert_eq!(body(parsed, b"{\"value\":1}"), Err(400));
    }
    #[test]
    fn templates_are_explicit_safe_and_only_metadata() {
        for template in templates() {
            let mut route: Route = serde_json::from_value(serde_json::json!({"id":"app","hostname":"example.test","path":"/","path_match":"prefix","upstream":"app"})).expect("legacy");
            let legacy = serde_json::to_value(&route).expect("serialize");
            assert!(
                legacy.get("profile").is_none()
                    && legacy.get("content").is_none()
                    && legacy.get("retry").is_none()
            );
            let values = serde_json::to_value(&template).expect("template");
            let mut upgraded = legacy.clone();
            upgraded
                .as_object_mut()
                .expect("object")
                .extend(values.as_object().expect("object").clone());
            route = serde_json::from_value(upgraded).expect("profile route");
            validate(&route).expect("valid template");
            assert_eq!(
                serde_json::to_value(&route).expect("profile wire")["retry"]["mode"],
                "disabled"
            );
            assert_eq!(
                route.waf.as_ref().expect("waf").mode,
                waf::Mode::DetectionOnly
            );
            assert_eq!(route.waf.as_ref().expect("waf").paranoia_level, 1);
            assert_eq!(route.retry.mode, retry::Mode::Disabled);
            let before = route.clone();
            route.profile.as_mut().expect("profile").version = 999;
            validate(&route).expect("future metadata");
            assert_eq!(route.body, before.body);
            assert_eq!(route.content, before.content);
        }
    }
}
