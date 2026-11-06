//! Bounded route policies. No network I/O, credentials or arbitrary interpolation.
use crate::{Validation, canonical_path, request_host, valid_id};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub rewrite: Option<Rewrite>,
    pub request_headers: Headers,
    pub response_headers: Headers,
    pub cors: Option<Cors>,
    pub forward_auth: Option<ForwardAuth>,
    pub identity_rate_limit: Option<IdentityRateLimit>,
    pub api_schema: Option<crate::api_schema::Policy>,
    pub detectors: Option<crate::abuse::Policy>,
}
impl Policy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&mut self) -> Result<(), Validation> {
        if let Some(rewrite) = &mut self.rewrite {
            rewrite.validate()?;
        }
        self.request_headers.validate(true)?;
        self.response_headers.validate(false)?;
        if let Some(cors) = &mut self.cors {
            cors.validate()?;
        }
        if let Some(auth) = &mut self.forward_auth {
            auth.validate()?;
            if auth.response_headers.iter().any(|name| {
                self.request_headers
                    .set
                    .iter()
                    .any(|header| &header.name == name)
                    || self.request_headers.remove.contains(name)
            }) {
                return Err(Validation::Middleware);
            }
        }
        if let Some(detectors) = &self.detectors {
            detectors.validate()?;
        }
        if let Some(schema) = &self.api_schema {
            schema.validate()?;
        }
        if let Some(quota) = &mut self.identity_rate_limit {
            quota.header = quota.header.to_ascii_lowercase();
            let auth = self.forward_auth.as_ref().ok_or(Validation::Middleware)?;
            if !auth.identity_headers.contains(&quota.header)
                || !(1..=10000).contains(&quota.per_second)
                || !(1..=10000).contains(&quota.burst)
            {
                return Err(Validation::Middleware);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRateLimit {
    pub header: String,
    pub per_second: u32,
    pub burst: u32,
    #[serde(default)]
    pub require_identity: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Rewrite {
    pub strip_prefix: Option<String>,
    pub add_prefix: Option<String>,
    pub replace_path: Option<String>,
}
impl Rewrite {
    fn validate(&mut self) -> Result<(), Validation> {
        if self.replace_path.is_some() && (self.strip_prefix.is_some() || self.add_prefix.is_some())
        {
            return Err(Validation::Middleware);
        }
        for path in [
            &mut self.strip_prefix,
            &mut self.add_prefix,
            &mut self.replace_path,
        ]
        .into_iter()
        .flatten()
        {
            *path = canonical_path(path).map_err(|_| Validation::Middleware)?;
        }
        if self
            .strip_prefix
            .as_ref()
            .is_some_and(|p| p.len() > 1 && p.ends_with('/'))
            || self
                .add_prefix
                .as_ref()
                .is_some_and(|p| p == "/" || p.ends_with('/'))
        {
            return Err(Validation::Middleware);
        }
        Ok(())
    }
    pub fn apply(&self, original: &Uri) -> Result<Uri, Validation> {
        let mut path = canonical_path(original.path()).map_err(|_| Validation::Middleware)?;
        if let Some(replace) = &self.replace_path {
            path = replace.clone();
        }
        if let Some(prefix) = &self.strip_prefix {
            if prefix == "/" { /* stripping root preserves the leading slash */
            } else if path == *prefix {
                path = "/".into();
            } else if let Some(rest) = path
                .strip_prefix(prefix)
                .filter(|rest| rest.starts_with('/'))
            {
                path = rest.into();
            } else {
                return Err(Validation::Middleware);
            }
        }
        if let Some(prefix) = &self.add_prefix {
            path = format!("{prefix}{path}");
        }
        canonical_path(&path).map_err(|_| Validation::Middleware)?;
        if let Some(query) = original.query() {
            path.push('?');
            path.push_str(query);
        }
        if path.len() > 8192 {
            return Err(Validation::Limit);
        }
        path.parse().map_err(|_| Validation::Middleware)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Headers {
    pub set: Vec<Header>,
    pub remove: Vec<String>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}
pub fn reserved(name: &str) -> bool {
    name.starts_with("x-forwarded-")
        || name.starts_with("access-control-")
        || name.starts_with("sec-websocket-")
        || name.starts_with("cf-")
        || name.starts_with("proxy-")
        || matches!(
            name,
            "host"
                | "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "content-length"
                | "content-encoding"
                | "trailer"
                | "te"
                | "upgrade"
                | "expect"
                | "forwarded"
                | "x-real-ip"
                | "x-openwaf-hop"
                | "x-openwaf-challenge"
                | "x-openwaf-maintenance"
                | "x-request-id"
                | "vary"
                | "location"
                | "authorization"
                | "cookie"
                | "set-cookie"
                | "www-authenticate"
                | "x-api-key"
                | "api-key"
        )
}
fn names(values: &mut [String], allow_sensitive: bool) -> Result<(), Validation> {
    if values.len() > 32 {
        return Err(Validation::Middleware);
    }
    let mut seen = BTreeSet::new();
    for name in values {
        *name = name.to_ascii_lowercase();
        if name.len() > 64
            || name.parse::<HeaderName>().is_err()
            || !seen.insert(name.clone())
            || (!allow_sensitive && reserved(name))
        {
            return Err(Validation::Middleware);
        }
    }
    Ok(())
}
impl Headers {
    fn validate(&mut self, request: bool) -> Result<(), Validation> {
        if self.set.len() > 32
            || self
                .set
                .iter()
                .map(|h| h.name.len() + h.value.len())
                .sum::<usize>()
                > 8192
        {
            return Err(Validation::Middleware);
        }
        names(&mut self.remove, false)?;
        let mut seen = BTreeSet::new();
        for header in &mut self.set {
            header.name = header.name.to_ascii_lowercase();
            if header.name.len() > 64
                || header.name.parse::<HeaderName>().is_err()
                || reserved(&header.name)
                || header.value.len() > 2048
                || !header.value.bytes().all(|b| (32..=126).contains(&b))
                || (request && header.name == "content-type")
                || !seen.insert(header.name.clone())
                || self.remove.contains(&header.name)
            {
                return Err(Validation::Middleware);
            }
        }
        if request && self.remove.iter().any(|n| n == "content-type") {
            return Err(Validation::Middleware);
        }
        Ok(())
    }
    pub fn apply(&self, headers: &mut HeaderMap) -> Result<(), Validation> {
        for name in &self.remove {
            headers.remove(name);
        }
        for header in &self.set {
            headers.insert(
                header
                    .name
                    .parse::<HeaderName>()
                    .map_err(|_| Validation::Middleware)?,
                header
                    .value
                    .parse::<HeaderValue>()
                    .map_err(|_| Validation::Middleware)?,
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Cors {
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub credentials: bool,
    pub max_age_seconds: u32,
}
impl Default for Cors {
    fn default() -> Self {
        Self {
            origins: vec![],
            methods: vec!["GET".into(), "HEAD".into(), "POST".into()],
            allowed_headers: vec![],
            exposed_headers: vec![],
            credentials: false,
            max_age_seconds: 600,
        }
    }
}
pub fn origin(value: &str) -> bool {
    let Ok(uri) = value.parse::<Uri>() else {
        return false;
    };
    matches!(uri.scheme_str(), Some("https" | "http"))
        && uri.authority().is_some_and(|a| {
            !a.as_str().contains('@') && a.port_u16() != Some(0) && request_host(a.as_str()).is_ok()
        })
        && uri.path() == "/"
        && uri.query().is_none()
        && !value.ends_with('/')
        && value.len() <= 512
}
impl Cors {
    fn validate(&mut self) -> Result<(), Validation> {
        if self.origins.is_empty()
            || self.origins.len() > 32
            || self.origins.iter().any(|o| o != "*" && !origin(o))
            || (self.origins.iter().any(|o| o == "*")
                && (self.credentials || self.origins.len() != 1))
            || self.origins.iter().collect::<BTreeSet<_>>().len() != self.origins.len()
            || self.methods.is_empty()
            || self.methods.len() > 16
            || self.methods.iter().any(|m| {
                m.len() > 32 || m.parse::<Method>().is_err() || m.to_ascii_uppercase() != *m
            })
            || self.methods.iter().collect::<BTreeSet<_>>().len() != self.methods.len()
            || self.max_age_seconds > 86400
        {
            return Err(Validation::Middleware);
        }
        names(&mut self.allowed_headers, true)?;
        names(&mut self.exposed_headers, true)?;
        Ok(())
    }
    pub fn check(&self, headers: &HeaderMap, method: &str) -> Result<Option<CorsResponse>, u16> {
        let Some(value) = single(headers, "origin")? else {
            return Ok(None);
        };
        if !origin(value) || !self.origins.iter().any(|o| o == "*" || o == value) {
            return Err(403);
        }
        let preflight =
            method == "OPTIONS" && headers.contains_key("access-control-request-method");
        if preflight {
            let requested = single(headers, "access-control-request-method")?.ok_or(400_u16)?;
            if !self.methods.iter().any(|m| m == requested) {
                return Err(403);
            }
            if let Some(requested) = single(headers, "access-control-request-headers")?
                && (requested.len() > 2048
                    || requested.split(',').count() > 32
                    || requested.split(',').any(|h| {
                        !self
                            .allowed_headers
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(h.trim()))
                    }))
            {
                return Err(403);
            }
        }
        Ok(Some(CorsResponse {
            origin: if self.origins.iter().any(|o| o == "*") {
                "*".into()
            } else {
                value.into()
            },
            preflight,
        }))
    }
    pub fn apply(
        &self,
        state: Option<&CorsResponse>,
        headers: &mut HeaderMap,
    ) -> Result<(), Validation> {
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
        ] {
            headers.remove(name);
        }
        // Also vary responses without Origin so caches cannot reuse them for CORS requests.
        vary(headers, "Origin")?;
        let Some(state) = state else { return Ok(()) };
        let mut insert = |name: &'static str, value: String| -> Result<(), Validation> {
            headers.insert(name, value.parse().map_err(|_| Validation::Middleware)?);
            Ok(())
        };
        insert("access-control-allow-origin", state.origin.clone())?;
        if self.credentials {
            insert("access-control-allow-credentials", "true".into())?;
        }
        if state.preflight {
            insert("access-control-allow-methods", self.methods.join(", "))?;
            if !self.allowed_headers.is_empty() {
                insert(
                    "access-control-allow-headers",
                    self.allowed_headers.join(", "),
                )?;
            }
            insert("access-control-max-age", self.max_age_seconds.to_string())?;
        } else if !self.exposed_headers.is_empty() {
            insert(
                "access-control-expose-headers",
                self.exposed_headers.join(", "),
            )?;
        }
        if state.preflight {
            vary(headers, "Access-Control-Request-Method")?;
            vary(headers, "Access-Control-Request-Headers")?;
        }
        Ok(())
    }
}
pub struct CorsResponse {
    pub origin: String,
    pub preflight: bool,
}
pub fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, u16> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|v| v.to_str().map_err(|_| 400_u16))
        .transpose()?;
    if values.next().is_some() {
        return Err(400);
    }
    Ok(value)
}
fn vary(headers: &mut HeaderMap, name: &str) -> Result<(), Validation> {
    let mut values = Vec::new();
    for value in headers.get_all("vary") {
        let value = value.to_str().map_err(|_| Validation::Middleware)?;
        if value.len() > 4096 {
            return Err(Validation::Middleware);
        }
        values.extend(value.split(',').map(|v| v.trim().to_owned()));
    }
    if !values
        .iter()
        .any(|v| v == "*" || v.eq_ignore_ascii_case(name))
    {
        values.push(name.into());
    }
    let value = values.join(", ");
    if value.len() > 8192 {
        return Err(Validation::Limit);
    }
    headers.insert("vary", value.parse().map_err(|_| Validation::Middleware)?);
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardAuth {
    pub upstream: String,
    pub path: String,
    pub timeout_ms: u64,
    pub request_headers: Vec<String>,
    pub response_headers: Vec<String>,
    pub identity_headers: Vec<String>,
    pub response_cookies: Vec<String>,
    pub redirect_origins: Vec<String>,
}
impl Default for ForwardAuth {
    fn default() -> Self {
        Self {
            upstream: String::new(),
            path: "/".into(),
            timeout_ms: 2000,
            request_headers: vec!["cookie".into(), "authorization".into()],
            response_headers: vec![],
            identity_headers: vec![],
            response_cookies: vec![],
            redirect_origins: vec![],
        }
    }
}
impl ForwardAuth {
    fn validate(&mut self) -> Result<(), Validation> {
        self.path = canonical_path(&self.path).map_err(|_| Validation::Middleware)?;
        if !valid_id(&self.upstream)
            || !(100..=5000).contains(&self.timeout_ms)
            || self.redirect_origins.len() > 16
            || self.redirect_origins.iter().any(|o| !origin(o))
            || self.redirect_origins.iter().collect::<BTreeSet<_>>().len()
                != self.redirect_origins.len()
            || self.response_cookies.len() > 16
            || self.response_cookies.iter().any(|n| {
                n.is_empty()
                    || n.len() > 64
                    || !n
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            })
        {
            return Err(Validation::Middleware);
        }
        names(&mut self.request_headers, true)?;
        names(&mut self.response_headers, false)?;
        names(&mut self.identity_headers, false)?;
        if self.identity_headers.iter().any(|n| {
            n.starts_with("content-")
                || matches!(
                    n.as_str(),
                    "accept"
                        | "accept-encoding"
                        | "accept-language"
                        | "user-agent"
                        | "range"
                        | "cache-control"
                        | "x-content-type-options"
                        | "referrer-policy"
                )
        }) {
            return Err(Validation::Middleware);
        }

        if self
            .identity_headers
            .iter()
            .any(|n| !self.response_headers.contains(n))
        {
            return Err(Validation::Middleware);
        }
        if self
            .response_headers
            .iter()
            .any(|n| n.starts_with("content-"))
        {
            return Err(Validation::Middleware);
        }
        if self
            .request_headers
            .iter()
            .any(|n| reserved(n) && n != "cookie" && n != "authorization")
        {
            return Err(Validation::Middleware);
        }
        if self
            .response_headers
            .iter()
            .any(|n| self.request_headers.contains(n))
        {
            return Err(Validation::Middleware);
        }
        Ok(())
    }
    pub fn permits_redirect(&self, value: &str) -> bool {
        if value.len() > 8192
            || !value.bytes().all(|b| (33..=126).contains(&b))
            || value.contains(['\\', '#'])
        {
            return false;
        }
        if value.starts_with('/') {
            return !value.starts_with("//")
                && value
                    .parse::<Uri>()
                    .is_ok_and(|u| u.scheme().is_none() && u.authority().is_none());
        }
        let Ok(uri) = value.parse::<Uri>() else {
            return false;
        };
        let Some(authority) = uri.authority() else {
            return false;
        };
        let Some(scheme) = uri.scheme_str() else {
            return false;
        };
        self.redirect_origins
            .iter()
            .any(|o| o == &format!("{scheme}://{authority}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn policy(value: serde_json::Value) -> Result<Policy, Validation> {
        let mut policy: Policy = serde_json::from_value(value).expect("fixture schema");
        policy.validate()?;
        Ok(policy)
    }
    #[test]
    fn rewrites_preserve_query_and_match_segment_boundaries() {
        let p = policy(json!({"rewrite":{"strip_prefix":"/grafana","add_prefix":"/internal"}}))
            .unwrap();
        let rewrite = p.rewrite.unwrap();
        assert_eq!(
            rewrite
                .apply(&"/grafana/a?sig=%2B%2F&x=1&x=2".parse().unwrap())
                .unwrap()
                .to_string(),
            "/internal/a?sig=%2B%2F&x=1&x=2"
        );
        assert_eq!(
            rewrite
                .apply(&"/grafana".parse().unwrap())
                .unwrap()
                .to_string(),
            "/internal/"
        );
        assert!(rewrite.apply(&"/grafana-other".parse().unwrap()).is_err());
        for value in [
            json!({"rewrite":{"replace_path":"/a","strip_prefix":"/b"}}),
            json!({"rewrite":{"add_prefix":"//evil"}}),
            json!({"rewrite":{"replace_path":"/%2fadmin"}}),
            json!({"rewrite":{"strip_prefix":"/app/"}}),
        ] {
            assert!(policy(value).is_err());
        }
    }
    #[test]
    fn headers_cannot_override_transport_credentials_or_verified_identity() {
        for name in [
            "Host",
            "Connection",
            "Content-Length",
            "X-Forwarded-For",
            "Cookie",
            "Authorization",
            "Location",
            "Vary",
            "Access-Control-Allow-Origin",
            "Sec-WebSocket-Key",
            "CF-Connecting-IP",
        ] {
            assert!(
                policy(json!({"request_headers":{"set":[{"name":name,"value":"x"}]}})).is_err(),
                "{name}"
            );
        }
        for value in [
            json!({"response_headers":{"set":[{"name":"x-a","value":"a\r\nInjected: yes"}]}}),
            json!({"request_headers":{"set":[{"name":"X-Test","value":"a"},{"name":"x-test","value":"b"}]}}),
            json!({"request_headers":{"remove":["X-Test","x-test"]}}),
            json!({"forward_auth":{"upstream":"auth","response_headers":["remote-user"]},"request_headers":{"set":[{"name":"Remote-User","value":"forged"}]}}),
        ] {
            assert!(policy(value).is_err());
        }
        let p = policy(
            json!({"request_headers":{"set":[{"name":"X-App","value":"one"}],"remove":["x-drop"]}}),
        )
        .unwrap();
        let mut h = HeaderMap::new();
        h.append("x-app", "old".parse().unwrap());
        h.append("x-app", "duplicate".parse().unwrap());
        h.insert("x-drop", "drop".parse().unwrap());
        p.request_headers.apply(&mut h).unwrap();
        assert_eq!(h["x-app"], "one");
        assert_eq!(h.get_all("x-app").iter().count(), 1);
        assert!(!h.contains_key("x-drop"));
    }
    #[test]
    fn cors_preflight_is_explicit_and_cache_safe() {
        let cors=policy(json!({"cors":{"origins":["https://app.test"],"methods":["GET"],"allowed_headers":["Authorization"],"credentials":true}})).unwrap().cors.unwrap();
        let mut h = HeaderMap::new();
        h.insert("origin", "https://app.test".parse().unwrap());
        h.insert("access-control-request-method", "GET".parse().unwrap());
        h.insert(
            "access-control-request-headers",
            "authorization".parse().unwrap(),
        );
        let state = cors.check(&h, "OPTIONS").unwrap().unwrap();
        assert!(state.preflight);
        let mut out = HeaderMap::new();
        out.append("vary", "Accept-Encoding".parse().unwrap());
        out.append("vary", "Accept-Language".parse().unwrap());
        cors.apply(Some(&state), &mut out).unwrap();
        assert_eq!(out["access-control-allow-origin"], "https://app.test");
        assert_eq!(out["access-control-allow-credentials"], "true");
        assert!(out["vary"].to_str().unwrap().contains("Accept-Encoding"));
        assert!(
            out["vary"]
                .to_str()
                .unwrap()
                .contains("Access-Control-Request-Headers")
        );
        h.insert(
            "access-control-request-headers",
            "x-forbidden".parse().unwrap(),
        );
        assert!(cors.check(&h, "OPTIONS").is_err());
        h.append("origin", "https://app.test".parse().unwrap());
        assert_eq!(cors.check(&h, "GET").err(), Some(400));
        for origin in [
            "null",
            "https://app.test/",
            "https://user@app.test",
            "https://app.test/path",
        ] {
            assert!(policy(json!({"cors":{"origins":[origin]}})).is_err());
        }
        assert!(policy(json!({"cors":{"origins":["*"],"credentials":true}})).is_err());
        out.insert("access-control-allow-origin", "*".parse().unwrap());
        cors.apply(None, &mut out).unwrap();
        assert!(!out.contains_key("access-control-allow-origin"));
        assert!(out.contains_key("vary"));
    }
    #[test]
    fn auth_redirects_and_config_are_bounded() {
        let auth = policy(
            json!({"forward_auth":{"upstream":"auth","redirect_origins":["https://login.test"]}}),
        )
        .unwrap()
        .forward_auth
        .unwrap();
        for value in ["/login?next=%2F", "https://login.test/login?next=x"] {
            assert!(auth.permits_redirect(value));
        }
        for value in [
            "//evil.test",
            "/\\evil.test",
            "https://evil.test/",
            "https://login.test@evil.test/",
            "http://login.test/",
            "javascript:alert(1)",
            "https://login.test/\r\nX:evil",
        ] {
            assert!(!auth.permits_redirect(value));
        }
        for value in [
            json!({"forward_auth":{"upstream":"auth","timeout_ms":0}}),
            json!({"forward_auth":{"upstream":"auth","path":"http://evil/"}}),
            json!({"forward_auth":{"upstream":"auth","response_headers":["authorization"]}}),
        ] {
            assert!(policy(value).is_err());
        }
    }
    #[test]
    fn redirect_preserves_raw_path_query_only_when_opted_in() {
        let mut redirect = crate::response::Redirect {
            url: "https://new.test/".into(),
            status: 308,
            http_only: false,
            preserve_path: true,
            preserve_query: true,
        };
        let original = "/a%20b?x=%2f&x=2".parse().unwrap();
        assert_eq!(
            redirect.location(&original).unwrap(),
            "https://new.test/a%20b?x=%2f&x=2"
        );
        redirect.preserve_path = false;
        redirect.preserve_query = false;
        redirect.url = "https://new.test/fixed?q=one".into();
        assert_eq!(redirect.location(&original).unwrap(), redirect.url);
        redirect.preserve_query = true;
        assert!(redirect.location(&original).is_err());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    fn quota_requires_explicit_auth_approval_and_cannot_manufacture_identity() {
        let mut p = Policy {
            identity_rate_limit: Some(IdentityRateLimit {
                header: "remote-user".into(),
                per_second: 1,
                burst: 2,
                require_identity: true,
            }),
            ..Default::default()
        };
        assert!(p.validate().is_err());
        p.forward_auth = Some(ForwardAuth {
            upstream: "auth".into(),
            response_headers: vec!["remote-user".into()],
            ..Default::default()
        });
        assert!(p.validate().is_err());
        p.forward_auth.as_mut().unwrap().identity_headers = vec!["remote-user".into()];
        p.validate().unwrap();
        p.request_headers.set.push(Header {
            name: "remote-user".into(),
            value: "forgery".into(),
        });
        assert!(p.validate().is_err());
        p.request_headers.set.clear();
        p.forward_auth
            .as_mut()
            .unwrap()
            .request_headers
            .push("remote-user".into());
        assert!(p.validate().is_err());
    }
}
