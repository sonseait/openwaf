//! Validated response policy; no arbitrary header names or request interpolation.
use crate::{Route, Validation, canonical_path, hostname};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityHeaders {
    pub hsts_max_age: Option<u32>,
    pub hsts_include_subdomains: bool,
    pub content_security_policy: Option<String>,
    pub nosniff: bool,
    pub referrer_policy: Option<ReferrerPolicy>,
    pub frame_options: Option<FrameOptions>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReferrerPolicy {
    NoReferrer,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
}
impl ReferrerPolicy {
    pub fn value(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::SameOrigin => "same-origin",
            Self::StrictOrigin => "strict-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FrameOptions {
    Deny,
    Sameorigin,
}
impl FrameOptions {
    pub fn value(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::Sameorigin => "SAMEORIGIN",
        }
    }
}
impl SecurityHeaders {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if self.hsts_max_age.is_some_and(|age| age > 63072000)
            || (self.hsts_include_subdomains && self.hsts_max_age.is_none())
            || self.content_security_policy.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 4096
                    || !value.bytes().all(|b| (32..=126).contains(&b))
            })
        {
            return Err(Validation::SecurityHeaders);
        }
        Ok(())
    }
    /// HSTS is sent only over a TLS connection terminated by this gateway.
    pub fn values(&self, tls: bool) -> Vec<(&'static str, String)> {
        let mut values = Vec::with_capacity(5);
        if tls && let Some(age) = self.hsts_max_age {
            values.push((
                "strict-transport-security",
                format!(
                    "max-age={age}{}",
                    if self.hsts_include_subdomains {
                        "; includeSubDomains"
                    } else {
                        ""
                    }
                ),
            ));
        }
        if let Some(value) = &self.content_security_policy {
            values.push(("content-security-policy", value.clone()));
        }
        if self.nosniff {
            values.push(("x-content-type-options", "nosniff".into()));
        }
        if let Some(value) = self.referrer_policy {
            values.push(("referrer-policy", value.value().into()));
        }
        if let Some(value) = self.frame_options {
            values.push(("x-frame-options", value.value().into()));
        }
        values
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    #[serde(default)]
    pub preserve_path: bool,
    #[serde(default)]
    pub preserve_query: bool,
    /// Fixed absolute URL. No client-controlled authority or interpolation.
    pub url: String,
    pub status: u16,
    /// Redirect HTTP; use the route's upstream over HTTPS.
    #[serde(default)]
    pub http_only: bool,
}
impl Redirect {
    fn target(&self) -> Result<http::Uri, Validation> {
        let uri: http::Uri = self.url.parse().map_err(|_| Validation::Redirect)?;
        if self.url.len() > 2048
            || !self.url.bytes().all(|b| (33..=126).contains(&b))
            || self.url.contains(['#', '\\'])
            || !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.port_u16() == Some(0)
            || (self.http_only && uri.scheme_str() != Some("https"))
            || !matches!(self.status, 301 | 302 | 303 | 307 | 308)
            || (self.preserve_path && uri.path() != "/" && !uri.path().is_empty())
            || (self.preserve_query && uri.query().is_some())
        {
            return Err(Validation::Redirect);
        }
        let authority = uri.authority().ok_or(Validation::Redirect)?;
        crate::request_host(authority.as_str()).map_err(|_| Validation::Redirect)?;
        canonical_path(uri.path()).map_err(|_| Validation::Redirect)?;
        Ok(uri)
    }
    pub fn location(&self, original: &http::Uri) -> Result<String, Validation> {
        let target = self.target()?;
        let path = if self.preserve_path {
            original.path()
        } else {
            target.path()
        };
        let query = if self.preserve_query {
            original.query()
        } else {
            target.query()
        };
        let location = format!(
            "{}://{}{}{}",
            target.scheme_str().ok_or(Validation::Redirect)?,
            target.authority().ok_or(Validation::Redirect)?,
            if path.is_empty() { "/" } else { path },
            query.map_or(String::new(), |q| format!("?{q}"))
        );
        if location.len() > 8192 {
            return Err(Validation::Limit);
        }
        Ok(location)
    }
}

/// Reject possible cycles among configured redirect hosts. Conservative by
/// design: path/method precedence is ignored, so even a potential host cycle
/// cannot depend on request method rewriting by a browser.
pub fn validate_redirects(routes: &[Route]) -> Result<(), Validation> {
    let targets: Vec<_> = routes
        .iter()
        .map(|r| r.redirect.as_ref().map(Redirect::target).transpose())
        .collect::<Result<_, _>>()?;
    let mut edges = vec![Vec::new(); routes.len()];
    for (i, target) in targets.iter().enumerate() {
        let Some(target) = target else { continue };
        let host = hostname(
            target
                .host()
                .ok_or(Validation::Redirect)?
                .trim_matches(['[', ']']),
        )?;
        for (j, route) in routes.iter().enumerate() {
            let Some(next) = &route.redirect else {
                continue;
            };
            if next.http_only && target.scheme_str() == Some("https") {
                continue;
            }
            if route.hostname == host
                || route.hostname.strip_prefix("*.").is_some_and(|suffix| {
                    host.strip_suffix(suffix)
                        .is_some_and(|p| p.ends_with('.') && p.len() > 1)
                })
            {
                edges[i].push(j);
            }
        }
    }
    fn visit(i: usize, edges: &[Vec<usize>], state: &mut [u8]) -> Result<(), Validation> {
        if state[i] == 1 {
            return Err(Validation::RedirectLoop);
        }
        if state[i] == 2 {
            return Ok(());
        }
        state[i] = 1;
        for &next in &edges[i] {
            visit(next, edges, state)?;
        }
        state[i] = 2;
        Ok(())
    }
    let mut state = vec![0; routes.len()];
    for i in 0..routes.len() {
        visit(i, &edges, &mut state)?;
    }
    Ok(())
}
