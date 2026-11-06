//! Read-only routing simulation using the gateway's exact matcher. Never calls an upstream.
use crate::{Snapshot, Validation, canonical_path, normalized_ip, request_host};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(default = "default_scheme")]
    pub scheme: crate::Protocol,
    pub hostname: String,
    pub path: String,
    pub method: String,
    pub client_ip: IpAddr,
}
fn default_scheme() -> crate::Protocol {
    crate::Protocol::Https
}
#[derive(Serialize)]
pub struct Candidate {
    pub route_id: String,
    pub host_matches: bool,
    pub path_matches: bool,
    pub method_matches: bool,
    pub selected: bool,
    pub precedence: (bool, usize, bool, usize, bool),
}
impl Snapshot {
    pub fn playground(&self, input: Input) -> Result<serde_json::Value, Validation> {
        let host = request_host(&input.hostname)?;
        let path = canonical_path(&input.path)?;
        if path.starts_with(crate::password::LOGIN_PREFIX) {
            return Err(Validation::Path);
        }
        if input.method.len() > 32
            || input.method.parse::<http::Method>().is_err()
            || !input
                .method
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b == b'-')
        {
            return Err(Validation::Method);
        }
        let selected = self.route(&host, &path, &input.method);
        let mut candidates: Vec<_> = self
            .document
            .routes
            .iter()
            .enumerate()
            .map(|(i, r)| Candidate {
                route_id: r.id.clone(),
                host_matches: r.host_matches(&host),
                path_matches: r.path_matches(&path),
                method_matches: r.methods.is_empty() || r.methods.contains(&input.method),
                selected: Some(i) == selected,
                precedence: r.precedence(),
            })
            .collect();
        candidates.sort_by_key(|c| std::cmp::Reverse(c.precedence));
        let effective = selected.map(|i| {
            let r = &self.document.routes[i];
            let uri: http::Uri = path.parse().map_err(|_| Validation::Path)?;
            let rewritten = r.middleware.rewrite.as_ref().map(|w| w.apply(&uri).map(|u|u.path().to_owned())).transpose()?;
            let redirect = r.redirect.as_ref().filter(|redirect| !redirect.http_only || input.scheme == crate::Protocol::Http);
            let redirect = redirect.map(|r| r.location(&uri).map(|url| serde_json::json!({"url":url,"status":r.status}))).transpose()?;
            Ok::<_,Validation>(serde_json::json!({"route_id":r.id,"maintenance":r.maintenance,"upstream":r.upstream,"application":r.application,"redirect":redirect,
                "rewritten_path":rewritten.unwrap_or_else(||path.clone()),"acl_permits_ip":self.document.global_rules.permits_ip(input.client_ip) && r.access.permits_ip(input.client_ip),
                "global_rules":{"acl_permits_ip":self.document.global_rules.permits_ip(input.client_ip), "geo_policy":self.document.global_rules.geo.is_some(), "rate_limit":self.document.global_rules.rate_limit,"ddos":self.document.global_rules.ddos,"challenge":self.document.global_rules.challenge},
                "waf_mode":r.waf.as_ref().map(|w|w.mode),"inspection":r.body.as_ref().map(|b|b.inspection),
                "password_protected":r.password_protect.is_some(),"forward_auth":r.middleware.forward_auth.is_some(),
                "challenge":r.access.challenge,"ddos":r.access.ddos,"rate_limit":r.access.rate_limit,"geo_policy":r.access.geo.is_some()}))
        }).transpose()?;
        Ok(
            serde_json::json!({"schema_version":1,"config_version":self.version,"scheme":input.scheme,"hostname":host,"path":path,"method":input.method,
            "client_ip":normalized_ip(input.client_ip),"candidates":candidates,"effective":effective,
            "runtime_checks":"not_run","limitations":["No requests sent; WAF payload inspection, rate counters, GeoIP, CrowdSec, sessions, DNS, TLS and upstream health are not evaluated.","An omitted WAF mode inherits the gateway startup mode."]}),
        )
    }
}
