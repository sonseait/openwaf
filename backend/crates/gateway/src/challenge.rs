//! Stateless browser proof-of-work. Fixed-cost verification, random process key,
//! signed host/IP/version/scope/expiry binding, bounded issuance/verification rate.
//! This increases automated-client cost; it does not establish human identity.
use anyhow::Result;
use http::HeaderMap;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use openwaf_config::access::{Challenge, RateLimit};
use openwaf_security::{
    ddos::Protection,
    traffic::{Limiter, Verdict},
};
use serde::Deserialize;
use std::{net::IpAddr, time::Instant};
use zeroize::Zeroizing;

pub const HEADER: &str = "x-openwaf-challenge";
const PENDING: &str = "__Host-openwaf-challenge-pending";
const PREFIX: &str = "__Host-openwaf-challenge-";
const PROOF_SECONDS: u32 = 120;
const MAX_COUNTER: u32 = (1 << 22) - 1;

pub struct Binding<'a> {
    pub authority: &'a str,
    pub version: i64,
    pub ip: IpAddr,
    pub route: &'a str,
    pub target: &'a str,
    pub global: Option<Challenge>,
    pub local: Option<Challenge>,
}
impl Binding<'_> {
    pub fn difficulty(&self) -> u8 {
        self.global
            .into_iter()
            .chain(self.local)
            .map(|p| p.difficulty)
            .max()
            .unwrap_or(0)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub token: String,
    pub counter: u32,
}
pub struct Page {
    pub body: String,
    pub nonce: String,
    pub cookie: String,
}
pub struct Gate {
    key: PKey<openssl::pkey::Private>,
    per_ip: Limiter,
    aggregate: Protection,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn nonce() -> Result<String> {
    let mut bytes = [0; 24];
    openssl::rand::rand_bytes(&mut bytes)?;
    Ok(hex(&bytes))
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut result = None;
    for value in headers.get_all("cookie") {
        for pair in value.to_str().ok()?.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=')
                && key == name
            {
                if result.is_some() || value.len() > 256 {
                    return None;
                }
                result = Some(value.to_owned());
            }
        }
    }
    result
}
fn cookie_name(scope: &str) -> String {
    format!("{PREFIX}{scope}")
}
fn set_cookie(name: &str, token: &str, seconds: u32) -> String {
    format!("{name}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={seconds}")
}
/// Select only the challenge representation, never authorize a request.
/// Old tabs/service workers may request a document with a wildcard or absent
/// Accept. Keep explicit API/stream media types and subresources noninteractive.
pub fn wants_page(headers: &HeaderMap) -> bool {
    if headers.contains_key("upgrade")
        || headers.get("sec-fetch-dest").is_some_and(|value| {
            value
                .to_str()
                .is_ok_and(|v| v != "document" && v != "empty")
                || value.to_str().is_err()
        })
    {
        return false;
    }
    let mut html = None;
    let mut text = None;
    let mut wildcard = false;
    let mut explicit_other = false;
    let mut has_accept = false;
    for value in headers.get_all("accept") {
        has_accept = true;
        let Ok(value) = value.to_str() else {
            return false;
        };
        for range in value.split(',') {
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or_default().trim();
            let allowed = parts.all(|parameter| {
                let Some((name, value)) = parameter.trim().split_once('=') else {
                    return true;
                };
                !name.trim().eq_ignore_ascii_case("q")
                    || value
                        .trim()
                        .parse::<f32>()
                        .is_ok_and(|q| q > 0.0 && q <= 1.0)
            });
            if media.eq_ignore_ascii_case("text/html") {
                html = Some(html.unwrap_or(true) && allowed);
            } else if media.eq_ignore_ascii_case("text/*") {
                text = Some(text.unwrap_or(true) && allowed);
            } else if media == "*/*" {
                wildcard |= allowed;
            } else if !media.is_empty() && allowed {
                explicit_other = true;
            }
        }
    }
    html.unwrap_or_else(|| !has_accept || (!explicit_other && text.unwrap_or(wildcard)))
}

pub fn strip_cookies(headers: &mut HeaderMap) {
    let values: Vec<_> = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|v| {
            !v.is_empty()
                && !v.starts_with(PREFIX)
                && v.split('=').next() != Some(openwaf_security::correlation::COOKIE)
        })
        .collect();
    let value = values.join("; ");
    headers.remove("cookie");
    headers.remove(HEADER);
    if let Ok(value) = http::HeaderValue::from_str(&value)
        && !value.is_empty()
    {
        headers.insert("cookie", value);
    }
}
impl Gate {
    pub fn new() -> Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(key.as_mut())?;
        Ok(Self {
            key: PKey::hmac(key.as_ref())?,
            per_ip: Limiter::global(),
            aggregate: Protection::default(),
        })
    }
    pub fn limit(&self, ip: IpAddr) -> Verdict {
        let now = Instant::now();
        let verdict = self.aggregate.check_global(
            RateLimit {
                per_second: 200,
                burst: 400,
            },
            now,
        );
        if verdict != Verdict::Allow {
            return verdict;
        }
        self.per_ip.check(
            openwaf_config::traffic::Class::Api,
            "challenge",
            ip,
            RateLimit {
                per_second: 2,
                burst: 12,
            },
            now,
        )
    }
    // Global clearance is shared across routes on the same authority. Route
    // clearance has a disjoint scope. Proofs additionally bind both policies and
    // the original request target, including its query (never echoed in HTML).
    fn mac(&self, b: &Binding<'_>, purpose: &str, body: &str) -> Result<String> {
        let global = serde_json::to_string(&b.global)?;
        let local = serde_json::to_string(&b.local)?;
        let ip = openwaf_config::normalized_ip(b.ip).to_string();
        let version = b.version.to_string();
        let (route, target, policy) = match purpose {
            "global" => ("", "", global.clone()),
            "route" => (b.route, "", local.clone()),
            _ => (b.route, b.target, format!("{global}:{local}")),
        };
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        for part in [
            "openwaf-pow-v1",
            b.authority,
            &version,
            &ip,
            purpose,
            route,
            target,
            &policy,
            body,
        ] {
            signer.update(part.as_bytes())?;
            signer.update(&[0])?;
        }
        Ok(hex(&signer.sign_to_vec()?))
    }
    fn token(&self, b: &Binding<'_>, purpose: &str, issued: u64, seconds: u32) -> Result<String> {
        let body = format!(
            "{issued}.{}.{}",
            issued.saturating_add(u64::from(seconds) * 1000),
            nonce()?
        );
        Ok(format!("{body}.{}", self.mac(b, purpose, &body)?))
    }
    fn valid(
        &self,
        b: &Binding<'_>,
        purpose: &str,
        token: &str,
        seconds: u32,
        now: u64,
    ) -> Option<u64> {
        if token.len() > 256 {
            return None;
        }
        let (body, mac) = token.rsplit_once('.')?;
        let mut parts = body.split('.');
        let issued = parts.next()?.parse::<u64>().ok()?;
        let expiry = parts.next()?.parse::<u64>().ok()?;
        let nonce = parts.next()?;
        if parts.next().is_some()
            || nonce.len() != 48
            || !nonce.bytes().all(|v| v.is_ascii_hexdigit())
            || issued > now
            || expiry <= now
            || expiry.checked_sub(issued)? != u64::from(seconds) * 1000
        {
            return None;
        }
        let expected = self.mac(b, purpose, body).ok()?;
        (mac.len() == expected.len() && openssl::memcmp::eq(mac.as_bytes(), expected.as_bytes()))
            .then_some(issued)
    }
    pub fn cleared(&self, b: &Binding<'_>, headers: &HeaderMap, now: u64) -> bool {
        [("global", b.global), ("route", b.local)]
            .into_iter()
            .all(|(purpose, policy)| {
                policy.is_none_or(|policy| {
                    let scope = if purpose == "global" {
                        "global".to_owned()
                    } else {
                        format!("route-{}", b.route)
                    };
                    cookie(headers, &cookie_name(&scope)).is_some_and(|v| {
                        self.valid(b, purpose, &v, policy.clearance_seconds, now)
                            .is_some()
                    })
                })
            })
    }
    pub fn page(&self, b: &Binding<'_>, now: u64) -> Result<Page> {
        let token = self.token(b, "proof", now, PROOF_SECONDS)?;
        let nonce = nonce()?;
        Ok(Page {
            body: include_str!("challenge.html")
                .replace("{{nonce}}", &nonce)
                .replace("{{token}}", &token)
                .replace("{{context}}", &self.mac(b, "proof", "")?)
                .replace("{{difficulty}}", &b.difficulty().to_string()),
            nonce,
            cookie: set_cookie(PENDING, &token, PROOF_SECONDS),
        })
    }
    pub fn verify(
        &self,
        b: &Binding<'_>,
        headers: &HeaderMap,
        proof: &Proof,
        now: u64,
    ) -> Option<u64> {
        if proof.counter > MAX_COUNTER || proof.token.len() > 256 {
            return None;
        }
        let pending = cookie(headers, PENDING)?;
        if pending.len() != proof.token.len()
            || !openssl::memcmp::eq(pending.as_bytes(), proof.token.as_bytes())
        {
            return None;
        }
        // Browser's custom same-origin GET cannot be submitted by cross-site
        // HTML forms. Reject cross-site Fetch Metadata and any foreign Origin.
        if headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) != Some("same-origin") {
            return None;
        }
        if let Some(origin) = headers.get("origin") {
            let origin = origin.to_str().ok()?.parse::<http::Uri>().ok()?;
            if origin.scheme_str() != Some("https")
                || origin.authority()?.as_str() != b.authority
                || origin.path() != "/"
                || origin.query().is_some()
            {
                return None;
            }
        }
        let issued = self.valid(b, "proof", &proof.token, PROOF_SECONDS, now)?;
        if [b.global, b.local].into_iter().flatten().any(|p| {
            issued.saturating_add(u64::from(p.clearance_seconds) * 1000) <= now.saturating_add(1000)
        }) {
            return None;
        }
        let hash = openssl::sha::sha256(format!("{}.{}", proof.token, proof.counter).as_bytes());
        let difficulty = b.difficulty();
        if difficulty == 0 || difficulty > 20 {
            return None;
        }
        let zero = usize::from(difficulty / 8);
        if hash[..zero].iter().any(|v| *v != 0)
            || (!difficulty.is_multiple_of(8) && hash[zero] >> (8 - difficulty % 8) != 0)
        {
            return None;
        }
        Some(issued)
    }
    pub fn success(&self, b: &Binding<'_>, issued: u64, now: u64) -> Result<Vec<String>> {
        let mut cookies = vec![set_cookie(PENDING, "", 0)];
        for (purpose, policy) in [("global", b.global), ("route", b.local)] {
            if let Some(policy) = policy {
                let scope = if purpose == "global" {
                    "global".to_owned()
                } else {
                    format!("route-{}", b.route)
                };
                // Replaying the bounded proof never renews clearance from "now".
                let remaining = issued
                    .saturating_add(u64::from(policy.clearance_seconds) * 1000)
                    .saturating_sub(now)
                    / 1000;
                cookies.push(set_cookie(
                    &cookie_name(&scope),
                    &self.token(b, purpose, issued, policy.clearance_seconds)?,
                    remaining as u32,
                ));
            }
        }
        Ok(cookies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding<'static> {
        Binding {
            authority: "app.test:8443",
            version: 1,
            ip: "192.0.2.1".parse().expect("IP"),
            route: "app",
            target: "/private?x=redacted",
            global: Some(Challenge {
                difficulty: 8,
                clearance_seconds: 300,
            }),
            local: Some(Challenge {
                difficulty: 9,
                clearance_seconds: 60,
            }),
        }
    }
    fn solve(gate: &Gate, b: &Binding<'_>, now: u64) -> (HeaderMap, Proof) {
        let page = gate.page(b, now).expect("page");
        assert!(!page.body.contains(b.target));
        let token = page
            .cookie
            .split(';')
            .next()
            .expect("pair")
            .split_once('=')
            .expect("token")
            .1
            .to_owned();
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            format!("{PENDING}={token}").parse().expect("cookie"),
        );
        headers.insert("sec-fetch-site", "same-origin".parse().expect("site"));
        let counter = (0..=MAX_COUNTER)
            .find(|counter| {
                gate.verify(
                    b,
                    &headers,
                    &Proof {
                        token: token.clone(),
                        counter: *counter,
                    },
                    now,
                )
                .is_some()
            })
            .expect("solution");
        (headers, Proof { token, counter })
    }
    fn cookies(values: &[String]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            values
                .iter()
                .map(|v| v.split(';').next().expect("pair"))
                .collect::<Vec<_>>()
                .join("; ")
                .parse()
                .expect("cookies"),
        );
        headers
    }
    #[test]
    fn proof_is_bound_to_host_ip_version_route_target_policy_cookie_and_expiry() {
        let gate = Gate::new().expect("gate");
        let b = binding();
        let now = 1_000_000;
        let (headers, proof) = solve(&gate, &b, now);
        assert_eq!(gate.verify(&b, &headers, &proof, now + 1), Some(now));
        assert!(gate.verify(&b, &headers, &proof, now - 1).is_none());
        assert!(gate.verify(&b, &headers, &proof, now + 120_000).is_none());
        assert!(
            gate.verify(
                &b,
                &headers,
                &Proof {
                    token: proof.token.clone(),
                    counter: MAX_COUNTER + 1
                },
                now
            )
            .is_none()
        );
        for changed in [
            Binding {
                authority: "other.test",
                ..binding()
            },
            Binding {
                ip: "192.0.2.2".parse().expect("IP"),
                ..binding()
            },
            Binding {
                version: 2,
                ..binding()
            },
            Binding {
                route: "other",
                ..binding()
            },
            Binding {
                target: "/elsewhere",
                ..binding()
            },
            Binding {
                local: None,
                ..binding()
            },
        ] {
            assert!(gate.verify(&changed, &headers, &proof, now).is_none());
        }
        let mut invalid = headers.clone();
        invalid.remove("cookie");
        assert!(gate.verify(&b, &invalid, &proof, now).is_none());
        invalid = headers.clone();
        invalid.append("cookie", headers["cookie"].clone());
        assert!(gate.verify(&b, &invalid, &proof, now).is_none());
        invalid = headers.clone();
        invalid.insert("origin", "https://evil.test".parse().expect("origin"));
        assert!(gate.verify(&b, &invalid, &proof, now).is_none());
        invalid = headers.clone();
        invalid.insert("sec-fetch-site", "cross-site".parse().expect("site"));
        assert!(gate.verify(&b, &invalid, &proof, now).is_none());
        let mut tampered = proof;
        tampered.token.push('0');
        assert!(gate.verify(&b, &headers, &tampered, now).is_none());
    }
    #[test]
    fn clearance_scopes_expiry_restart_and_proof_replay_do_not_extend_session() {
        let gate = Gate::new().expect("gate");
        let b = binding();
        let now = 1_000_000;
        let (pending, proof) = solve(&gate, &b, now);
        let issued = gate.verify(&b, &pending, &proof, now).expect("proof");
        let values = gate.success(&b, issued, now + 1000).expect("clearance");
        assert!(
            values
                .iter()
                .all(|v| v.contains("Secure; HttpOnly; SameSite=Strict"))
        );
        let headers = cookies(&values);
        assert!(gate.cleared(&b, &headers, now + 1001));
        assert!(!gate.cleared(&b, &headers, now + 60_000));
        assert!(!gate.cleared(
            &Binding {
                version: 2,
                ..binding()
            },
            &headers,
            now + 1
        ));
        assert!(!Gate::new().expect("restart").cleared(&b, &headers, now + 1));
        let other = Binding {
            route: "other",
            local: None,
            ..binding()
        };
        assert!(
            gate.cleared(&other, &headers, now + 1),
            "global clearance should cover another route"
        );
        assert!(
            !gate.cleared(
                &Binding {
                    local: b.local,
                    ..other
                },
                &headers,
                now + 1
            ),
            "global cookie bypassed route challenge"
        );
        let replayed = cookies(&gate.success(&b, issued, now + 30_000).expect("replay"));
        assert!(!gate.cleared(&b, &replayed, now + 60_000));
        assert!(gate.verify(&b, &pending, &proof, now + 60_000).is_none());
        let mut stripped = headers.clone();
        stripped.append("cookie", "application=ok".parse().expect("cookie"));
        stripped.insert(HEADER, "sensitive".parse().expect("header"));
        strip_cookies(&mut stripped);
        assert_eq!(stripped["cookie"], "application=ok");
        assert!(!stripped.contains_key(HEADER));
    }
    #[test]
    fn challenge_page_negotiation_recovers_ambiguous_gets_but_preserves_api_and_streams() {
        let mut headers = HeaderMap::new();
        assert!(wants_page(&headers));
        for accept in [
            "*/*",
            "text/*",
            "text/html",
            "TEXT/HTML; charset=utf-8",
            "text/html,application/xhtml+xml,*/*;q=0.8",
        ] {
            headers.insert("accept", accept.parse().expect("accept"));
            assert!(wants_page(&headers), "{accept}");
        }
        for accept in [
            "application/json",
            "application/problem+json,*/*",
            "text/event-stream",
            "text/event-stream,*/*",
            "image/avif,*/*",
            "text/html;q=0,*/*",
            "text/*;q=0,*/*",
            "*/*;q=0",
            "text/html;q=bogus",
            "text/html;q=NaN",
            "text/html;q=2",
        ] {
            headers.insert("accept", accept.parse().expect("accept"));
            assert!(!wants_page(&headers), "{accept}");
        }
        headers.insert("accept", "*/*".parse().expect("accept"));
        for destination in [
            "script",
            "style",
            "image",
            "worker",
            "serviceworker",
            "iframe",
        ] {
            headers.insert("sec-fetch-dest", destination.parse().expect("destination"));
            assert!(!wants_page(&headers));
        }
        for destination in ["document", "empty"] {
            headers.insert("sec-fetch-dest", destination.parse().expect("destination"));
            assert!(wants_page(&headers));
        }
        headers.insert("upgrade", "websocket".parse().expect("upgrade"));
        assert!(!wants_page(&headers));
    }
    #[test]
    fn challenge_work_is_rate_bounded() {
        let gate = Gate::new().expect("gate");
        let ip = binding().ip;
        for _ in 0..12 {
            assert_eq!(gate.limit(ip), Verdict::Allow);
        }
        assert!(matches!(gate.limit(ip), Verdict::Limited(_)));
    }
}
