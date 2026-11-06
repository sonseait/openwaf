//! Password-only route gate. No storage I/O; fixed-cost Argon2 runs in bounded
//! blocking jobs whose permits survive cancellation. Sessions are host/route/policy
//! bound signed cookies, invalidated by password rotation and process restart.
use anyhow::{Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use http::HeaderMap;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use openwaf_config::Route;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const PREFIX: &str = openwaf_config::password::LOGIN_PREFIX;
pub struct Gate {
    key: PKey<openssl::pkey::Private>,
    workers: Arc<tokio::sync::Semaphore>,
    attempts: Mutex<Attempts>,
}
struct Attempts {
    started: Instant,
    total: u16,
    clients: BTreeMap<IpAddr, u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub password: String,
    pub csrf: String,
    pub return_path: String,
}
impl Drop for Login {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub cookies: Vec<String>,
    pub location: Option<String>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn nonce() -> Result<String> {
    let mut b = [0; 32];
    openssl::rand::rand_bytes(&mut b)?;
    Ok(hex(&b))
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut result = None;
    for header in headers.get_all("cookie") {
        for part in header.to_str().ok()?.split(';') {
            if let Some((key, value)) = part.trim().split_once('=')
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
pub fn strip_cookies(headers: &mut HeaderMap) {
    let values: Vec<_> = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|v| !v.starts_with("__Host-openwaf-pw-") && !v.starts_with("__Host-openwaf-csrf-"))
        .filter(|v| !v.is_empty())
        .collect();
    let value = values.join("; ");
    headers.remove("cookie");
    if let Ok(value) = http::HeaderValue::from_str(&value)
        && !value.is_empty()
    {
        headers.insert("cookie", value);
    }
}
impl Gate {
    pub fn new() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(bytes.as_mut())?;
        Ok(Self {
            key: PKey::hmac(bytes.as_ref())?,
            workers: Arc::new(tokio::sync::Semaphore::new(2)),
            attempts: Mutex::new(Attempts {
                started: Instant::now(),
                total: 0,
                clients: BTreeMap::new(),
            }),
        })
    }
    fn mac(
        &self,
        host: &str,
        route: &Route,
        purpose: &str,
        target: &str,
        body: &str,
    ) -> Result<String> {
        let policy = route
            .password_protect
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("password gate disabled"))?;
        let mut s = Signer::new(MessageDigest::sha256(), &self.key)?;
        for part in [
            "openwaf-route-password-v1",
            host,
            &route.id,
            &route.hostname,
            &route.path,
            &policy.sealed_verifier,
            &policy.session_seconds.to_string(),
            purpose,
            target,
            body,
        ] {
            s.update(part.as_bytes())?;
            s.update(&[0])?;
        }
        Ok(hex(&s.sign_to_vec()?))
    }
    fn token(
        &self,
        host: &str,
        route: &Route,
        purpose: &str,
        target: &str,
        lifetime: u32,
        now: u64,
    ) -> Result<String> {
        let body = format!(
            "{now}.{}.{}",
            now.saturating_add(u64::from(lifetime) * 1000),
            nonce()?
        );
        Ok(format!(
            "{body}.{}",
            self.mac(host, route, purpose, target, &body)?
        ))
    }
    fn valid(
        &self,
        host: &str,
        route: &Route,
        purpose: &str,
        target: &str,
        token: &str,
        now: u64,
    ) -> bool {
        if token.len() > 256 {
            return false;
        }
        let Some((body, mac)) = token.rsplit_once('.') else {
            return false;
        };
        let parts: Vec<_> = body.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        let (Ok(issued), Ok(expiry)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) else {
            return false;
        };
        let lifetime = if purpose == "csrf" {
            600
        } else {
            route
                .password_protect
                .as_ref()
                .map_or(0, |p| p.session_seconds)
        };
        if issued > now
            || expiry <= now
            || expiry.saturating_sub(issued) != u64::from(lifetime) * 1000
        {
            return false;
        }
        self.mac(host, route, purpose, target, body)
            .is_ok_and(|expected| {
                expected.len() == mac.len()
                    && openssl::memcmp::eq(expected.as_bytes(), mac.as_bytes())
            })
    }
    pub fn authenticated(&self, host: &str, route: &Route, headers: &HeaderMap, now: u64) -> bool {
        cookie(headers, &format!("__Host-openwaf-pw-{}", route.id))
            .is_some_and(|v| self.valid(host, route, "session", "", &v, now))
    }
    pub fn page(
        &self,
        host: &str,
        route: &Route,
        path: &str,
        now: u64,
        invalid: bool,
    ) -> Result<Reply> {
        let token = self.token(host, route, "csrf", path, 600, now)?;
        Ok(Reply {
            status: 401,
            location: None,
            cookies: vec![format!(
                "__Host-openwaf-csrf-{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600",
                route.id
            )],
            body: include_str!("password_login.html")
                .replace("{{action}}", &format!("{PREFIX}{}", route.id))
                .replace("{{csrf}}", &token)
                .replace("{{path}}", &escape(path))
                .replace(
                    "{{message}}",
                    if invalid {
                        "Incorrect password. Try again."
                    } else {
                        "Enter the shared password to access this application."
                    },
                ),
        })
    }
    pub fn limit(&self, ip: IpAddr) -> std::result::Result<(), u16> {
        let mut attempts = self.attempts.try_lock().map_err(|_| 503u16)?;
        if attempts.started.elapsed() >= Duration::from_secs(60) {
            attempts.started = Instant::now();
            attempts.total = 0;
            attempts.clients.clear();
        }
        if attempts.total >= 120 || attempts.clients.get(&ip).copied().unwrap_or(0) >= 5 {
            return Err(429);
        }
        if attempts.clients.len() >= 4096 && !attempts.clients.contains_key(&ip) {
            return Err(503);
        }
        attempts.total += 1;
        *attempts.clients.entry(ip).or_default() += 1;
        Ok(())
    }
    pub fn csrf_valid(
        &self,
        host: &str,
        authority: &str,
        route: &Route,
        headers: &HeaderMap,
        input: &Login,
        now: u64,
    ) -> bool {
        let origin = headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<http::Uri>().ok());
        if !origin.is_some_and(|o| {
            o.scheme_str() == Some("https")
                && o.authority()
                    .is_some_and(|a| a.as_str().eq_ignore_ascii_case(authority))
                && o.path() == "/"
                && o.query().is_none()
        }) {
            return false;
        }
        cookie(headers, &format!("__Host-openwaf-csrf-{}", route.id)).is_some_and(|v| {
            v.len() == input.csrf.len() && openssl::memcmp::eq(v.as_bytes(), input.csrf.as_bytes())
        }) && self.valid(host, route, "csrf", &input.return_path, &input.csrf, now)
    }
    pub async fn verify(
        &self,
        mut input: Login,
        verifier: Arc<Zeroizing<String>>,
    ) -> std::result::Result<bool, u16> {
        if input.password.is_empty() || input.password.len() > 128 {
            return Err(422);
        }
        let permit = self
            .workers
            .clone()
            .try_acquire_owned()
            .map_err(|_| 503u16)?;
        let password = Zeroizing::new(std::mem::take(&mut input.password));
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                PasswordHash::new(verifier.as_str()).is_ok_and(|h| {
                    Argon2::default()
                        .verify_password(password.as_bytes(), &h)
                        .is_ok()
                })
            }),
        )
        .await
        .map_err(|_| 503u16)?
        .map_err(|_| 503u16)
    }
    pub fn success(&self, host: &str, route: &Route, path: &str, now: u64) -> Result<Reply> {
        ensure!(
            openwaf_config::canonical_path(path).is_ok() && !path.starts_with(PREFIX),
            "invalid return path"
        );
        let lifetime = route
            .password_protect
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("password gate disabled"))?
            .session_seconds;
        let token = self.token(host, route, "session", "", lifetime, now)?;
        Ok(Reply {
            status: 303,
            body: String::new(),
            location: Some(path.to_owned()),
            cookies: vec![
                format!(
                    "__Host-openwaf-pw-{}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={lifetime}",
                    route.id
                ),
                format!(
                    "__Host-openwaf-csrf-{}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
                    route.id
                ),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route() -> Route {
        serde_json::from_value(serde_json::json!({"id":"app","hostname":"app.test","path":"/","path_match":"prefix","password_protect":{"sealed_verifier":"ab".repeat(128),"session_seconds":300}})).expect("route")
    }
    #[test]
    fn sessions_are_bound_to_host_route_policy_expiry_and_process() {
        let gate = Gate::new().expect("gate");
        let mut route = route();
        let now = 1000000;
        let reply = gate.success("app.test", &route, "/", now).expect("session");
        let value = reply.cookies[0].split(';').next().expect("cookie");
        let mut headers = HeaderMap::new();
        headers.insert("cookie", value.parse().expect("header"));
        assert!(gate.authenticated("app.test", &route, &headers, now + 1));
        assert!(!gate.authenticated("other.test", &route, &headers, now + 1));
        assert!(!gate.authenticated("app.test", &route, &headers, now - 1));
        assert!(!gate.authenticated("app.test", &route, &headers, now + 300000));
        assert!(!Gate::new().expect("restart").authenticated(
            "app.test",
            &route,
            &headers,
            now + 1
        ));
        route
            .password_protect
            .as_mut()
            .expect("policy")
            .sealed_verifier = "cd".repeat(128);
        assert!(!gate.authenticated("app.test", &route, &headers, now + 1));
        route = tests::route();
        route.id = "other".into();
        assert!(!gate.authenticated("app.test", &route, &headers, now + 1));
        assert!(
            gate.success("app.test", &route, "//outside.test/", now)
                .is_err()
        );
    }
    #[test]
    fn csrf_origin_double_submit_and_return_path_are_required() {
        let gate = Gate::new().expect("gate");
        let route = route();
        let now = 1000000;
        let page = gate
            .page("app.test", &route, "/private", now, false)
            .expect("page");
        let cookie = page.cookies[0].split(';').next().expect("cookie");
        let token = cookie.split_once('=').expect("token").1;
        let mut input = Login {
            password: String::new(),
            csrf: token.into(),
            return_path: "/private".into(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().expect("header"));
        headers.insert("origin", "https://app.test:8443".parse().expect("origin"));
        assert!(gate.csrf_valid(
            "app.test",
            "app.test:8443",
            &route,
            &headers,
            &input,
            now + 1
        ));
        input.return_path = "/other".into();
        assert!(!gate.csrf_valid(
            "app.test",
            "app.test:8443",
            &route,
            &headers,
            &input,
            now + 1
        ));
        input.return_path = "/private".into();
        for origin in [
            "https://evil.test",
            "null",
            "http://app.test:8443",
            "https://app.test",
        ] {
            headers.insert("origin", origin.parse().expect("origin"));
            assert!(!gate.csrf_valid(
                "app.test",
                "app.test:8443",
                &route,
                &headers,
                &input,
                now + 1
            ));
        }
        headers.remove("origin");
        assert!(!gate.csrf_valid(
            "app.test",
            "app.test:8443",
            &route,
            &headers,
            &input,
            now + 1
        ));
        headers.insert("origin", "https://app.test:8443".parse().expect("origin"));
        headers.remove("cookie");
        assert!(!gate.csrf_valid(
            "app.test",
            "app.test:8443",
            &route,
            &headers,
            &input,
            now + 1
        ));
    }
    #[test]
    fn limiter_and_cookie_filter_are_bounded() {
        let gate = Gate::new().expect("gate");
        let ip = "192.0.2.1".parse().expect("ip");
        for _ in 0..5 {
            assert!(gate.limit(ip).is_ok());
        }
        assert_eq!(gate.limit(ip), Err(429));
        let mut headers = HeaderMap::new();
        headers.append(
            "cookie",
            "application=ok; __Host-openwaf-pw-app=private"
                .parse()
                .expect("header"),
        );
        headers.append(
            "cookie",
            "__Host-openwaf-csrf-app=secret; another=ok"
                .parse()
                .expect("header"),
        );
        strip_cookies(&mut headers);
        assert_eq!(headers["cookie"], "application=ok; another=ok");
    }
}
