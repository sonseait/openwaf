//! Verified ForwardAuth quotas. Raw identity is borrowed only while deriving a
//! process-keyed digest; it never enters retained state, diagnostics or logs.
use crate::traffic::Verdict;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use openwaf_config::middleware::{ForwardAuth, IdentityRateLimit};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
const MAX_KEYS: usize = 4096;
const ROUTE_KEYS: usize = 128;
const CREDIT: u128 = 1_000_000_000;
type Key = ([u8; 32], u32, u32);
struct Bucket {
    credits: u128,
    updated: Instant,
    used: Instant,
    ttl: Duration,
    scope: [u8; 32],
}
pub struct Limiter {
    key: PKey<openssl::pkey::Private>,
    debits: std::sync::atomic::AtomicU64,
    state: Mutex<HashMap<Key, Bucket>>,
}
impl Limiter {
    pub fn new() -> anyhow::Result<Self> {
        let mut secret = zeroize::Zeroizing::new([0; 32]);
        openssl::rand::rand_bytes(secret.as_mut())?;
        Ok(Self {
            key: PKey::hmac(secret.as_ref())?,
            debits: Default::default(),
            state: Mutex::new(HashMap::new()),
        })
    }
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({"max_keys":MAX_KEYS,"per_route":ROUTE_KEYS,"keys":self.state.try_lock().ok().map(|s|s.len()),"debited_requests":self.debits.load(std::sync::atomic::Ordering::Relaxed),"reset":"process_restart"})
    }
    fn digest(&self, fields: &[&[u8]]) -> Option<[u8; 32]> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).ok()?;
        for field in fields {
            signer.update(&(field.len() as u64).to_be_bytes()).ok()?;
            signer.update(field).ok()?;
        }
        signer.sign_to_vec().ok()?.try_into().ok()
    }
    /// Call exclusively after successful ForwardAuth. Auth upstream, path and
    /// approved header namespace the principal. Policy apply retains unchanged
    /// quotas; changed policies have separate bounded buckets. Restart resets.
    pub fn check(
        &self,
        route: &str,
        auth: &ForwardAuth,
        quota: &IdentityRateLimit,
        identity: Option<&[u8]>,
        now: Instant,
    ) -> Verdict {
        if !auth.identity_headers.contains(&quota.header)
            || route.len() > 64
            || !(1..=10000).contains(&quota.per_second)
            || !(1..=10000).contains(&quota.burst)
        {
            return Verdict::Unavailable;
        }
        if identity.is_some_and(|v| v.is_empty() || v.len() > 1024) {
            return Verdict::Unavailable;
        }
        let Some(identity) = identity else {
            return if quota.require_identity {
                Verdict::Deny
            } else {
                Verdict::Allow
            };
        };
        let Some(scope) = self.digest(&[route.as_bytes()]) else {
            return Verdict::Unavailable;
        };
        let Some(digest) = self.digest(&[
            route.as_bytes(),
            auth.upstream.as_bytes(),
            auth.path.as_bytes(),
            quota.header.as_bytes(),
            identity,
        ]) else {
            return Verdict::Unavailable;
        };
        let Ok(mut state) = self.state.try_lock() else {
            return Verdict::Unavailable;
        };
        // At most 4096 entries examined; no attacker-sized cleanup or eviction
        // of depleted live buckets. Expiry always exceeds full refill duration.
        state.retain(|_, b| now.saturating_duration_since(b.used) < b.ttl);
        let key = (digest, quota.per_second, quota.burst);
        if !state.contains_key(&key)
            && (state.len() >= MAX_KEYS
                || state.values().filter(|b| b.scope == scope).count() >= ROUTE_KEYS)
        {
            return Verdict::Unavailable;
        }
        let full = u128::from(quota.burst) * CREDIT;
        let b = state.entry(key).or_insert(Bucket {
            credits: full,
            updated: now,
            used: now,
            ttl: Duration::from_secs(
                60.max(u64::from(quota.burst).div_ceil(u64::from(quota.per_second))),
            ),
            scope,
        });
        b.credits = full.min(
            b.credits.saturating_add(
                now.saturating_duration_since(b.updated)
                    .as_nanos()
                    .saturating_mul(u128::from(quota.per_second)),
            ),
        );
        b.updated = now;
        b.used = now;
        if b.credits >= CREDIT {
            b.credits -= CREDIT;
            self.debits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Verdict::Allow
        } else {
            Verdict::Limited(1)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> (ForwardAuth, IdentityRateLimit) {
        (
            ForwardAuth {
                upstream: "auth".into(),
                identity_headers: vec!["remote-user".into()],
                ..Default::default()
            },
            IdentityRateLimit {
                header: "remote-user".into(),
                per_second: 1,
                burst: 1,
                require_identity: false,
            },
        )
    }
    #[test]
    fn nat_rotation_sources_reload_ttl_and_missing() {
        let l = Limiter::new().unwrap();
        let (mut a, mut q) = policy();
        let n = Instant::now();
        assert_eq!(l.check("r", &a, &q, Some(b"alice"), n), Verdict::Allow);
        assert_eq!(l.check("r", &a, &q, Some(b"bob"), n), Verdict::Allow); // NAT independent
        assert_eq!(l.check("r", &a, &q, Some(b"alice"), n), Verdict::Limited(1)); // rotation/apply no reset
        q.per_second = 2;
        assert_eq!(l.check("r", &a, &q, Some(b"alice"), n), Verdict::Allow);
        q.per_second = 1;
        assert_eq!(l.check("r", &a, &q, Some(b"alice"), n), Verdict::Limited(1));
        a.path = "/different-source".into();
        assert_eq!(l.check("r", &a, &q, Some(b"alice"), n), Verdict::Allow);
        assert_eq!(l.check("r", &a, &q, None, n), Verdict::Allow);
        q.require_identity = true;
        assert_eq!(l.check("r", &a, &q, None, n), Verdict::Deny);
        assert_eq!(
            l.check("r", &a, &q, Some(b"alice"), n + Duration::from_secs(61)),
            Verdict::Allow
        );
    }
    #[test]
    fn churn_cap_and_try_lock_fail_closed() {
        let l = Limiter::new().unwrap();
        let (a, q) = policy();
        let n = Instant::now();
        for i in 0..ROUTE_KEYS {
            assert_eq!(
                l.check("r", &a, &q, Some(i.to_string().as_bytes()), n),
                Verdict::Allow
            );
        }
        assert_eq!(
            l.check("r", &a, &q, Some(b"extra"), n),
            Verdict::Unavailable
        );
        let guard = l.state.lock().unwrap();
        assert_eq!(l.check("r", &a, &q, Some(b"0"), n), Verdict::Unavailable);
        drop(guard);
        assert_eq!(
            l.check("r", &a, &q, Some(b"extra"), n + Duration::from_secs(61)),
            Verdict::Allow
        );
    }
    #[test]
    fn malformed_verified_identity_cannot_use_missing_identity_fallback() {
        let limiter = Limiter::new().unwrap();
        let (auth, quota) = policy();
        for identity in [vec![], vec![b'x'; 1025]] {
            assert_eq!(
                limiter.check("r", &auth, &quota, Some(&identity), Instant::now()),
                Verdict::Unavailable
            );
        }
    }

    #[test]
    #[ignore = "explicit release-mode capacity measurement; prints local timings"]
    #[allow(clippy::assertions_on_constants)] // Runtime guard: debug suites must still compile.
    fn release_max_key_latency_and_expiry_recovery() {
        assert!(!cfg!(debug_assertions), "run with cargo test --release");
        let limiter = Limiter::new().unwrap();
        let (auth, mut quota) = policy();
        quota.per_second = 10000;
        quota.burst = 10000;
        let now = Instant::now();
        for route in 0..(MAX_KEYS / ROUTE_KEYS) {
            for identity in 0..ROUTE_KEYS {
                assert_eq!(
                    limiter.check(
                        &format!("r{route}"),
                        &auth,
                        &quota,
                        Some(identity.to_string().as_bytes()),
                        now
                    ),
                    Verdict::Allow
                );
            }
        }
        assert_eq!(limiter.stats()["keys"], MAX_KEYS);
        assert_eq!(
            limiter.check("new", &auth, &quota, Some(b"new"), now),
            Verdict::Unavailable
        );
        // Fixed logical time prevents expiry/refill from hiding saturation costs.
        let mut timings = Vec::with_capacity(20000);
        let started = Instant::now();
        for i in 0..20000 {
            let identity = (i % ROUTE_KEYS).to_string();
            let before = Instant::now();
            let verdict = limiter.check("r0", &auth, &quota, Some(identity.as_bytes()), now);
            timings.push(before.elapsed().as_nanos());
            assert_eq!(verdict, Verdict::Allow);
        }
        let elapsed = started.elapsed();
        timings.sort_unstable();
        println!(
            "principal capacity: keys={MAX_KEYS} samples={} elapsed_ms={} p50_ns={} p95_ns={} p99_ns={} max_ns={}",
            timings.len(),
            elapsed.as_millis(),
            timings[10000],
            timings[19000],
            timings[19800],
            timings[19999]
        );
        assert_eq!(limiter.stats()["keys"], MAX_KEYS);
        let before = Instant::now();
        assert_eq!(
            limiter.check(
                "new",
                &auth,
                &quota,
                Some(b"new"),
                now + Duration::from_secs(61)
            ),
            Verdict::Allow
        );
        println!(
            "principal expiry recovery: elapsed_ns={} keys={}",
            before.elapsed().as_nanos(),
            limiter.stats()["keys"]
        );
        assert_eq!(limiter.stats()["keys"], 1);
    }
}
