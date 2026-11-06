//! In-memory GeoIP and bounded traffic admission, independent of CrowdSec I/O.
use anyhow::{Context, Result, ensure};
use maxminddb::{Reader, geoip2};
use openwaf_config::access::RateLimit;
use std::{
    collections::HashMap,
    io::Read,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct CountryDb(Reader<Vec<u8>>);
impl CountryDb {
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .context("open GeoIP country database")?;
        ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() <= 64 * 1024 * 1024,
            "GeoIP database must be a bounded regular file"
        );
        let mut bytes = Vec::new();
        file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 64 * 1024 * 1024, "GeoIP database too large");
        let reader = Reader::from_source(bytes).context("parse GeoIP database")?;
        ensure!(
            matches!(
                reader.metadata.database_type.as_str(),
                "GeoIP2-Country" | "GeoLite2-Country"
            ),
            "GeoIP requires a country database"
        );
        Ok(Self(reader))
    }
    pub fn country(&self, ip: IpAddr) -> Result<Option<&str>> {
        match self
            .0
            .lookup::<geoip2::Country<'_>>(openwaf_config::normalized_ip(ip))
        {
            Ok(record) => Ok(record.country.and_then(|country| country.iso_code)),
            Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => Ok(None),
            Err(_) => anyhow::bail!("GeoIP country lookup failed"),
        }
    }
}

pub const MAX_RATE_KEYS: usize = 4096;
const CREDIT: u128 = 1_000_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Limited(u64),
    Unavailable,
}
struct Bucket {
    credits: u128,
    updated: Instant,
    used: Instant,
    ttl: Duration,
}
struct State {
    buckets: HashMap<(String, u32, u32, IpAddr), Bucket>,
    cleaned: Instant,
    rejected: u64,
    peak: usize,
}
/// Class sharding isolates critical state/lock capacity from bulk churn. Within
/// each class a route gets at most 128 keys; no LRU eviction of depleted buckets.
pub struct Limiter {
    shard_capacity: usize,
    scope_capacity: usize,
    states: [Mutex<State>; 4],
    contention: std::sync::atomic::AtomicU64,
}
impl Default for Limiter {
    fn default() -> Self {
        Self {
            shard_capacity: MAX_RATE_KEYS / 4,
            scope_capacity: 128,
            states: std::array::from_fn(|_| {
                Mutex::new(State {
                    buckets: HashMap::new(),
                    cleaned: Instant::now(),
                    rejected: 0,
                    peak: 0,
                })
            }),
            contention: Default::default(),
        }
    }
}
impl Limiter {
    /// Dedicated global scope, shared across route admission classes, with the
    /// same total key budget as a route limiter but no per-route subdivision.
    pub fn global() -> Self {
        Self {
            shard_capacity: MAX_RATE_KEYS,
            scope_capacity: MAX_RATE_KEYS,
            ..Self::default()
        }
    }

    /// Identity is (class, stable route ID, exact rate policy, normalized client).
    /// Unchanged policies retain state through reorder/apply/rollback. A changed
    /// rate policy gets separate buckets; switching back resumes unexpired state.
    pub fn check(
        &self,
        class: openwaf_config::traffic::Class,
        route: &str,
        ip: IpAddr,
        limit: RateLimit,
        now: Instant,
    ) -> Verdict {
        if route.len() > 64
            || !(1..=10000).contains(&limit.per_second)
            || !(1..=10000).contains(&limit.burst)
        {
            return Verdict::Unavailable;
        }
        let Ok(mut state) = self.states[class.index()].try_lock() else {
            self.contention
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Verdict::Unavailable;
        };
        if now.saturating_duration_since(state.cleaned) >= Duration::from_secs(1) {
            state
                .buckets
                .retain(|_, bucket| now.saturating_duration_since(bucket.used) < bucket.ttl);
            state.cleaned = now;
        }
        let key = (
            route.to_owned(),
            limit.per_second,
            limit.burst,
            openwaf_config::normalized_ip(ip),
        );
        // Route cap includes all policy generations. Policy churn cannot grow the
        // route's share; old buckets expire only after their refill-safe TTL.
        if !state.buckets.contains_key(&key)
            && (state.buckets.len() >= self.shard_capacity
                || state
                    .buckets
                    .keys()
                    .filter(|(id, _, _, _)| id == route)
                    .count()
                    >= self.scope_capacity)
        {
            state.rejected += 1;
            return Verdict::Unavailable;
        }
        let full = limit.burst as u128 * CREDIT;
        let bucket = state.buckets.entry(key).or_insert_with(|| Bucket {
            credits: full,
            updated: now,
            used: now,
            ttl: Duration::from_secs(
                60.max((limit.burst as u64).div_ceil(limit.per_second as u64)),
            ),
        });
        let refill = now
            .saturating_duration_since(bucket.updated)
            .as_nanos()
            .saturating_mul(limit.per_second as u128);
        bucket.credits = bucket.credits.saturating_add(refill).min(full);
        bucket.updated = now;
        bucket.used = now;
        let verdict = if bucket.credits >= CREDIT {
            bucket.credits -= CREDIT;
            Verdict::Allow
        } else {
            Verdict::Limited(
                (CREDIT - bucket.credits)
                    .div_ceil(limit.per_second as u128 * CREDIT)
                    .max(1) as u64,
            )
        };
        state.peak = state.peak.max(state.buckets.len());
        verdict
    }
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({"max_keys":MAX_RATE_KEYS,"per_class":self.shard_capacity,"per_route":self.scope_capacity,"contention_total":self.contention.load(std::sync::atomic::Ordering::Relaxed),"classes":self.states.iter().map(|s|s.try_lock().ok().map(|s|serde_json::json!({"keys":s.buckets.len(),"high_water":s.peak,"capacity_rejections":s.rejected}))).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(value: &str) -> IpAddr {
        value.parse().expect("fixture")
    }
    #[test]
    fn maxmind_country_ipv4_ipv6_unknown_and_invalid_database() {
        let database = CountryDb::load(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/GeoIP2-Country-Test.mmdb"
        )))
        .expect("MaxMind fixture");
        assert_eq!(
            database.country(ip("81.2.69.160")).expect("lookup"),
            Some("GB")
        );
        assert_eq!(
            database.country(ip("::ffff:81.2.69.160")).expect("mapped"),
            Some("GB")
        );
        assert_eq!(
            database.country(ip("2001:218::")).expect("IPv6"),
            Some("JP")
        );
        assert_eq!(database.country(ip("127.0.0.1")).expect("unknown"), None);
        let file = tempfile::NamedTempFile::new().expect("file");
        assert!(CountryDb::load(file.path()).is_err());
    }
    #[test]
    fn stable_route_policy_refills_and_does_not_reset_on_apply() {
        use openwaf_config::traffic::Class::*;
        let limiter = Limiter::default();
        let now = Instant::now();
        let limit = RateLimit {
            per_second: 2,
            burst: 2,
        };
        let check = |route, ip, time| limiter.check(Api, route, ip, limit, time);
        assert_eq!(check("app", ip("192.0.2.1"), now), Verdict::Allow);
        assert_eq!(check("app", ip("::ffff:192.0.2.1"), now), Verdict::Allow);
        assert_eq!(check("app", ip("192.0.2.1"), now), Verdict::Limited(1));
        assert_eq!(
            check("app", ip("192.0.2.1"), now + Duration::from_millis(499)),
            Verdict::Limited(1)
        );
        assert_eq!(
            check("app", ip("192.0.2.1"), now + Duration::from_millis(500)),
            Verdict::Allow
        );
        assert_eq!(check("other", ip("192.0.2.1"), now), Verdict::Allow);
        let changed = RateLimit {
            per_second: 1,
            burst: 1,
        };
        assert_eq!(
            limiter.check(Api, "app", ip("192.0.2.1"), changed, now),
            Verdict::Allow
        );
        assert_eq!(
            limiter.check(Api, "app", ip("192.0.2.1"), changed, now),
            Verdict::Limited(1)
        );
        assert_eq!(check("app", ip("192.0.2.1"), now), Verdict::Limited(1));
    }
    #[test]
    fn churn_and_policy_versions_cannot_evict_depleted_or_starve_other_class_route() {
        use openwaf_config::traffic::Class::*;
        let limiter = Limiter::default();
        let now = Instant::now();
        let limit = RateLimit {
            per_second: 1,
            burst: 1,
        };
        for i in 0..128u32 {
            let client = IpAddr::V4((0xc0000200 + i).into());
            assert_eq!(
                limiter.check(Upload, "bulk", client, limit, now),
                Verdict::Allow
            );
        }
        assert_eq!(
            limiter.check(Upload, "bulk", ip("198.51.100.1"), limit, now),
            Verdict::Unavailable
        );
        assert_eq!(
            limiter.check(Upload, "bulk", ip("192.0.2.1"), limit, now),
            Verdict::Limited(1)
        );
        assert_eq!(
            limiter.check(Upload, "other", ip("198.51.100.1"), limit, now),
            Verdict::Allow
        );
        assert_eq!(
            limiter.check(Critical, "payment", ip("198.51.100.1"), limit, now),
            Verdict::Allow
        );
        let guard = limiter.states[1].lock().expect("state");
        assert_eq!(
            limiter.check(Upload, "bulk", ip("192.0.2.1"), limit, now),
            Verdict::Unavailable
        );
        assert_eq!(
            limiter.check(Critical, "other", ip("192.0.2.1"), limit, now),
            Verdict::Allow
        );
        drop(guard);
        assert_eq!(
            limiter.check(
                Upload,
                "bulk",
                ip("198.51.100.1"),
                limit,
                now + Duration::from_secs(61)
            ),
            Verdict::Allow
        );
        assert_eq!(limiter.states[1].lock().expect("state").buckets.len(), 1);
    }
    #[test]
    fn slow_refill_is_not_forgotten_early() {
        use openwaf_config::traffic::Class::Api;
        let limiter = Limiter::default();
        let now = Instant::now();
        let limit = RateLimit {
            per_second: 1,
            burst: 100,
        };
        for _ in 0..100 {
            assert_eq!(
                limiter.check(Api, "app", ip("192.0.2.1"), limit, now),
                Verdict::Allow
            );
        }
        for _ in 0..61 {
            assert_eq!(
                limiter.check(
                    Api,
                    "app",
                    ip("192.0.2.1"),
                    limit,
                    now + Duration::from_secs(61)
                ),
                Verdict::Allow
            );
        }
        assert_eq!(
            limiter.check(
                Api,
                "app",
                ip("192.0.2.1"),
                limit,
                now + Duration::from_secs(61)
            ),
            Verdict::Limited(1)
        );
    }
}

#[cfg(test)]
mod global_tests {
    use super::*;
    #[test]
    fn global_clients_share_one_bounded_scope_and_are_independent_of_route_buckets() {
        let limiter = Limiter::global();
        let route = Limiter::default();
        let limit = RateLimit {
            per_second: 1,
            burst: 1,
        };
        let now = Instant::now();
        let class = openwaf_config::traffic::Class::Api;
        for i in 0..MAX_RATE_KEYS as u32 {
            assert_eq!(
                limiter.check(
                    class,
                    "global",
                    IpAddr::V4((0xc0000000 + i).into()),
                    limit,
                    now
                ),
                Verdict::Allow
            );
        }
        assert_eq!(
            limiter.check(
                class,
                "global",
                "198.51.100.1".parse().expect("IP"),
                limit,
                now
            ),
            Verdict::Unavailable
        );
        let client = "192.0.0.1".parse().expect("IP");
        assert_eq!(
            limiter.check(class, "global", client, limit, now),
            Verdict::Limited(1)
        );
        assert_eq!(
            route.check(class, "global", client, limit, now),
            Verdict::Allow,
            "route named global has a separate budget"
        );
    }
}
