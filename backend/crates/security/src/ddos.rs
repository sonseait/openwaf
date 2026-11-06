//! Aggregate HTTP admission before WAF/upstream work. No per-client allocation,
//! waiting queue, I/O or background task. State belongs to the running node.
use crate::traffic::{Limiter, Verdict};
use openwaf_config::{access::RateLimit, traffic::Class};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Default)]
pub struct Protection {
    // Separate instances prevent a route named "global" from sharing node state.
    global: Limiter,
    routes: Limiter,
    limited: AtomicU64,
    unavailable: AtomicU64,
}
impl Protection {
    pub fn check_global(&self, limit: RateLimit, now: Instant) -> Verdict {
        self.check(&self.global, Class::Api, "global", limit, now)
    }
    pub fn check_route(
        &self,
        class: Class,
        route: &str,
        limit: RateLimit,
        now: Instant,
    ) -> Verdict {
        self.check(&self.routes, class, route, limit, now)
    }
    fn check(
        &self,
        limiter: &Limiter,
        class: Class,
        scope: &str,
        limit: RateLimit,
        now: Instant,
    ) -> Verdict {
        // Internal identity only, never an upstream or a client-controlled key.
        // Reusing the bounded token bucket preserves refill-safe TTL, policy
        // generations and critical-class isolation without storing attacker IPs.
        let verdict = limiter.check(class, scope, IpAddr::V4(Ipv4Addr::UNSPECIFIED), limit, now);
        match verdict {
            Verdict::Limited(_) => {
                self.limited.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Unavailable => {
                self.unavailable.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        verdict
    }
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "limited_total": self.limited.load(Ordering::Relaxed),
            "unavailable_total": self.unavailable.load(Ordering::Relaxed),
            "global": self.global.stats(), "routes": self.routes.stats()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn global_and_route_scopes_refill_and_keep_policy_generations() {
        let protection = Protection::default();
        let now = Instant::now();
        let limit = RateLimit {
            per_second: 2,
            burst: 2,
        };
        assert_eq!(protection.check_global(limit, now), Verdict::Allow);
        assert_eq!(protection.check_global(limit, now), Verdict::Allow);
        assert_eq!(protection.check_global(limit, now), Verdict::Limited(1));
        // Route identity cannot collide with the global scope.
        assert_eq!(
            protection.check_route(Class::Api, "global", limit, now),
            Verdict::Allow
        );
        let changed = RateLimit {
            per_second: 1,
            burst: 1,
        };
        assert_eq!(protection.check_global(changed, now), Verdict::Allow);
        assert_eq!(protection.check_global(limit, now), Verdict::Limited(1));
        assert_eq!(
            protection.check_global(limit, now + Duration::from_millis(499)),
            Verdict::Limited(1)
        );
        assert_eq!(
            protection.check_global(limit, now + Duration::from_millis(500)),
            Verdict::Allow
        );
        assert_eq!(protection.stats()["limited_total"], 3);
    }

    #[test]
    fn policy_churn_is_bounded_and_does_not_starve_critical_routes() {
        let protection = Protection::default();
        let now = Instant::now();
        for burst in 1..=128 {
            let limit = RateLimit {
                per_second: 1,
                burst,
            };
            assert_eq!(
                protection.check_route(Class::Upload, "bulk", limit, now),
                Verdict::Allow
            );
        }
        let limit = RateLimit {
            per_second: 1,
            burst: 129,
        };
        assert_eq!(
            protection.check_route(Class::Upload, "bulk", limit, now),
            Verdict::Unavailable
        );
        assert_eq!(
            protection.check_route(Class::Critical, "payment", limit, now),
            Verdict::Allow
        );
        assert_eq!(protection.stats()["unavailable_total"], 1);
        assert_eq!(
            protection.check_route(Class::Upload, "bulk", limit, now + Duration::from_secs(129)),
            Verdict::Allow
        );
    }
}
