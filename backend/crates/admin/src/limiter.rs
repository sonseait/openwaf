use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Fixed-window login admission; socket IP and account keys, never forwarded headers.
/// At capacity, reject new keys rather than evicting an attacker's existing quota.
pub struct Limiter {
    keys: HashMap<String, (Instant, u8)>,
}
impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}
impl Limiter {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    pub fn admit(&mut self, ip: String, account: String, now: Instant) -> bool {
        self.keys
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        let keys = [format!("ip:{ip}"), format!("user:{account}")];
        let missing = keys
            .iter()
            .filter(|key| !self.keys.contains_key(*key))
            .count();
        if self.keys.len() + missing > 4096
            || keys
                .iter()
                .any(|key| self.keys.get(key).is_some_and(|(_, count)| *count >= 5))
        {
            return false;
        }
        for key in keys {
            self.keys.entry(key).or_insert((now, 0)).1 += 1;
        }
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_quota_expiry_and_account_protection() {
        let mut limiter = Limiter::new();
        let now = Instant::now();
        for i in 0..5 {
            assert!(limiter.admit(i.to_string(), "admin".into(), now));
        }
        assert!(!limiter.admit("different".into(), "admin".into(), now));
        assert!(limiter.admit(
            "different".into(),
            "admin".into(),
            now + Duration::from_secs(60)
        ));
        for i in 0..2100 {
            limiter.admit(
                format!("ip{i}"),
                format!("user{i}"),
                now + Duration::from_secs(60),
            );
        }
        assert!(limiter.keys.len() <= 4096);
        assert!(!limiter.admit("new".into(), "new".into(), now + Duration::from_secs(60)));
    }
}
