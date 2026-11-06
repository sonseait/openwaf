//! Fixed-cardinality counters. Raw addresses and User-Agent strings are never retained.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

const COUNTRY_CODES: usize = 26 * 26;
pub(crate) const UNATTRIBUTED: usize = COUNTRY_CODES;
pub const AGENTS: [&str; 9] = [
    "Edge",
    "Opera",
    "Chrome",
    "Firefox",
    "Safari",
    "Bot / crawler",
    "CLI / library",
    "Other",
    "Missing",
];
pub const METHODS: [&str; 10] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE", "OTHER",
];

pub enum Country<'a> {
    Code(&'a str),
    Unknown,
    Unavailable,
    LookupFailed,
}
impl Country<'_> {
    pub(crate) fn index(&self) -> usize {
        match self {
            Self::Code(code) if code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase()) => {
                usize::from(code.as_bytes()[0] - b'A') * 26 + usize::from(code.as_bytes()[1] - b'A')
            }
            Self::Code(_) | Self::Unknown => COUNTRY_CODES + 1,
            Self::Unavailable => COUNTRY_CODES + 2,
            Self::LookupFailed => COUNTRY_CODES + 3,
        }
    }
}

pub(crate) fn agent(value: Option<&[u8]>) -> usize {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        return 8;
    };
    if value.len() > 1024 || !value.is_ascii() {
        return 7;
    }
    let contains = |needle: &[u8]| {
        value
            .windows(needle.len())
            .any(|s| s.eq_ignore_ascii_case(needle))
    };
    // A coarse, unverified client claim, never a security decision.
    if [b"bot".as_slice(), b"crawler", b"spider", b"slurp"]
        .iter()
        .any(|n| contains(n))
    {
        5
    } else if [
        b"curl/".as_slice(),
        b"wget/",
        b"python-",
        b"go-http-client",
        b"okhttp",
        b"postmanruntime",
        b"libwww",
    ]
    .iter()
    .any(|n| contains(n))
    {
        6
    } else if contains(b"edg/") || contains(b"edga/") || contains(b"edgios/") {
        0
    } else if contains(b"opr/") || contains(b"opera") {
        1
    } else if contains(b"chrome/") || contains(b"crios/") {
        2
    } else if contains(b"firefox/") || contains(b"fxios/") {
        3
    } else if contains(b"safari/") {
        4
    } else {
        7
    }
}

#[derive(Default)]
pub(crate) struct Bucket {
    pub received: AtomicU64,
    pub blocked: AtomicU64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Count {
    pub label: String,
    pub received: u64,
    pub blocked: u64,
}
impl Bucket {
    fn snapshot(&self, label: String) -> Count {
        Count {
            label,
            received: self.received.load(Relaxed),
            blocked: self.blocked.load(Relaxed),
        }
    }
}
pub(crate) struct Counters {
    pub countries: [Bucket; COUNTRY_CODES + 4],
    pub agents: [Bucket; AGENTS.len()],
    pub methods: [Bucket; METHODS.len()],
}
impl Default for Counters {
    fn default() -> Self {
        Self {
            countries: std::array::from_fn(|_| Bucket::default()),
            agents: std::array::from_fn(|_| Bucket::default()),
            methods: std::array::from_fn(|_| Bucket::default()),
        }
    }
}
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dimensions {
    pub source: String,
    pub countries: Vec<Count>,
    pub user_agents: Vec<Count>,
    pub methods: Vec<Count>,
}
impl Counters {
    pub fn restore(&self, snapshot: &Dimensions) -> Result<(), &'static str> {
        if snapshot.source != "gateway_counters" {
            return Err("invalid statistics source");
        }
        let expected = Self::default().snapshot();
        let country_labels: Vec<_> = (0..COUNTRY_CODES + 4)
            .map(|i| match i {
                UNATTRIBUTED => "Unattributed".to_owned(),
                i if i == COUNTRY_CODES + 1 => "Unknown".to_owned(),
                i if i == COUNTRY_CODES + 2 => "Unavailable".to_owned(),
                i if i == COUNTRY_CODES + 3 => "Lookup failed".to_owned(),
                _ => format!(
                    "{}{}",
                    (b'A' + (i / 26) as u8) as char,
                    (b'A' + (i % 26) as u8) as char
                ),
            })
            .collect();
        let agents: Vec<_> = expected
            .user_agents
            .iter()
            .map(|c| c.label.clone())
            .collect();
        let methods: Vec<_> = expected.methods.iter().map(|c| c.label.clone()).collect();
        let groups = [
            (
                &snapshot.countries,
                &country_labels,
                self.countries.as_slice(),
            ),
            (&snapshot.user_agents, &agents, self.agents.as_slice()),
            (&snapshot.methods, &methods, self.methods.as_slice()),
        ];
        // Validate all groups before restoring any of them.
        for (values, labels, _) in &groups {
            let mut seen = std::collections::BTreeSet::new();
            if values.len() > labels.len()
                || values
                    .iter()
                    .any(|v| !labels.contains(&v.label) || !seen.insert(&v.label))
            {
                return Err("invalid statistics dimensions");
            }
        }
        for (values, labels, buckets) in groups {
            for (label, bucket) in labels.iter().zip(buckets) {
                let value = values.iter().find(|v| &v.label == label);
                bucket
                    .received
                    .store(value.map_or(0, |v| v.received), Relaxed);
                bucket
                    .blocked
                    .store(value.map_or(0, |v| v.blocked), Relaxed);
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Dimensions {
        Dimensions {
            source: "gateway_counters".into(),
            countries: self
                .countries
                .iter()
                .enumerate()
                .filter_map(|(i, bucket)| {
                    let label = match i {
                        UNATTRIBUTED => "Unattributed".to_owned(),
                        i if i == COUNTRY_CODES + 1 => "Unknown".to_owned(),
                        i if i == COUNTRY_CODES + 2 => "Unavailable".to_owned(),
                        i if i == COUNTRY_CODES + 3 => "Lookup failed".to_owned(),
                        _ => format!(
                            "{}{}",
                            (b'A' + (i / 26) as u8) as char,
                            (b'A' + (i % 26) as u8) as char
                        ),
                    };
                    let value = bucket.snapshot(label);
                    (value.received > 0 || value.blocked > 0).then_some(value)
                })
                .collect(),
            user_agents: self
                .agents
                .iter()
                .zip(AGENTS)
                .map(|(b, label)| b.snapshot(label.to_owned()))
                .collect(),
            methods: self
                .methods
                .iter()
                .zip(METHODS)
                .map(|(b, label)| b.snapshot(label.to_owned()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification_precedence_and_untrusted_input_are_bounded() {
        for (input, expected) in [
            ("Chrome/1 Safari/1 OPR/1", 1),
            ("Chrome/1", 2),
            ("FxiOS/1 Safari/1", 3),
            ("Version/1 Safari/1", 4),
            ("Mozilla Chrome/1 Googlebot/1", 5),
            ("cURL/8.0", 6),
            ("private-value", 7),
            ("", 8),
        ] {
            assert_eq!(agent(Some(input.as_bytes())), expected);
        }
        assert_eq!(agent(None), 8);
        assert_eq!(agent(Some(&vec![b'A'; 1025])), 7);
        assert_eq!(agent(Some(&[255, 0])), 7);
        assert_eq!(
            Country::Code("../../private").index(),
            Country::Unknown.index()
        );
        assert_ne!(Country::Unavailable.index(), Country::LookupFailed.index());
    }
    #[test]
    fn maximum_dimensions_payload_fits_the_sse_client_limit() {
        let counters = Counters::default();
        for bucket in counters
            .countries
            .iter()
            .chain(&counters.agents)
            .chain(&counters.methods)
        {
            bucket.received.store(u64::MAX, Relaxed);
            bucket.blocked.store(u64::MAX, Relaxed);
        }
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.countries.len(), COUNTRY_CODES + 4);
        // Reserve 8 KiB for the surrounding metrics/event payload.
        assert!(serde_json::to_vec(&snapshot).expect("serialize").len() < 65536 - 8192);
    }
}
