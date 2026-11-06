//! Bounded, payload-free CRS observations. Action describes the report-level
//! decision, not proof that an individual finding independently caused a block.
use openwaf_waf::{Decision, Report};
use serde::Serialize;

const MAX_SIGNALS: usize = 16;

#[derive(Serialize)]
pub struct Signals {
    pub status: &'static str,
    pub observed_at_unix_ms: Option<u64>,
    pub coverage: String,
    pub entries: Vec<Signal>,
    pub truncated: bool,
}

#[derive(Clone, Serialize)]
pub struct Signal {
    pub source: &'static str,
    pub reason: &'static str,
    pub scope: &'static str,
    pub action: &'static str,
    pub rule_id: u32,
    pub phase: i32,
    pub severity: i32,
}

impl Signals {
    pub fn from_waf(
        report: Option<&Report>,
        enforced: bool,
        coverage: &str,
        observed_at_unix_ms: u64,
    ) -> Self {
        let action = match report {
            Some(r) if r.decision == Decision::Block && enforced => "enforced_block",
            Some(r) if r.decision == Decision::Block => "would_block",
            _ => "observed",
        };
        let mut signals = Self {
            status: if report.is_some() {
                "collected"
            } else {
                "not_collected"
            },
            observed_at_unix_ms: report.map(|_| observed_at_unix_ms),
            coverage: coverage.chars().take(32).collect(),
            entries: report
                .into_iter()
                .flat_map(|r| r.findings.iter())
                .take(MAX_SIGNALS)
                .map(|finding| Signal {
                    source: "crs",
                    reason: "rule_match",
                    scope: "request",
                    action,
                    rule_id: finding.rule_id,
                    phase: finding.phase,
                    severity: finding.severity,
                })
                .collect(),
            truncated: report.is_some_and(|r| r.truncated || r.findings.len() > MAX_SIGNALS),
        };
        // Disruptive decisions may have no logged finding (e.g. nolog).
        // Do not invent rule metadata or claim CRS provenance in that case.
        if report.is_some_and(|r| r.decision == Decision::Block) && signals.entries.is_empty() {
            signals
                .entries
                .push(Signal::outcome("waf", "native_decision", action));
        }
        signals
    }
}

impl Signal {
    pub fn outcome(source: &'static str, reason: &'static str, action: &'static str) -> Self {
        Self {
            source,
            reason,
            scope: "request",
            action,
            rule_id: 0,
            phase: 0,
            severity: 0,
        }
    }
}
impl Signals {
    pub fn with_outcomes(mut self, outcomes: &[Signal], now: u64) -> Self {
        if !outcomes.is_empty() {
            self.status = "collected";
            self.observed_at_unix_ms = Some(now);
        }
        self.truncated |= self.entries.len() + outcomes.len() > MAX_SIGNALS;
        // Actual gate outcomes take precedence over optional CRS finding detail.
        let mut entries: Vec<_> = outcomes.iter().take(MAX_SIGNALS).cloned().collect();
        entries.extend(self.entries.into_iter().take(MAX_SIGNALS - entries.len()));
        self.entries = entries;
        self
    }
}
