//! Bounded decision timings measured with a monotonic clock. Each timer covers
//! only its explicit stage, including async waits, never time since the request
//! started or since the previous checkpoint. No request payload is retained.
use serde::Serialize;
use std::time::Instant;

const MAX_STEPS: usize = 16;

#[derive(Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Trace {
    steps: Vec<Step>,
    #[serde(skip)]
    active: Option<(&'static str, Instant)>,
}

#[derive(Serialize)]
struct Step {
    stage: &'static str,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<f64>,
}

impl Trace {
    pub(crate) fn begin(&mut self, stage: &'static str) {
        self.active = (self.steps.len() < MAX_STEPS).then(|| (stage, Instant::now()));
    }

    pub(crate) fn checked(&mut self, stage: &'static str, result: &'static str) {
        self.checked_at(stage, result, Instant::now());
    }

    fn checked_at(&mut self, stage: &'static str, result: &'static str, now: Instant) {
        let duration_ms = self.active.take().and_then(|(active, started)| {
            (active == stage).then(|| now.duration_since(started).as_secs_f64() * 1000.0)
        });
        if self.steps.len() < MAX_STEPS {
            self.steps.push(Step {
                stage,
                result,
                duration_ms,
            });
        }
    }

    pub(crate) fn stop(&mut self, result: &'static str) {
        if let Some((stage, _)) = self.active {
            self.checked(stage, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn timings_belong_to_each_stage_and_keep_submillisecond_precision() {
        let mut trace = Trace::default();
        let now = Instant::now();
        trace.active = Some(("routing", now));
        trace.checked_at("routing", "matched", now + Duration::from_millis(3));
        // A gap between stages must not inflate the next stage's duration.
        let later = now + Duration::from_secs(1);
        trace.active = Some(("waf", later));
        trace.checked_at("waf", "passed", later + Duration::from_micros(250));
        let json = serde_json::to_value(&trace).expect("trace JSON");
        assert_eq!(json[0]["duration_ms"], 3.0);
        assert_eq!(json[1]["duration_ms"], 0.25);
    }

    #[test]
    fn stopped_and_interrupted_stages_are_recorded_once_without_later_steps() {
        let mut trace = Trace::default();
        trace.begin("waf");
        trace.stop("stopped");
        trace.stop("interrupted");
        let json = serde_json::to_value(&trace).expect("trace JSON");
        assert_eq!(json.as_array().expect("steps").len(), 1);
        assert_eq!(json[0]["stage"], "waf");
        assert_eq!(json[0]["result"], "stopped");
        assert!(json[0]["duration_ms"].as_f64().is_some_and(|v| v >= 0.0));
    }

    #[test]
    fn trace_is_bounded_and_never_invents_a_missing_timing() {
        let mut trace = Trace::default();
        trace.checked("legacy", "passed");
        trace.begin("routing");
        trace.checked("other", "passed");
        for _ in 0..MAX_STEPS * 2 {
            trace.begin("waf");
            trace.checked("waf", "passed");
        }
        let json = serde_json::to_value(&trace).expect("trace JSON");
        assert_eq!(json.as_array().expect("steps").len(), MAX_STEPS);
        assert!(json[0].get("duration_ms").is_none());
        assert!(json[1].get("duration_ms").is_none());
        assert!(trace.active.is_none());
    }
}
