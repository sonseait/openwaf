use openwaf_gateway::security_signals::Signals;
use openwaf_waf::{Decision, Finding, Report};

#[test]
fn native_block_without_logged_findings_still_has_a_decision_signal() {
    let report = Report {
        body_inspected: true,
        decision: Decision::Block,
        findings: vec![],
        truncated: false,
        anomaly_score: None,
    };
    for (enforced, action) in [(true, "enforced_block"), (false, "would_block")] {
        let value =
            serde_json::to_value(Signals::from_waf(Some(&report), enforced, "full", 123)).unwrap();
        assert_eq!(value["entries"][0]["source"], "waf");
        assert_eq!(value["entries"][0]["reason"], "native_decision");
        assert_eq!(value["entries"][0]["action"], action);
        assert_eq!(value["entries"][0]["rule_id"], 0);
    }
}

#[test]
fn crs_signals_distinguish_observation_from_enforcement_and_bound_output() {
    let report = Report {
        body_inspected: true,
        decision: Decision::Block,
        findings: vec![
            Finding {
                rule_id: 942100,
                phase: 2,
                severity: 2
            };
            40
        ],
        truncated: true,
        anomaly_score: Some(5),
    };
    let observed = Signals::from_waf(Some(&report), false, "full", 123);
    let json = serde_json::to_value(&observed).expect("serialize");
    assert_eq!(json["status"], "collected");
    assert_eq!(json["entries"].as_array().expect("entries").len(), 16);
    assert_eq!(json["entries"][0]["action"], "would_block");
    assert_eq!(json["entries"][0]["source"], "crs");
    assert_eq!(json["entries"][0]["rule_id"], 942100);
    assert_eq!(json["observed_at_unix_ms"], 123);
    assert_eq!(json["truncated"], true);
    let enforced = serde_json::to_value(Signals::from_waf(Some(&report), true, "full", 123))
        .expect("serialize");
    assert_eq!(enforced["entries"][0]["action"], "enforced_block");
    let missing = serde_json::to_value(Signals::from_waf(None, false, "not_inspected", 123))
        .expect("serialize");
    assert_eq!(missing["status"], "not_collected");
    assert!(missing["entries"].as_array().expect("entries").is_empty());
    assert!(missing["observed_at_unix_ms"].is_null());
}

#[test]
fn allow_report_is_observed_and_signals_do_not_carry_payloads() {
    let report = Report {
        body_inspected: false,
        decision: Decision::Allow,
        findings: vec![Finding {
            rule_id: 920100,
            phase: 1,
            severity: 4,
        }],
        truncated: false,
        anomaly_score: None,
    };
    let signals = serde_json::to_value(Signals::from_waf(
        Some(&report),
        true,
        "headers_query_only",
        10,
    ))
    .expect("serialize");
    assert_eq!(signals["entries"][0]["action"], "observed");
    assert_eq!(signals["coverage"], "headers_query_only");
    assert_eq!(signals["truncated"], false);
    assert!(signals["entries"][0].get("matched_data").is_none());
    let details = openwaf_gateway::request_details::serialize(
        serde_json::json!({"security_signals": signals}),
    );
    assert!(details.len() <= openwaf_gateway::request_details::MAX_DETAILS_BYTES);
}

#[test]
fn generic_outcomes_have_no_identity_and_remain_bounded_without_crs() {
    use openwaf_gateway::security_signals::Signal;
    let entries: Vec<_> = (0..32)
        .map(|_| {
            Signal::outcome(
                "identity_rate_limit",
                "verified_principal_quota",
                "capacity_error",
            )
        })
        .collect();
    let value =
        serde_json::to_value(Signals::from_waf(None, false, "off", 0).with_outcomes(&entries, 100))
            .unwrap();
    assert_eq!(value["status"], "collected");
    assert_eq!(value["truncated"], true);
    assert_eq!(value["entries"].as_array().unwrap().len(), 16);
    assert_eq!(value["entries"][0]["action"], "capacity_error");
    assert!(value.to_string().len() < 4096);
    for key in ["principal", "identity", "payload", "token", "matched_data"] {
        assert!(value["entries"][0].get(key).is_none());
    }
}
