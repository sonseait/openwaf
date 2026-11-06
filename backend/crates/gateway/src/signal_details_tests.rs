use super::*;

#[test]
fn signals_survive_details_transport_without_inventing_enforcement() {
    let mut ctx = RequestContext::default();
    ctx.body_inspection = "full";
    ctx.waf_observed_at_unix_ms = 123;
    ctx.waf_report = Some(openwaf_waf::Report {
        body_inspected: true,
        decision: Decision::Block,
        findings: vec![openwaf_waf::Finding {
            rule_id: 942100,
            phase: 2,
            severity: 2,
        }],
        truncated: false,
        anomaly_score: Some(5),
    });
    let observed: serde_json::Value =
        serde_json::from_str(&ctx.details("completed", true, 200)).expect("details");
    assert_eq!(observed["schema_version"], 9);
    assert_eq!(
        observed["security_signals"]["entries"][0]["action"],
        "would_block"
    );
    ctx.waf_enforced = true;
    let enforced: serde_json::Value =
        serde_json::from_str(&ctx.details("completed", true, 403)).expect("details");
    assert_eq!(
        enforced["security_signals"]["entries"][0]["action"],
        "enforced_block"
    );
}
