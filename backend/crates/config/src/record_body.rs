//! Opt-in capture policy; body inspection and retry/replay remain independent.
use crate::Validation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub request_enabled: bool,
    #[serde(default)]
    pub response_enabled: bool,
    #[serde(default)]
    pub query_enabled: bool,
    #[serde(default)]
    pub redact_fields: Vec<String>,
}
impl Policy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn validate(&self) -> Result<(), Validation> {
        if self.redact_fields.len() > 64
            || self.redact_fields.iter().any(|name| {
                name.is_empty() || name.len() > 128 || name.chars().any(char::is_control)
            })
        {
            return Err(Validation::RecordBody);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_bounded_redaction_names() {
        let mut policy: Policy = serde_json::from_str("{}").expect("legacy defaults");
        assert!(policy.is_default());
        assert!(!policy.query_enabled);
        policy.response_enabled = true;
        policy.redact_fields.push("private_field".into());
        assert!(policy.validate().is_ok());
        policy.redact_fields.push("\n".into());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn recording_roundtrips_diff_apply_and_rollback_keep_pinned_policy() {
        use crate::{Context, Document, Snapshot, Store};
        let document: Document = serde_json::from_value(serde_json::json!({
            "routes":[{"id":"record","hostname":"body.test","path":"/","path_match":"prefix","upstream":"app"}],
            "upstreams":[{"id":"app","endpoints":[{"address":"127.0.0.1:8081","protocol":"http"}]}]
        })).expect("legacy document");
        let context = Context {
            listeners: vec![],
            local_ips: vec![],
        };
        let store = Store::new(Snapshot::prepare(0, document, &context).expect("initial snapshot"));
        let pinned = store.load();
        assert!(
            serde_json::to_value(&pinned.document).expect("wire")["routes"][0]
                .get("record_body")
                .is_none()
        );
        let mut changed = pinned.document.clone();
        changed.routes[0].record_body = Policy {
            request_enabled: false,
            response_enabled: true,
            query_enabled: true,
            redact_fields: vec!["private".into()],
        };
        let wire = serde_json::to_string(&changed).expect("wire");
        let roundtrip: Document = serde_json::from_str(&wire).expect("roundtrip");
        assert_eq!(roundtrip, changed);
        assert_eq!(
            crate::diff(&pinned.document, &changed).routes.changed,
            vec!["record"]
        );
        store.publish(Snapshot::prepare(1, changed, &context).expect("apply"));
        assert!(store.load().document.routes[0].record_body.response_enabled);
        assert!(store.load().document.routes[0].record_body.query_enabled);
        assert!(pinned.document.routes[0].record_body.is_default());
        store.publish(Snapshot::prepare(2, pinned.document.clone(), &context).expect("rollback"));
        assert!(store.load().document.routes[0].record_body.is_default());
    }
}
