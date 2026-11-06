//! Independent compiler/native workers. No reference to live counters, detectors,
//! ForwardAuth client, telemetry, storage or upstream networking exists here.
use openwaf_admin::{
    config::Preparer,
    simulator::{Backend, Input},
};
use openwaf_waf::{Pool, Request};
use std::{sync::Arc, time::Duration};
pub struct Service {
    mode: openwaf_waf::Mode,
    compiler: crate::waf_policy::Compiler,
    slots: tokio::sync::Semaphore,
}
impl Service {
    pub fn new(path: String, mode: openwaf_waf::Mode) -> anyhow::Result<Arc<Self>> {
        let config = openwaf_waf::Configuration::new(mode);
        let pool = Arc::new(Pool::configured(&path, config.clone(), 1, 1)?);
        Ok(Arc::new(Self {
            mode,
            compiler: crate::waf_policy::Compiler::with_budgets(path, config, pool, 1, 1)?,
            slots: tokio::sync::Semaphore::new(2),
        }))
    }
}
#[async_trait::async_trait]
impl Backend for Service {
    async fn simulate(
        &self,
        snapshot: openwaf_config::Snapshot,
        input: Input,
    ) -> Result<serde_json::Value, ()> {
        input.validate().map_err(|_| ())?;
        let _slot = self.slots.try_acquire().map_err(|_| ())?;
        let uri: http::Uri = input.path.parse().map_err(|_| ())?;
        let selected = snapshot.route(&input.hostname, uri.path(), &input.method);
        let mut result = serde_json::json!({"config_version":snapshot.version,"route_id":null,"acl":"not_simulated","content":"not_simulated","api_schema":"not_simulated","crs":{"status":"not_simulated"},"not_simulated":["ip_global_identity_quotas","geoip","crowdsec","challenge","forward_auth","password_sessions","detectors","incidents","dns_tls_health","upstream","response_body","websocket_frames"]});
        let Some(index) = selected else {
            result["routing"] = "no_match".into();
            return Ok(result);
        };
        let route = &snapshot.document.routes[index];
        result["routing"] = "matched".into();
        result["route_id"] = route.id.clone().into();
        result["acl"] = if snapshot.document.global_rules.permits_ip(input.client_ip)
            && route.access.permits_ip(input.client_ip)
        {
            "permitted"
        } else {
            "would_block"
        }
        .into();
        let mut headers = http::HeaderMap::new();
        headers.insert("host", input.hostname.parse().map_err(|_| ())?);
        for (k, v) in &input.headers {
            headers.insert(
                k.parse::<http::HeaderName>().map_err(|_| ())?,
                v.parse().map_err(|_| ())?,
            );
        }
        let streaming = route
            .body
            .as_ref()
            .is_some_and(|b| b.inspection == openwaf_config::retry::Inspection::HeadersQueryOnly);
        let multipart = headers
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"multipart/"));
        let cap = route.body.as_ref().map_or(65536, |b| b.max_body_bytes).min(
            route
                .waf
                .as_ref()
                .map_or(65536, |w| w.body_limit_bytes as u64),
        );
        if input.body.len() as u64 > cap {
            result["body_limit"] = "would_reject_413".into();
            result["crs"]["status"] = "not_simulated_body_limit".into();
            return Ok(result);
        }
        if let Some(content) = &route.content {
            result["content"] =
                match openwaf_config::traffic::headers(content, &headers, !input.body.is_empty())
                    .and_then(|p| {
                        if streaming || multipart {
                            Ok(())
                        } else {
                            openwaf_config::traffic::body(p, input.body.as_bytes())
                        }
                    }) {
                    Ok(()) => "valid",
                    Err(_) => "would_reject",
                }
                .into();
        }
        if let Some(schema) = &route.middleware.api_schema {
            result["api_schema"] = serde_json::json!({"outcome":schema.check(headers.get("content-type").and_then(|v|v.to_str().ok()),input.body.as_bytes()),"mode":schema.mode});
        }
        let timeout = route.waf.as_ref().map_or(2000, |w| w.inspection_timeout_ms);
        let mode = route
            .waf
            .as_ref()
            .map_or(self.mode, crate::waf_policy::mode);
        let snapshot = self
            .compiler
            .client
            .prepare(snapshot)
            .await
            .map_err(|_| ())?;
        let pool = snapshot
            .prepared
            .as_ref()
            .and_then(|p| p.downcast_ref::<crate::waf_policy::Prepared>())
            .and_then(|p| p.routes[index].clone());
        if let Some(pool) = pool {
            let ticket = pool.try_reserve().map_err(|_| ())?;
            // Ticket is transferred to the native Job. Caller cancellation cannot
            // release it or native transaction ownership until the worker ends.
            let report = pool
                .inspect_report(
                    ticket,
                    Request {
                        inspect_body: !streaming && !multipart,
                        uri: input.path,
                        method: input.method,
                        version: "1.1".into(),
                        client: std::net::SocketAddr::new(input.client_ip, 12345),
                        server: "127.0.0.1:443".parse().map_err(|_| ())?,
                        headers: headers
                            .iter()
                            .map(|(k, v)| (k.as_str().as_bytes().to_vec(), v.as_bytes().to_vec()))
                            .collect(),
                        body: if streaming || multipart {
                            vec![]
                        } else {
                            input.body.into_bytes()
                        },
                    },
                    Duration::from_millis(timeout),
                )
                .await
                .map_err(|_| ())?;
            result["crs"] = serde_json::json!({"status":"simulated","coverage":if streaming{"headers_query_only"}else if multipart{"skipped_multipart"}else{"full"},"mode":format!("{mode:?}"),"report":report});
        } else {
            result["crs"]["status"] = "off".into();
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn isolated_native_execution_rejects_invalid_input_without_normalizing() {
        let service = Service::new(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../waf/tests/fixtures/rules.conf"
            )
            .into(),
            openwaf_waf::Mode::On,
        )
        .unwrap();
        let document=serde_json::from_value(serde_json::json!({"routes":[{"id":"r","hostname":"app.test","path":"/","path_match":"prefix","redirect":{"url":"https://outside.invalid/","status":308},"waf":{"mode":"On"}}]})).unwrap();
        let snapshot = openwaf_config::Snapshot::prepare(
            7,
            document,
            &openwaf_config::Context {
                listeners: vec![],
                local_ips: vec![],
            },
        )
        .unwrap();
        let input:Input=serde_json::from_value(serde_json::json!({"hostname":"app.test","path":"/?q=openwaf-test-attack","method":"GET","client_ip":"192.0.2.1","headers":[["x-test-attack","yes"]]})).unwrap();
        let result = service.simulate(snapshot, input.clone()).await.unwrap();
        assert_eq!(result["config_version"], 7);
        assert_eq!(result["crs"]["status"], "simulated");
        assert_eq!(result["crs"]["report"]["decision"], "block");
        for (method, path) in [
            ("get", "/"),
            ("GET", "/%61"),
            ("GET", "/a/../b"),
            ("GET", "https://app.test/"),
        ] {
            let mut bad = input.clone();
            bad.method = method.into();
            bad.path = path.into();
            assert!(bad.validate().is_err());
        }
    }
}
