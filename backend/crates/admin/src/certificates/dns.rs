//! Explicit, audited DNS edits scoped to one saved zone. Never used by routing.
use super::providers::{self, Page};
use super::*;
use axum::extract::Query;
use serde_json::{Value, json};

pub(super) fn routes() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/api/v1/certificate-providers/{id}/dns",
            get(list).post(create),
        )
        .route(
            "/api/v1/certificate-providers/{id}/dns/{record}",
            axum::routing::put(update).delete(remove),
        )
}
fn protected(record: &Value) -> bool {
    record["name"].as_str().is_none_or(|name| {
        name.split('.')
            .any(|label| label.eq_ignore_ascii_case("_acme-challenge"))
    }) || record["comment"]
        .as_str()
        .is_some_and(|v| v.starts_with("openwaf-acme:"))
}
fn supported(kind: &str) -> bool {
    matches!(kind, "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "NS")
}
fn version(record: &Value) -> ApiResult<String> {
    Ok(crypto::hex(&sha256(
        &serde_json::to_vec(record).map_err(|_| Error::CloudflareUnavailable)?,
    )))
}
fn summary(record: &Value) -> ApiResult<Value> {
    let id = record["id"]
        .as_str()
        .filter(|id| openwaf_cloudflare::valid_id(id))
        .ok_or(Error::CloudflareUnavailable)?;
    let name = record["name"]
        .as_str()
        .filter(|n| n.len() <= 253)
        .ok_or(Error::CloudflareUnavailable)?;
    let kind = record["type"]
        .as_str()
        .filter(|n| n.len() <= 16)
        .ok_or(Error::CloudflareUnavailable)?;
    let content = record["content"]
        .as_str()
        .filter(|n| n.len() <= 8192)
        .ok_or(Error::CloudflareUnavailable)?;
    Ok(
        json!({"id":id,"name":name,"type":kind,"content":content,"ttl":record["ttl"],"proxied":record["proxied"].as_bool().unwrap_or(false),"priority":record["priority"],"version":version(record)?,"editable":supported(kind) && !protected(record),"protected":protected(record)}),
    )
}
async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Page>,
) -> ApiResult<Json<Value>> {
    authenticate(&app, &headers, false).await?;
    let _permit = providers::permit(&app)?;
    let p = providers::saved(&app, &id).await?;
    let v = p
        .client
        .call(
            Method::GET,
            &format!("/zones/{}/dns_records", p.zone_id),
            &providers::page_query(&q)?,
            None,
        )
        .await
        .map_err(Error::from)?;
    let raw = v["result"]
        .as_array()
        .filter(|v| v.len() <= 50)
        .ok_or(Error::CloudflareUnavailable)?;
    if raw
        .iter()
        .any(|r| r["name"].as_str().is_none_or(|n| !in_zone(n, &p.zone)))
    {
        return Err(Error::CloudflareUnavailable);
    }
    let records = raw.iter().map(summary).collect::<ApiResult<Vec<_>>>()?;
    let pages = v["result_info"]["total_pages"]
        .as_u64()
        .filter(|n| *n <= 10000)
        .ok_or(Error::CloudflareUnavailable)?;
    Ok(Json(
        json!({"records":records,"page":q.page,"has_more":u64::from(q.page)<pages,"provider_revision":p.revision,"zone_name":p.zone,"source":"cloudflare","observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordInput {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    content: String,
    ttl: u32,
    #[serde(default)]
    proxied: bool,
    priority: Option<u16>,
}
fn owner(input: &str, zone: &str) -> ApiResult<String> {
    let input = input.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = if input == "@" {
        zone.into()
    } else if in_zone(&input, zone) {
        input
    } else {
        format!("{input}.{zone}")
    };
    if name.len() > 253
        || name.split('.').enumerate().any(|(i, label)| {
            label.is_empty()
                || label.len() > 63
                || !(i == 0 && label == "*")
                    && !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        })
    {
        return Err(Error::Invalid);
    }
    Ok(name)
}
impl RecordInput {
    fn payload(&self, zone: &str) -> ApiResult<Value> {
        if !supported(&self.kind)
            || self.content.is_empty()
            || self.content.len() > 2048
            || self
                .content
                .chars()
                .any(|c| c == '\0' || c == '\r' || c == '\n')
            || !(self.ttl == 1 || (60..=86400).contains(&self.ttl))
            || self.proxied
                && (!matches!(self.kind.as_str(), "A" | "AAAA" | "CNAME") || self.ttl != 1)
            || (self.kind == "MX") != self.priority.is_some()
        {
            return Err(Error::Invalid);
        }
        let name = owner(&self.name, zone)?;
        let content = match self.kind.as_str() {
            "A" => self
                .content
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| Error::Invalid)?
                .to_string(),
            "AAAA" => self
                .content
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| Error::Invalid)?
                .to_string(),
            "CNAME" | "NS" | "MX" => {
                let n = hostname(&self.content)?;
                if n.starts_with("*.") {
                    return Err(Error::Invalid);
                }
                n
            }
            _ => self.content.clone(),
        };
        let mut payload = json!({"type":self.kind,"name":name,"content":content,"ttl":self.ttl});
        if matches!(self.kind.as_str(), "A" | "AAAA" | "CNAME") {
            payload["proxied"] = self.proxied.into();
        }
        if let Some(priority) = self.priority {
            payload["priority"] = priority.into();
        }
        if protected(&payload) {
            return Err(Error::Conflict);
        }
        Ok(payload)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Write {
    record: RecordInput,
    expected_provider_revision: i64,
    expected_record: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Delete {
    expected_provider_revision: i64,
    expected_record: String,
}
async fn log(
    app: &App,
    auth: &Auth,
    peer: SocketAddr,
    action: &str,
    target: &str,
) -> ApiResult<()> {
    let mut tx = app.db.begin().await?;
    audit(&mut tx, Some(auth.id), action, target, Some(peer)).await?;
    tx.commit().await?;
    Ok(())
}
async fn get_record(p: &providers::Saved, id: &str) -> ApiResult<Value> {
    if !openwaf_cloudflare::valid_id(id) {
        return Err(Error::Invalid);
    }
    let v = p
        .client
        .call(
            Method::GET,
            &format!("/zones/{}/dns_records/{id}", p.zone_id),
            &[],
            None,
        )
        .await
        .map_err(Error::from)?;
    let r = &v["result"];
    if r["id"] != id || r["name"].as_str().is_none_or(|n| !in_zone(n, &p.zone)) {
        return Err(Error::CloudflareUnavailable);
    }
    Ok(r.clone())
}
fn current(record: &Value, expected: &str) -> ApiResult<()> {
    if protected(record)
        || !record["type"].as_str().is_some_and(supported)
        || expected.len() != 64
        || version(record)? != expected
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path(id): Path<String>,
    Json(input): Json<Write>,
) -> ApiResult<Json<Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    let _permit = providers::permit(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    let p = providers::saved(&app, &id).await?;
    if p.revision != input.expected_provider_revision || input.expected_record.is_some() {
        return Err(Error::Conflict);
    }
    let body = input.record.payload(&p.zone)?;
    log(&app, &auth, peer, "cloudflare.dns.create_attempted", &id).await?;
    let result = p
        .client
        .call(
            Method::POST,
            &format!("/zones/{}/dns_records", p.zone_id),
            &[],
            Some(&body),
        )
        .await;
    let result = checked_result(result, &body, None);
    complete(&app, &auth, peer, "create", &id, result).await
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path((id, record)): Path<(String, String)>,
    Json(input): Json<Write>,
) -> ApiResult<Json<Value>> {
    let auth = authenticate(&app, &headers, true).await?;
    let _permit = providers::permit(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    let p = providers::saved(&app, &id).await?;
    if p.revision != input.expected_provider_revision {
        return Err(Error::Conflict);
    }
    let before = get_record(&p, &record).await?;
    current(
        &before,
        input.expected_record.as_deref().ok_or(Error::Invalid)?,
    )?;
    let body = input.record.payload(&p.zone)?;
    // Preserve record type and provider-managed fields (tags/comments/settings).
    if before["type"] != body["type"] {
        return Err(Error::Invalid);
    }
    log(
        &app,
        &auth,
        peer,
        "cloudflare.dns.update_attempted",
        &record,
    )
    .await?;
    let result = p
        .client
        .call(
            Method::PATCH,
            &format!("/zones/{}/dns_records/{record}", p.zone_id),
            &[],
            Some(&body),
        )
        .await;
    let result = checked_result(result, &body, Some(&record));
    complete(&app, &auth, peer, "update", &record, result).await
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    Path((id, record)): Path<(String, String)>,
    Json(input): Json<Delete>,
) -> ApiResult<StatusCode> {
    let auth = authenticate(&app, &headers, true).await?;
    let _permit = providers::permit(&app)?;
    let _gate = app
        .certificates
        .mutation
        .try_lock()
        .map_err(|_| Error::Conflict)?;
    let p = providers::saved(&app, &id).await?;
    if p.revision != input.expected_provider_revision {
        return Err(Error::Conflict);
    }
    current(&get_record(&p, &record).await?, &input.expected_record)?;
    log(
        &app,
        &auth,
        peer,
        "cloudflare.dns.delete_attempted",
        &record,
    )
    .await?;
    let result = p
        .client
        .call(
            Method::DELETE,
            &format!("/zones/{}/dns_records/{record}", p.zone_id),
            &[],
            None,
        )
        .await;
    let outcome = match result {
        Ok(v) if v["result"]["id"] == record => Ok(()),
        Ok(_) => Err(Error::CloudflareOutcomeUnknown),
        Err(e) => Err(e.into()),
    };
    log(
        &app,
        &auth,
        peer,
        if outcome.is_ok() {
            "cloudflare.dns.delete_acknowledged"
        } else {
            "cloudflare.dns.delete_unacknowledged"
        },
        &record,
    )
    .await
    .map_err(|_| Error::CloudflareOutcomeUnknown)?;
    outcome?;
    Ok(StatusCode::NO_CONTENT)
}
fn checked_result(
    result: openwaf_cloudflare::ApiResult<Value>,
    body: &Value,
    id: Option<&str>,
) -> openwaf_cloudflare::ApiResult<Value> {
    let value = result?;
    let r = &value["result"];
    if r["name"] != body["name"] || r["type"] != body["type"] || id.is_some_and(|id| r["id"] != id)
    {
        return Err(openwaf_cloudflare::ApiError::OutcomeUnknown);
    }
    Ok(value)
}
async fn complete(
    app: &App,
    auth: &Auth,
    peer: SocketAddr,
    verb: &str,
    target: &str,
    result: openwaf_cloudflare::ApiResult<Value>,
) -> ApiResult<Json<Value>> {
    let result = match result {
        Ok(v) => summary(&v["result"]).map_err(|_| Error::CloudflareOutcomeUnknown),
        Err(e) => Err(e.into()),
    };
    let action = format!(
        "cloudflare.dns.{verb}_{}",
        if result.is_ok() {
            "acknowledged"
        } else {
            "unacknowledged"
        }
    );
    log(app, auth, peer, &action, target)
        .await
        .map_err(|_| Error::CloudflareOutcomeUnknown)?;
    Ok(Json(
        json!({"record":result?,"source":"cloudflare","observed_at_unix_ms":openwaf_telemetry::now_ms()}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validation_scopes_names_and_protects_acme() {
        let mut r = RecordInput {
            kind: "A".into(),
            name: "www".into(),
            content: "192.0.2.5".into(),
            ttl: 1,
            proxied: true,
            priority: None,
        };
        assert_eq!(
            r.payload("example.test").ok().map(|v| v["name"].clone()),
            Some(json!("www.example.test"))
        );
        assert!(
            owner("evil.example.test.attacker.test", "example.test")
                .is_ok_and(|v| v.ends_with(".example.test"))
        );
        r.kind = "TXT".into();
        r.proxied = false;
        r.name = "_acme-challenge".into();
        assert!(r.payload("example.test").is_err());
        r.name = "_dmarc".into();
        assert!(r.payload("example.test").is_ok());
        r.proxied = true;
        assert!(r.payload("example.test").is_err());
        assert!(protected(
            &json!({"name":"safe.example.test","comment":"openwaf-acme:owned"})
        ));
        assert!(owner("a..b", "example.test").is_err());
    }
}
