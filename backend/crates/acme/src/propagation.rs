//! Bounded DNS-01 visibility checks. Never log TXT values or resolver error payloads.
use anyhow::{Result, ensure};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
};
use std::{net::SocketAddr, time::Duration};

const OVERRIDE: &str = "OPENWAF_ACME_DNS_RESOLVER";

fn resolver_config(
    configured: Option<SocketAddr>,
    override_value: Option<&str>,
) -> Result<(ResolverConfig, ResolverOpts)> {
    let address = override_value
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value.trim().parse::<SocketAddr>().map_err(|_| {
                anyhow::anyhow!("{OVERRIDE} must be an IP:port (IPv6: [address]:port)")
            })
        })
        .transpose()?
        .or(configured);
    let (config, mut options) = if let Some(address) = address {
        ensure!(
            !address.ip().is_unspecified() && !address.ip().is_multicast() && address.port() != 0,
            "invalid ACME DNS resolver address"
        );
        (
            ResolverConfig::from_parts(
                None,
                vec![],
                NameServerConfigGroup::from_ips_clear(&[address.ip()], address.port(), true),
            ),
            ResolverOpts::default(),
        )
    } else {
        hickory_resolver::system_conf::read_system_conf()
            .map_err(|_| anyhow::anyhow!("cannot load DNS resolver configuration"))?
    };
    options.timeout = Duration::from_secs(2);
    options.attempts = 1;
    options.cache_size = 0;
    Ok((config, options))
}

fn failure(error: &ResolveError) -> (&'static str, String) {
    match error.kind() {
        ResolveErrorKind::NoRecordsFound {
            response_code,
            negative_ttl,
            ..
        } => (
            match response_code {
                hickory_resolver::proto::op::ResponseCode::NXDomain => "nxdomain",
                hickory_resolver::proto::op::ResponseCode::ServFail => "servfail",
                _ => "no_records",
            },
            format!("response={response_code}, negative_ttl_seconds={negative_ttl:?}"),
        ),
        ResolveErrorKind::Timeout => ("timeout", "lookup timed out".into()),
        ResolveErrorKind::NoConnections | ResolveErrorKind::Io(_) => (
            "network",
            "resolver unavailable or network I/O failed".into(),
        ),
        _ => ("protocol", "DNS protocol or resolver failure".into()),
    }
}

pub struct Checker {
    resolver: TokioAsyncResolver,
    endpoints: String,
}

impl Checker {
    pub fn new(configured: Option<SocketAddr>) -> Result<Self> {
        let value = std::env::var(OVERRIDE)
            .map(Some)
            .or_else(|error| match error {
                std::env::VarError::NotPresent => Ok(None),
                _ => Err(anyhow::anyhow!("{OVERRIDE} must be valid text")),
            })?;
        Self::from_config(resolver_config(configured, value.as_deref())?)
    }

    fn from_config((config, options): (ResolverConfig, ResolverOpts)) -> Result<Self> {
        ensure!(
            !config.name_servers().is_empty(),
            "no ACME DNS resolvers configured"
        );
        // Bound diagnostic output even if the system resolver list is unusually large.
        let endpoints = config
            .name_servers()
            .iter()
            .take(8)
            .map(|server| server.socket_addr.to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self {
            resolver: TokioAsyncResolver::tokio(config, options),
            endpoints,
        })
    }

    pub async fn wait(&self, name: &str, expected: &str, deadline: Duration) -> Result<()> {
        // Fully qualified to avoid expanding resolver search domains.
        let name = format!("{}.", name.trim_end_matches('.'));
        eprintln!(
            "ACME DNS propagation: name={name}, resolvers={}, deadline_seconds={}",
            self.endpoints,
            deadline.as_secs()
        );
        let mut attempts = 0u32;
        let mut last = ("timeout", "lookup timed out".to_owned());
        let check = async {
            loop {
                attempts += 1;
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    self.resolver.txt_lookup(name.as_str()),
                )
                .await
                {
                    Ok(Ok(answer)) => {
                        if answer.iter().any(|txt| {
                            txt.txt_data()
                                .iter()
                                .flat_map(|part| part.iter())
                                .copied()
                                .eq(expected.bytes())
                        }) {
                            return;
                        }
                        last = (
                            "txt_mismatch",
                            "TXT response does not contain the current challenge".into(),
                        );
                    }
                    Ok(Err(error)) => last = failure(&error),
                    Err(_) => last = ("timeout", "lookup timed out".into()),
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };
        if tokio::time::timeout(deadline, check).await.is_err() {
            // The gateway accepts only this finite code, never raw DNS errors or TXT values.
            eprintln!("OWAF_DNS {}", last.0);
            anyhow::bail!(
                "DNS propagation deadline exceeded: name={name}, resolvers={}, attempts={attempts}, last={}; check DNS delegation, resolver cache and outbound DNS; {OVERRIDE} can select a reachable resolver",
                self.endpoints,
                last.1
            );
        }
        eprintln!("DNS challenge visible at configured resolver");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::{Message, MessageType, ResponseCode},
        rr::{
            Name, RData, Record,
            rdata::{SOA, TXT},
        },
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::{net::UdpSocket, task::JoinHandle};

    struct Server {
        address: SocketAddr,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    enum Reply {
        NegativeThenVisible,
        WrongTxt,
        ServFail,
        Silent,
    }
    impl Server {
        async fn start(reply: Reply) -> Result<Self> {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let address = socket.local_addr()?;
            let requests = Arc::new(AtomicUsize::new(0));
            let count = requests.clone();
            let task = tokio::spawn(async move {
                let mut bytes = [0; 2048];
                loop {
                    let (size, peer) = socket.recv_from(&mut bytes).await.expect("DNS request");
                    let index = count.fetch_add(1, Ordering::Relaxed);
                    if matches!(reply, Reply::Silent) {
                        continue;
                    }
                    let query = Message::from_vec(&bytes[..size]).expect("decode DNS request");
                    let mut response = Message::new();
                    response
                        .set_id(query.id())
                        .set_message_type(MessageType::Response)
                        .set_recursion_desired(true)
                        .set_recursion_available(true)
                        .add_queries(query.queries().iter().cloned());
                    match reply {
                        Reply::NegativeThenVisible if index == 0 => {
                            response.set_response_code(ResponseCode::NXDomain);
                            response.add_name_server(Record::from_rdata(
                                Name::from_ascii("example.test.").expect("zone"),
                                1800,
                                RData::SOA(SOA::new(
                                    Name::from_ascii("ns.example.test.").expect("NS"),
                                    Name::from_ascii("hostmaster.example.test.")
                                        .expect("hostmaster"),
                                    1,
                                    3600,
                                    600,
                                    86400,
                                    1800,
                                )),
                            ));
                        }
                        Reply::NegativeThenVisible | Reply::WrongTxt => {
                            let txt = if matches!(reply, Reply::WrongTxt) {
                                TXT::new(vec!["previous-challenge".into()])
                            } else {
                                // Multiple character strings form one TXT record value.
                                TXT::new(vec!["current-".into(), "challenge".into()])
                            };
                            response.add_answer(Record::from_rdata(
                                query.queries()[0].name().clone(),
                                60,
                                RData::TXT(txt),
                            ));
                        }
                        Reply::ServFail => {
                            response.set_response_code(ResponseCode::ServFail);
                        }
                        Reply::Silent => unreachable!(),
                    }
                    socket
                        .send_to(&response.to_vec().expect("encode response"), peer)
                        .await
                        .expect("DNS reply");
                }
            });
            Ok(Self {
                address,
                requests,
                task,
            })
        }
        fn checker(&self) -> Result<Checker> {
            Checker::from_config(resolver_config(None, Some(&self.address.to_string()))?)
        }
    }

    #[test]
    fn failure_codes_do_not_forward_external_error_payloads() -> Result<()> {
        use hickory_resolver::proto::{op::Query, rr::RecordType};
        for (response_code, expected) in [
            (ResponseCode::NXDomain, "nxdomain"),
            (ResponseCode::ServFail, "servfail"),
            (ResponseCode::NoError, "no_records"),
        ] {
            let error = ResolveError::from(ResolveErrorKind::NoRecordsFound {
                query: Box::new(Query::query(
                    Name::from_ascii("private-query.example.test.")?,
                    RecordType::TXT,
                )),
                soa: None,
                negative_ttl: Some(1800),
                response_code,
                trusted: true,
            });
            let (code, detail) = failure(&error);
            assert_eq!(code, expected);
            assert!(!detail.contains("private-query"));
        }
        for (kind, expected) in [
            (ResolveErrorKind::Timeout, "timeout"),
            (ResolveErrorKind::NoConnections, "network"),
            (
                ResolveErrorKind::Msg("private-error-payload".into()),
                "protocol",
            ),
        ] {
            let (code, detail) = failure(&ResolveError::from(kind));
            assert_eq!(code, expected);
            assert!(!detail.contains("private-error-payload"));
        }
        Ok(())
    }

    #[test]
    fn resolver_override_precedence_and_address_validation() -> Result<()> {
        let configured = "192.0.2.1:53".parse()?;
        let (config, _) = resolver_config(Some(configured), Some("  "))?;
        assert_eq!(config.name_servers()[0].socket_addr, configured);
        let address = "[::1]:5353".parse::<SocketAddr>()?;
        let (config, options) = resolver_config(Some(configured), Some(&address.to_string()))?;
        assert!(
            config
                .name_servers()
                .iter()
                .all(|server| server.socket_addr == address)
        );
        assert_eq!(options.cache_size, 0);
        for value in [
            "bad",
            "1.1.1.1",
            "0.0.0.0:53",
            "[::]:53",
            "224.0.0.1:53",
            "127.0.0.1:0",
        ] {
            assert!(resolver_config(Some(configured), Some(value)).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn propagation_requeries_after_nxdomain_and_matches_split_txt() -> Result<()> {
        let server = Server::start(Reply::NegativeThenVisible).await?;
        server
            .checker()?
            .wait(
                "_acme-challenge.admin.example.test",
                "current-challenge",
                Duration::from_secs(4),
            )
            .await?;
        assert!(server.requests.load(Ordering::Relaxed) >= 2);
        Ok(())
    }

    #[tokio::test]
    async fn stale_txt_and_resolver_failures_remain_failures_with_safe_diagnostics() -> Result<()> {
        for (reply, diagnostic) in [
            (
                Reply::WrongTxt,
                "TXT response does not contain the current challenge",
            ),
            (Reply::ServFail, "Server Failure"),
            (Reply::Silent, "lookup timed out"),
        ] {
            let server = Server::start(reply).await?;
            let error = server
                .checker()?
                .wait(
                    "_acme-challenge.admin.example.test",
                    "current-challenge",
                    Duration::from_millis(250),
                )
                .await
                .expect_err("must not bypass DNS check")
                .to_string();
            assert!(error.contains(diagnostic), "{error}");
            assert!(error.contains(&server.address.to_string()));
            assert!(!error.contains("previous-challenge"));
            assert!(!error.contains("current-challenge"));
            assert!(server.requests.load(Ordering::Relaxed) > 0);
        }
        Ok(())
    }
}
