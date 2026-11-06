//! One authority for routing, native WAF headers and HTTP/1 upstream conversion.
use pingora::http::{RequestHeader, Version};

pub fn prepare(header: &mut RequestHeader, tls: bool) -> Option<String> {
    let mut hosts = header.headers.get_all("host").iter();
    let host = hosts.next().map(|v| v.to_str()).transpose().ok()?;
    if hosts.next().is_some() {
        return None;
    }
    let authority = if header.version == Version::HTTP_2 {
        if header.uri.scheme_str() != Some(if tls { "https" } else { "http" }) {
            return None;
        }
        match (header.uri.authority(), host) {
            (Some(authority), host) => {
                if host.is_some_and(|host| !host.eq_ignore_ascii_case(authority.as_str())) {
                    return None;
                }
                authority.as_str()
            }
            (None, Some(host)) => host,
            _ => return None,
        }
    } else {
        // raw_path also catches absolute-form preserved separately by Pingora.
        if header.uri.scheme().is_some()
            || header.uri.authority().is_some()
            || !header.raw_path().starts_with(b"/")
        {
            return None;
        }
        host?
    };
    let normalized = openwaf_config::request_host(authority).ok()?;
    let authority = authority.to_owned();
    // Make Host visible to ModSecurity even for authority-only H2 requests.
    header.insert_header("host", authority).ok()?;
    Some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_shared_and_conflicts_rejected() {
        let mut h = RequestHeader::build("GET", b"/a?q=1", None).unwrap();
        h.set_version(Version::HTTP_2);
        h.set_uri("https://APP.example.test:8443/a?q=1".parse().unwrap());
        assert_eq!(prepare(&mut h, true).as_deref(), Some("app.example.test"));
        assert_eq!(h.headers["host"], "APP.example.test:8443");
        h.insert_header("host", "other.example.test").unwrap();
        assert!(prepare(&mut h, true).is_none());
        h.insert_header("host", "app.example.test:8443").unwrap();
        assert!(prepare(&mut h, true).is_some());
        assert!(prepare(&mut h, false).is_none());
        h.append_header("host", "app.example.test:8443").unwrap();
        assert!(prepare(&mut h, true).is_none());
    }

    #[test]
    fn http1_remains_origin_form_only() {
        let mut h = RequestHeader::build("GET", b"/", None).unwrap();
        h.insert_header("host", "app.example.test").unwrap();
        assert!(prepare(&mut h, false).is_some());
        h.set_raw_path(b"http://app.example.test/").unwrap();
        assert!(prepare(&mut h, false).is_none());
    }
}
